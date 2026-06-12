// Fetch the certificate chain a host actually *presents*, from inside the Worker.
//
// fetch() never exposes the peer chain, so we open a raw TCP socket and speak
// just enough TLS by hand: send a TLS 1.2 ClientHello, then read the server's
// Certificate handshake message (which is cleartext in TLS <= 1.2) and pull the
// DER certs out. We deliberately omit the supported_versions extension so a
// TLS 1.3-capable server negotiates 1.2 and sends the chain in the clear; a
// TLS 1.3-only server will alert, and we surface that as an error.
import { connect } from "cloudflare:sockets";

const u16 = (n) => [(n >> 8) & 0xff, n & 0xff];
const u24 = (n) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function buildClientHello(host) {
  const hostBytes = new TextEncoder().encode(host);
  const sni = [0x00, ...u16(hostBytes.length), ...hostBytes]; // host_name entry
  const sniList = [...u16(sni.length), ...sni];
  const extSNI = [0x00, 0x00, ...u16(sniList.length), ...sniList];

  const groups = [0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]; // x25519, secp256r1, secp384r1
  const extGroups = [0x00, 0x0a, ...u16(groups.length + 2), ...u16(groups.length), ...groups];

  const extECPF = [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]; // ec_point_formats: uncompressed

  const sigalgs = [
    0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
  ];
  const extSig = [0x00, 0x0d, ...u16(sigalgs.length + 2), ...u16(sigalgs.length), ...sigalgs];

  const extReneg = [0xff, 0x01, 0x00, 0x01, 0x00]; // renegotiation_info (empty)

  const extensions = [...extSNI, ...extGroups, ...extECPF, ...extSig, ...extReneg];

  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const ciphers = [
    0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
    0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
  ];
  const body = [
    0x03, 0x03, // client_version TLS 1.2
    ...random,
    0x00, // session_id length 0
    ...u16(ciphers.length), ...ciphers,
    0x01, 0x00, // compression: null
    ...u16(extensions.length), ...extensions,
  ];
  const hs = [0x01, ...u24(body.length), ...body]; // ClientHello
  return new Uint8Array([0x16, 0x03, 0x01, ...u16(hs.length), ...hs]);
}

// Scan accumulated handshake bytes for a Certificate (type 11) message.
function parseCertificate(hs) {
  let off = 0;
  while (hs.length - off >= 4) {
    const mtype = hs[off];
    const mlen = (hs[off + 1] << 16) | (hs[off + 2] << 8) | hs[off + 3];
    if (hs.length - off - 4 < mlen) return null; // message incomplete
    const body = hs.subarray(off + 4, off + 4 + mlen);
    if (mtype === 11) {
      const certs = [];
      let p = 3; // skip 3-byte certificate_list length
      while (p + 3 <= body.length) {
        const cl = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
        p += 3;
        if (p + cl > body.length) break;
        certs.push(body.subarray(p, p + cl));
        p += cl;
      }
      return certs;
    }
    off += 4 + mlen;
  }
  return null;
}

function derToPem(der) {
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const lines = btoa(bin).match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// Returns the served chain as PEM text, or throws.
export async function getServedChainPEM(host) {
  const socket = connect({ hostname: host, port: 443 }, { secureTransport: "off" });
  const writer = socket.writable.getWriter();
  await writer.write(buildClientHello(host));
  writer.releaseLock();

  const reader = socket.readable.getReader();
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 8000));
  let buf = new Uint8Array(0);
  let handshake = new Uint8Array(0);
  let certs = null;
  try {
    for (let i = 0; i < 64 && !certs; i++) {
      const { value, done } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      buf = concat(buf, value);
      let off = 0;
      while (buf.length - off >= 5) {
        const type = buf[off];
        const recLen = (buf[off + 3] << 8) | buf[off + 4];
        if (buf.length - off - 5 < recLen) break;
        const payload = buf.subarray(off + 5, off + 5 + recLen);
        off += 5 + recLen;
        if (type === 0x16) handshake = concat(handshake, payload);
        else if (type === 0x15) throw new Error("server sent a TLS alert (likely TLS 1.3-only)");
      }
      buf = buf.subarray(off);
      certs = parseCertificate(handshake);
    }
  } finally {
    try { reader.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
  }
  if (!certs || !certs.length)
    throw new Error("no certificate received (server may be TLS 1.3-only or unreachable)");
  return certs.map(derToPem).join("");
}
