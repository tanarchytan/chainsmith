// Certificate bundle fixer -- core logic, runs CLIENT-SIDE in the browser.
// Works with any CA. Same logic as the Python cert-check.py: build the chain
// from the input certs + AIA, check validity / CRL / OCSP / signature, and if a
// served intermediate has been revoked but the issuer published a same-key
// reissue (same Subject Key Identifier, new serial), swap it in. It refuses to
// emit a chain that still contains a revoked / expired / bad-signature cert.
//
// `transport(url, init?)` performs an HTTP fetch and returns an ArrayBuffer (or
// null). In the browser it goes through the Worker's same-origin /proxy relay
// (CORS + http mixed-content make direct browser fetches to the issuer's
// endpoints impossible); in Node tests it can be a direct fetch. Only the
// issuer's own AIA/CRL/OCSP endpoints are used -- never a third-party log.
import * as pkijs from "pkijs";

pkijs.setEngine(
  "fixer",
  new pkijs.CryptoEngine({ name: "fixer", crypto: globalThis.crypto }),
);

const OID = {
  AIA: "1.3.6.1.5.5.7.1.1",
  CRLDP: "2.5.29.31",
  SKI: "2.5.29.14",
  BASIC: "2.5.29.19",
  OCSP_METHOD: "1.3.6.1.5.5.7.48.1",
  CAISSUERS_METHOD: "1.3.6.1.5.5.7.48.2",
};
const MAX_CHAIN = 8;

// --------------------------------------------------------------------------- //
// Encoding helpers
// --------------------------------------------------------------------------- //
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const stripZeros = (hex) => hex.replace(/^(00)+/, "") || "0";

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(u8) {
  let bin = "";
  for (const b of u8) bin += String.fromCharCode(b);
  return btoa(bin);
}
const looksPem = (bytes) =>
  new TextDecoder().decode(bytes.slice(0, 64)).includes("BEGIN");

function pemBlocksToDer(text) {
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(text)) !== null)
    out.push(b64ToBytes(m[1].replace(/\s+/g, "")).buffer);
  return out;
}
function derToPem(der) {
  const lines = bytesToB64(new Uint8Array(der)).match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

export function parseCerts(bytes) {
  if (looksPem(bytes))
    return pemBlocksToDer(new TextDecoder().decode(bytes)).map((d) =>
      pkijs.Certificate.fromBER(d),
    );
  return [pkijs.Certificate.fromBER(bytes.buffer ?? bytes)];
}

// --------------------------------------------------------------------------- //
// Cert accessors
// --------------------------------------------------------------------------- //
// DER encoding and SHA-256 fingerprints are computed many times per cert during
// chain building -- memoize both per Certificate object (keyed by identity).
const _derCache = new WeakMap();
const _fpCache = new WeakMap();
function certDer(c) {
  let d = _derCache.get(c);
  if (!d) _derCache.set(c, (d = c.toSchema(true).toBER(false)));
  return d;
}
function fp(c) {
  let p = _fpCache.get(c);
  if (!p) {
    p = crypto.subtle
      .digest("SHA-256", certDer(c))
      .then((h) => toHex(new Uint8Array(h)));
    _fpCache.set(c, p);
  }
  return p; // Promise<string>; cached so repeat calls are free
}
const NAME = {
  "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C",
  "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.97": "organizationIdentifier",
};
const nameStr = (n) =>
  n.typesAndValues.map((t) => `${NAME[t.type] || t.type}=${t.value.valueBlock.value}`).join(",");
const subjectStr = (c) => nameStr(c.subject);
const issuerStr = (c) => nameStr(c.issuer);
const isSelfSigned = (c) => c.subject.isEqual(c.issuer);
const serialHex = (c) =>
  stripZeros(toHex(new Uint8Array(c.serialNumber.valueBlock.valueHexView)));
const getExt = (c, oid) => (c.extensions || []).find((e) => e.extnID === oid);

function ski(c) {
  const e = getExt(c, OID.SKI);
  return e ? toHex(new Uint8Array(e.parsedValue.valueBlock.valueHexView)) : null;
}
function accessUrls(c, method) {
  const e = getExt(c, OID.AIA);
  return e
    ? e.parsedValue.accessDescriptions
        .filter((d) => d.accessMethod === method)
        .map((d) => d.accessLocation.value)
    : [];
}
const caIssuerUrls = (c) => accessUrls(c, OID.CAISSUERS_METHOD);
const ocspUrls = (c) => accessUrls(c, OID.OCSP_METHOD);
function crlUrls(c) {
  const e = getExt(c, OID.CRLDP);
  if (!e) return [];
  const urls = [];
  for (const dp of e.parsedValue.distributionPoints || [])
    for (const gn of dp.distributionPoint || []) if (gn.value) urls.push(gn.value);
  return urls;
}
const isCA = (c) => {
  const e = getExt(c, OID.BASIC);
  return e ? e.parsedValue.cA === true : false;
};
function validityStatus(c) {
  const now = new Date();
  if (c.notAfter.value < now) return "EXPIRED";
  if (c.notBefore.value > now) return "NOT_YET_VALID";
  return "OK";
}
async function signedBy(cert, issuer) {
  try {
    return await cert.verify(issuer);
  } catch {
    return false;
  }
}

// --------------------------------------------------------------------------- //
// Factory: bind the injected transport, return the API
// --------------------------------------------------------------------------- //
export function createCore(transport) {
  const derCache = new Map();
  const crlCache = new Map();
  const crlStatusCache = new WeakMap(); // per-cert revocation verdict

  async function fetchDer(url) {
    if (derCache.has(url)) return derCache.get(url);
    let out = null;
    const buf = await transport(url);
    if (buf) {
      const bytes = new Uint8Array(buf);
      out = looksPem(bytes)
        ? pemBlocksToDer(new TextDecoder().decode(bytes))[0]
        : buf;
    }
    derCache.set(url, out);
    return out;
  }
  async function loadCrl(url) {
    if (crlCache.has(url)) return crlCache.get(url);
    let crl = null;
    const buf = await transport(url);
    if (buf) {
      try {
        crl = pkijs.CertificateRevocationList.fromBER(buf);
      } catch {
        crl = null;
      }
    }
    crlCache.set(url, crl);
    return crl;
  }

  function crlStatus(cert) {
    // Memoized per cert: called once per candidate during scoring, then again
    // per chain cert and in swap detection -- the CRL scan should run once.
    let p = crlStatusCache.get(cert);
    if (!p) crlStatusCache.set(cert, (p = computeCrlStatus(cert)));
    return p;
  }
  async function computeCrlStatus(cert) {
    const urls = crlUrls(cert);
    if (!urls.length) return ["UNKNOWN", "no CRL DP"];
    const target = serialHex(cert);
    let saw = false;
    for (const u of urls) {
      const crl = await loadCrl(u);
      if (!crl) continue;
      saw = true;
      const hit = (crl.revokedCertificates || []).find(
        (rc) =>
          stripZeros(toHex(new Uint8Array(rc.userCertificate.valueBlock.valueHexView))) ===
          target,
      );
      if (hit) return ["REVOKED", u];
    }
    return saw ? ["GOOD", "not on CRL"] : ["UNKNOWN", "CRL unreachable"];
  }

  async function ocspStatus(cert, issuer) {
    if (!issuer) return ["UNKNOWN", "no issuer"];
    const urls = ocspUrls(cert);
    if (!urls.length) return ["UNKNOWN", "no OCSP URL"];
    const url = urls[0];
    try {
      const req = new pkijs.OCSPRequest();
      await req.createForCertificate(cert, {
        hashAlgorithm: "SHA-256",
        issuerCertificate: issuer,
      });
      const body = req.toSchema(true).toBER(false);
      const buf = await transport(url, {
        method: "POST",
        headers: { "Content-Type": "application/ocsp-request" },
        body,
      });
      if (!buf) return ["UNKNOWN", `${url} (no response)`];
      const resp = pkijs.OCSPResponse.fromBER(buf);
      if (resp.responseStatus.valueBlock.valueDec !== 0)
        return ["UNKNOWN", `${url} (status ${resp.responseStatus.valueBlock.valueDec})`];
      const st = await resp.getCertificateStatus(cert, issuer);
      return [["GOOD", "REVOKED", "UNKNOWN"][st.status] ?? "UNKNOWN", url];
    } catch (e) {
      return ["UNKNOWN", `${url} (${e.message || e})`];
    }
  }

  async function gatherCandidates(leaf, observed) {
    const pool = new Map();
    const leafFp = await fp(leaf);
    for (const c of observed) {
      const f = await fp(c);
      if (f !== leafFp) pool.set(f, c);
    }
    let frontier = [leaf];
    const seen = new Set();
    for (let depth = 0; depth < MAX_CHAIN; depth++) {
      const next = [];
      for (const cur of frontier) {
        const f = await fp(cur);
        if (seen.has(f) || isSelfSigned(cur)) continue;
        seen.add(f);
        for (const url of caIssuerUrls(cur)) {
          const der = await fetchDer(url);
          if (!der) continue;
          const issuer = pkijs.Certificate.fromBER(der);
          pool.set(await fp(issuer), issuer);
          next.push(issuer);
        }
      }
      frontier = next;
      if (!next.length) break;
    }
    return [...pool.values()];
  }

  async function linkChain(leaf, pool) {
    const chain = [leaf];
    let cur = leaf;
    const used = new Set([await fp(leaf)]);
    for (let i = 0; i < MAX_CHAIN; i++) {
      if (isSelfSigned(cur)) break;
      const cands = [];
      for (const c of pool) {
        if (used.has(await fp(c))) continue;
        if (!cur.issuer.isEqual(c.subject)) continue;
        if (await signedBy(cur, c)) cands.push(c);
      }
      if (!cands.length) break;
      const scored = [];
      for (const c of cands)
        scored.push({
          c,
          rev: (await crlStatus(c))[0] === "REVOKED" ? 1 : 0,
          exp: validityStatus(c) !== "OK" ? 1 : 0,
          nb: c.notBefore.value.getTime(),
        });
      scored.sort((a, b) => a.rev - b.rev || a.exp - b.exp || b.nb - a.nb);
      const nxt = scored[0].c;
      chain.push(nxt);
      used.add(await fp(nxt));
      cur = nxt;
    }
    return chain;
  }

  // ----- evaluate: same shape as cert-check.py, plus severity findings ------ //
  async function evaluate(leaf, observed) {
    const pool = await gatherCandidates(leaf, observed);
    const chain = await linkChain(leaf, pool);
    const report = {
      observedCount: observed.length,
      certs: [],
      findings: [], // {level: error|warn|note|ok, text}
      swaps: [],
      fatal: [],
      chainPem: "",
    };
    const add = (level, text) => report.findings.push({ level, text });

    const leafFp = await fp(leaf);
    const chainFps = new Set();
    for (const c of chain) chainFps.add(await fp(c));

    if (observed.length) {
      const obsFps = new Set();
      for (const c of observed) obsFps.add(await fp(c));
      const correctInter = chain.slice(1).filter((c) => !isSelfSigned(c));

      if (observed.length === 1)
        add("warn", "Server sends the leaf only — clients without the intermediate cached will fail. (incomplete chain)");
      for (const c of correctInter)
        if (!obsFps.has(await fp(c))) {
          add("warn", "Incomplete: the server does not send the correct intermediate.");
          break;
        }
      for (const c of observed) {
        const f = await fp(c);
        if (f === leafFp) continue;
        if (isSelfSigned(c))
          add("note", `Contains anchor: server sends the root ${subjectStr(c)} (harmless, but should be omitted).`);
        else if (!chainFps.has(f))
          add("note", `Extra/mismatched cert: server sends ${subjectStr(c)} which is not part of the valid path.`);
      }

      // Same-key reissue swap detection -> ERROR (served chain is broken).
      const chainInter = chain.slice(1).filter((c) => !isSelfSigned(c));
      for (const o of observed) {
        if ((await fp(o)) === leafFp || isSelfSigned(o)) continue;
        if ((await crlStatus(o))[0] !== "REVOKED") continue;
        let repl = null;
        for (const c of chainInter)
          if (ski(c) && ski(c) === ski(o) && serialHex(c) !== serialHex(o)) {
            repl = c;
            break;
          }
        if (repl) {
          report.swaps.push({
            subject: subjectStr(o),
            oldSerial: serialHex(o),
            newSerial: serialHex(repl),
            ski: ski(o),
          });
          add("error", `Served intermediate ${subjectStr(o)} (serial ${serialHex(o)}) is REVOKED — replaced with valid same-key reissue ${serialHex(repl)}. Server must redeploy.`);
        } else {
          report.fatal.push(`revoked intermediate ${subjectStr(o)} has no valid replacement`);
          add("error", `Served intermediate ${subjectStr(o)} (serial ${serialHex(o)}) is REVOKED and no valid replacement is available.`);
        }
      }
    }

    for (let i = 0; i < chain.length; i++) {
      const cert = chain[i];
      const issuer = i + 1 < chain.length ? chain[i + 1] : null;
      const label = i === 0 ? "LEAF" : isSelfSigned(cert) ? "ROOT" : "INT";
      const vstat = validityStatus(cert);
      const sig = issuer ? await signedBy(cert, issuer) : null;
      let crl = ["SKIP", "root"];
      let ocsp = ["SKIP", "root"];
      if (!isSelfSigned(cert)) {
        crl = await crlStatus(cert);
        ocsp = await ocspStatus(cert, issuer);
      }
      const revoked = crl[0] === "REVOKED" || ocsp[0] === "REVOKED";
      report.certs.push({
        label, subject: subjectStr(cert), issuer: issuerStr(cert),
        notBefore: cert.notBefore.value.toISOString().slice(0, 19) + "Z",
        notAfter: cert.notAfter.value.toISOString().slice(0, 19) + "Z",
        fp: await fp(cert), serial: serialHex(cert),
        validity: vstat, sig, crl, ocsp, revoked,
      });
      if (label !== "ROOT") {
        if (revoked) { report.fatal.push(`${label} ${subjectStr(cert)} is REVOKED`); add("error", `${label} ${subjectStr(cert)} is REVOKED.`); }
        if (vstat !== "OK") { report.fatal.push(`${label} is ${vstat}`); add("error", `${label} ${subjectStr(cert)} is ${vstat}.`); }
        if (sig === false) { report.fatal.push(`${label} bad signature`); add("error", `${label} signature does not verify against its issuer.`); }
      }
    }

    const shippable = chain.filter((c) => !isSelfSigned(c));
    if (shippable.length < 2 && !isSelfSigned(leaf)) {
      report.fatal.push("could not complete chain");
      add("error", "Could not complete the chain — no valid intermediate found via input or AIA.");
    }

    report.fixable = report.fatal.length === 0;
    if (report.fixable) report.chainPem = shippable.map((c) => derToPem(certDer(c))).join("");

    if (report.findings.every((f) => f.level === "note") && report.fixable)
      add("ok", "Served chain is correctly configured.");

    // Overall grade: error > warn > (notes/ok) -> OK
    report.grade = report.findings.some((f) => f.level === "error")
      ? "ERROR"
      : report.findings.some((f) => f.level === "warn")
        ? "WARN"
        : "OK";
    return report;
  }

  async function fixFromInput(bytes) {
    const certs = parseCerts(bytes);
    if (!certs.length) throw new Error("no certificate found in input");
    const caSubjects = certs.filter(isCA).map((c) => c.subject);
    const leaf = certs.find((c) => !caSubjects.some((s) => s.isEqual(c.subject))) || certs[0];
    return evaluate(leaf, certs);
  }

  return { evaluate, fixFromInput };
}

export { parseCerts as _parseCerts };
