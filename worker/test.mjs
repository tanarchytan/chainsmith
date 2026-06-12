// Parity / smoke test for the client-side core (Node harness).
//
//   npm test                      offline self-test (generates a cert, runs the
//                                 full pipeline -- no network, CA-agnostic)
//   node test.mjs host[ host...]  live audit of each host (pulls the served
//                                 chain via Node TLS, which a browser/Worker
//                                 cannot do) and prints the grade + any swap
//
// The fixer itself is issuer-agnostic: every endpoint it touches comes from the
// certificate's own AIA/CRL/OCSP extensions.
import tls from "node:tls";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { createCore, _parseCerts as parseCerts } from "./src/core.js";

const transport = async (url, init) => {
  try {
    const r = await fetch(url, init);
    return r.ok ? await r.arrayBuffer() : null;
  } catch {
    return null;
  }
};
const core = createCore(transport);

let failed = 0;
const ok = (cond, msg) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`);
  if (!cond) failed++;
};

// --- Offline self-test: build a cert, run the pipeline, no network ----------
async function selfTest() {
  console.log("\n[offline] generate a cert and run the full pipeline");
  const alg = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  };
  const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  const name = new pkijs.RelativeDistinguishedNames({
    typesAndValues: [
      new pkijs.AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new asn1js.Utf8String({ value: "chainsmith-selftest" }),
      }),
    ],
  });
  cert.subject = name;
  cert.issuer = name;
  cert.notBefore.value = new Date(Date.now() - 3600e3);
  cert.notAfter.value = new Date(Date.now() + 3600e3);
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(keys.privateKey, "SHA-256");

  const der = new Uint8Array(cert.toSchema(true).toBER(false));
  const parsed = parseCerts(der);
  ok(parsed.length === 1, "parses a DER certificate");
  const report = await core.evaluate(parsed[0], parsed);
  ok(["OK", "WARN", "ERROR"].includes(report.grade), `produces a grade (${report.grade})`);
  ok(report.certs.length === 1 && report.certs[0].label === "LEAF", "reports the leaf");
}

// --- Live audit (optional) --------------------------------------------------
function liveChain(host) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false },
      () => {
        const ders = [];
        const seen = new Set();
        let c = sock.getPeerCertificate(true);
        while (c && c.raw && !seen.has(c.fingerprint256)) {
          seen.add(c.fingerprint256);
          ders.push(new Uint8Array(c.raw));
          c = c.issuerCertificate;
        }
        sock.end();
        resolve(ders);
      },
    );
    sock.on("error", reject);
  });
}

async function liveAudit(host) {
  console.log(`\n[live] ${host}`);
  const observed = (await liveChain(host)).map((d) => parseCerts(d)[0]);
  const report = await core.evaluate(observed[0], observed);
  console.log(`    presented: ${observed.length} cert(s) | grade: ${report.grade}`);
  for (const f of report.findings) console.log(`    ${f.level.toUpperCase()}: ${f.text}`);
  if (report.swaps.length) console.log("    swaps:", report.swaps);
  ok(["OK", "WARN", "ERROR"].includes(report.grade), `${host}: produced a grade`);
  // CA-agnostic invariant: a revoked served cert must surface as ERROR + (swap | unfixable)
  const revokedServed = report.findings.some((f) => f.level === "error" && /REVOKED/i.test(f.text));
  if (revokedServed)
    ok(report.grade === "ERROR", `${host}: revoked served cert grades ERROR`);
}

const hosts = process.argv.slice(2);
await selfTest();
for (const h of hosts) {
  try {
    await liveAudit(h);
  } catch (e) {
    console.log(`FAIL  ${h}: ${e.message}`);
    failed++;
  }
}
if (!hosts.length)
  console.log("\n(tip: `node test.mjs example.com` to run a live audit)");
process.exit(failed ? 1 : 0);
