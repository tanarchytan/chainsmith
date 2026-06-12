// Browser entry. All cert logic runs here (client-side); the only server call
// is the same-origin /proxy relay that fetches the CA's http AIA/CRL/OCSP
// endpoints on our behalf (browsers can't, due to CORS + mixed content).
import { createCore } from "./core.js";

// Transport: route every CA fetch through the Worker's /proxy?url= relay.
// The X-Chainsmith header marks the call as coming from this app; the Worker
// rejects /proxy requests without it, so other sites can't use the relay.
async function transport(url, init = {}) {
  const headers = { ...(init.headers || {}), "X-Chainsmith": "1" };
  try {
    const r = await fetch(`/proxy?url=${encodeURIComponent(url)}`, { ...init, headers });
    return r.ok ? await r.arrayBuffer() : null;
  } catch {
    return null;
  }
}
const core = createCore(transport);

const out = document.getElementById("out");
const input = document.getElementById("pem");

function line(text = "", cls = "") {
  const div = document.createElement("div");
  div.className = `ln ${cls}`;
  div.textContent = text;
  out.appendChild(div);
}
function clear() {
  out.textContent = "";
}

const LEVEL_CLASS = { error: "err", warn: "warn", note: "note", ok: "ok" };
const STAT_CLASS = { GOOD: "ok", OK: "ok", REVOKED: "err", EXPIRED: "err", NOT_YET_VALID: "err", UNKNOWN: "warn", SKIP: "muted" };
const stat = (s) => `[${s}]`;

function render(report) {
  clear();

  // Grade banner
  const gradeCls = { ERROR: "err", WARN: "warn", OK: "ok" }[report.grade];
  line(`GRADE: ${report.grade}`, `grade ${gradeCls}`);
  line(`Presented by input: ${report.observedCount} cert(s)`, "muted");
  line();

  // Findings (the SSL-Labs-style summary)
  line("FINDINGS", "head");
  if (!report.findings.length) line("  (none)", "muted");
  for (const f of report.findings) {
    const tag = { error: "ERROR", warn: "WARN ", note: "NOTE ", ok: "OK   " }[f.level];
    line(`  ${tag}  ${f.text}`, LEVEL_CLASS[f.level]);
  }
  line();

  // Per-cert detail
  line("CHAIN", "head");
  for (const c of report.certs) {
    line(`  --- ${c.label} ---`, "head");
    line(`  Subject : ${c.subject}`);
    line(`  Issuer  : ${c.issuer}`);
    line(`  Valid   : ${c.notBefore} -> ${c.notAfter} ${stat(c.validity)}`, STAT_CLASS[c.validity]);
    line(`  Serial  : 0x${c.serial}`, "muted");
    line(`  SHA256  : ${c.fp}`, "muted");
    if (c.label !== "ROOT") {
      line(`  CRL     : ${stat(c.crl[0])} ${c.crl[1]}`, STAT_CLASS[c.crl[0]]);
      line(`  OCSP    : ${stat(c.ocsp[0])} ${c.ocsp[1]}`, STAT_CLASS[c.ocsp[0]]);
    }
    if (c.sig !== null) line(`  Sig     : ${c.sig ? "[VALID]" : "[INVALID]"}`, c.sig ? "ok" : "err");
  }
  line();

  // Result + client-side bundle download
  if (report.fixable) {
    line("RESULT: FIXABLE — corrected bundle (leaf + intermediate, root excluded)", "ok");
    const blob = new Blob([report.chainPem], { type: "application/x-pem-file" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "fullchain-fixed.pem";
    a.className = "dl";
    a.textContent = "⤓ download fullchain-fixed.pem";
    out.appendChild(a);
  } else {
    line("RESULT: CANNOT FIX — see ERROR findings above", "err");
  }
}

async function run() {
  const text = input.value.trim();
  if (!text) {
    clear();
    line("paste a PEM certificate or chain first", "warn");
    return;
  }
  clear();
  line("running checks (AIA / CRL / OCSP via CA, relayed) ...", "muted");
  try {
    const report = await core.fixFromInput(new TextEncoder().encode(text));
    render(report);
  } catch (e) {
    clear();
    line(`ERROR: ${e.message || e}`, "err");
  }
}

document.getElementById("go").addEventListener("click", run);

// Drag-and-drop a .crt/.pem onto the textarea
input.addEventListener("dragover", (e) => e.preventDefault());
input.addEventListener("drop", async (e) => {
  e.preventDefault();
  const file = e.dataTransfer.files[0];
  if (file) input.value = await file.text();
});

// Ctrl/Cmd+Enter to run
input.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run();
});
