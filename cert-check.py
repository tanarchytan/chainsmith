#!/usr/bin/env python3
"""Certificate bundle fixer + validator (CLI and local web UI).

What it does
------------
Given a hostname or a PEM/DER certificate file, it:
  1. Picks the leaf (end-entity) cert.
  2. Builds a candidate pool of intermediates from the input file *and* by
     walking AIA CA-Issuers, then links leaf -> ... -> root, preferring certs
     that are NOT revoked and NOT expired.
  3. Checks each cert for validity, CRL + OCSP revocation, and signature linkage.
  4. Detects same-key reissues: if the input carried a REVOKED intermediate and
     a valid replacement exists with the same key (SKI) but a new serial, it
     swaps it in and reports the swap. (Common when a CA revokes an intermediate
     and reissues it with the same key -- revocation is keyed on serial, so the
     reissue stays valid and the old leaf still verifies against it.)
  5. Emits a corrected bundle (leaf + intermediates, root excluded) -- but
     REFUSES to write one that still contains a revoked/expired cert or a broken
     signature link, exiting non-zero instead. A fixer must never ship a known-bad
     chain.

CA-agnostic: every endpoint it touches comes from the certificate's own
AIA/CRL/OCSP extensions -- no certificate-transparency logs, no third-party
proxies.

Usage
-----
  python cert-check.py --fix example.com -o example-bundle.crt
  python cert-check.py --file old-bundle.crt -o fixed-bundle.crt
  python cert-check.py --file some.crt --check       # report only, write nothing
  python cert-check.py --serve                        # web UI on :8080

Deps: pip install cryptography requests
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import ssl
import socket
import sys
import urllib.parse
import base64
import datetime
import html as html_mod
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

HTTP_TIMEOUT = 7
MAX_CHAIN = 8
EXPIRY_WARN_DAYS = 30
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER

# Module-level CRL cache: many certs in a chain share one CRL endpoint.
_CRL_CACHE = {}


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


# --------------------------------------------------------------------------- #
# Low-level cert helpers
# --------------------------------------------------------------------------- #
def is_self_signed(cert):
    return cert.subject == cert.issuer


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def ski(cert):
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex()
    except x509.ExtensionNotFound:
        return None


def aki(cert):
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier.hex()
    except (x509.ExtensionNotFound, AttributeError):
        return None


def is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def load_certs(data):
    """Parse one DER cert or a PEM file containing one-or-more certs."""
    if b"BEGIN CERTIFICATE" not in data:
        return [x509.load_der_x509_certificate(data)]
    certs = []
    marker = b"-----END CERTIFICATE-----"
    for part in data.split(marker):
        if b"BEGIN CERTIFICATE" in part:
            certs.append(x509.load_pem_x509_certificate(part + marker))
    return certs


def pick_leaf(certs):
    """Choose the end-entity cert: one that isn't acting as a CA/issuer."""
    ca_subjects = {c.subject for c in certs if is_ca(c)}
    leaves = [c for c in certs if c.subject not in ca_subjects]
    return leaves[0] if leaves else certs[0]


def get_host_chain(host, port=443):
    """Return (leaf, [certs the server actually presents])."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            leaf_der = ssock.getpeercert(binary_form=True)
            sent = []
            try:
                # get_unverified_chain() yields DER bytes on most builds, but
                # cert-like objects on some -- handle both, don't swallow.
                for entry in ssock.get_unverified_chain() or []:
                    der = (entry if isinstance(entry, (bytes, bytearray))
                           else entry.public_bytes(ssl.Encoding.DER))
                    sent.append(x509.load_der_x509_certificate(der))
            except (ssl.SSLError, ValueError):
                sent = []
    leaf = x509.load_der_x509_certificate(leaf_der)
    if not sent:
        sent = [leaf]
    return leaf, sent


def fetch_issuer(url):
    try:
        data = requests.get(url, timeout=HTTP_TIMEOUT).content
        return load_certs(data)[0]
    except (requests.RequestException, ValueError, IndexError):
        return None


def ca_issuer_urls(cert):
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in aia
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]


def verify_signed_by(cert, issuer):
    """True if issuer's key signed cert. Handles RSA (PKCS1v15/PSS), ECDSA, EdDSA."""
    pub = issuer.public_key()
    data = cert.tbs_certificate_bytes
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            for pad in (
                padding.PKCS1v15(),
                padding.PSS(mgf=padding.MGF1(cert.signature_hash_algorithm),
                            salt_length=padding.PSS.AUTO),
            ):
                try:
                    pub.verify(cert.signature, data, pad, cert.signature_hash_algorithm)
                    return True
                except Exception:
                    continue
            return False
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, data, ec.ECDSA(cert.signature_hash_algorithm))
            return True
        if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(cert.signature, data)  # EdDSA takes no hash/padding
            return True
    except Exception:
        return False
    return False


# --------------------------------------------------------------------------- #
# Validity + revocation
# --------------------------------------------------------------------------- #
def validity_status(cert):
    now = now_utc()
    if cert.not_valid_after_utc < now:
        return "EXPIRED"
    if cert.not_valid_before_utc > now:
        return "NOT_YET_VALID"
    return "OK"


def _load_crl(url):
    if url not in _CRL_CACHE:
        try:
            _CRL_CACHE[url] = x509.load_der_x509_crl(
                requests.get(url, timeout=HTTP_TIMEOUT).content)
        except (requests.RequestException, ValueError):
            _CRL_CACHE[url] = None
    return _CRL_CACHE[url]


def crl_status(cert):
    """Return (status, detail). status in GOOD / REVOKED / UNKNOWN."""
    try:
        dps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return "UNKNOWN", "no CRL DP"
    saw_crl = False
    for dp in dps:
        for name in dp.full_name or []:
            crl = _load_crl(name.value)
            if crl is None:
                continue
            saw_crl = True
            revoked = crl.get_revoked_certificate_by_serial_number(
                cert.serial_number)
            if revoked:
                try:
                    reason = revoked.extensions.get_extension_for_class(
                        x509.CRLReason).value.reason.name
                except x509.ExtensionNotFound:
                    reason = "unspecified"
                return "REVOKED", f"{name.value} ({reason}, {revoked.revocation_date_utc})"
    return ("GOOD", "not on CRL") if saw_crl else ("UNKNOWN", "CRL unreachable")


def ocsp_status(cert, issuer):
    if issuer is None:
        return "UNKNOWN", "no issuer"
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return "UNKNOWN", "no AIA"
    from cryptography.x509 import ocsp
    for d in aia:
        if d.access_method != AuthorityInformationAccessOID.OCSP:
            continue
        url = d.access_location.value
        try:
            req = (ocsp.OCSPRequestBuilder()
                   .add_certificate(cert, issuer, hashes.SHA256()).build())
            r = requests.post(url, data=req.public_bytes(DER),
                              headers={"Content-Type": "application/ocsp-request"},
                              timeout=HTTP_TIMEOUT)
            resp = ocsp.load_der_ocsp_response(r.content)
            if resp.response_status.name != "SUCCESSFUL":
                return "UNKNOWN", f"{url} ({resp.response_status.name})"
            return resp.certificate_status.name.replace("REVOKED", "REVOKED"), url
        except (requests.RequestException, ValueError) as e:
            return "UNKNOWN", f"{url} ({e})"
    return "UNKNOWN", "no OCSP URL"


def is_revoked_by_crl(cert):
    """Cheap, issuer-free revocation check used during candidate selection."""
    return crl_status(cert)[0] == "REVOKED"


# --------------------------------------------------------------------------- #
# Chain building from a candidate pool
# --------------------------------------------------------------------------- #
def gather_candidates(leaf, observed):
    """Pool = intermediates from input + everything reachable via AIA."""
    pool = {}

    def add(cert):
        if cert is not None:
            pool[fingerprint(cert)] = cert

    for cert in observed or []:
        if fingerprint(cert) != fingerprint(leaf):
            add(cert)

    # Walk AIA from the leaf upward to fetch canonical issuers.
    frontier = [leaf]
    seen = set()
    for _ in range(MAX_CHAIN):
        nxt = []
        for cur in frontier:
            fp = fingerprint(cur)
            if fp in seen or is_self_signed(cur):
                continue
            seen.add(fp)
            for url in ca_issuer_urls(cur):
                issuer = fetch_issuer(url)
                if issuer is not None:
                    add(issuer)
                    nxt.append(issuer)
        frontier = nxt
        if not frontier:
            break
    return list(pool.values())


def link_chain(leaf, pool):
    """Link leaf -> root through pool, preferring valid (non-revoked,
    unexpired) issuers so a revoked cert loses to its good same-key reissue."""
    chain = [leaf]
    cur = leaf
    used = {fingerprint(leaf)}
    for _ in range(MAX_CHAIN):
        if is_self_signed(cur):
            break
        cands = [c for c in pool
                 if fingerprint(c) not in used
                 and c.subject == cur.issuer
                 and verify_signed_by(cur, c)]
        if not cands:
            break
        # Sort: not-revoked first, then not-expired, then latest notBefore.
        cands.sort(key=lambda c: (
            is_revoked_by_crl(c),
            validity_status(c) != "OK",
            -c.not_valid_before_utc.timestamp(),
        ))
        nxt = cands[0]
        chain.append(nxt)
        used.add(fingerprint(nxt))
        cur = nxt
    return chain


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def evaluate(leaf, observed):
    """Build the best chain and produce a structured report."""
    pool = gather_candidates(leaf, observed)
    chain = link_chain(leaf, pool)

    report = {
        "chain": chain,
        "certs": [],
        "findings": [],
        "swaps": [],
        "linkage_ok": True,
        "fatal": [],
    }

    def add(level, text):
        report["findings"].append({"level": level, "text": text})

    if observed:
        non_root = [c for c in observed if not is_self_signed(c)]
        obs_fps = {fingerprint(c) for c in observed}
        chain_fps = {fingerprint(c) for c in chain}
        correct_inter = [c for c in chain[1:] if not is_self_signed(c)]

        if len(observed) == 1:
            add("warn", "Server sends the leaf only — clients without the "
                        "intermediate cached will fail. (incomplete chain)")
        if any(fingerprint(c) not in obs_fps for c in correct_inter):
            add("warn", "Incomplete: the server does not send the correct intermediate.")
        for c in observed:
            fp = fingerprint(c)
            if fp == fingerprint(leaf):
                continue
            if is_self_signed(c):
                add("note", f"Contains anchor: server sends the root "
                            f"{c.subject.rfc4514_string()} (redundant; omit it).")
            elif fp not in chain_fps:
                add("note", f"Extra/mismatched cert: server sends "
                            f"{c.subject.rfc4514_string()} which is not part of the valid path.")

        # Same-key reissue swap detection: a revoked observed intermediate
        # whose key (SKI) reappears as a different, valid serial in the chain.
        chain_inter = [c for c in chain[1:] if not is_self_signed(c)]
        for o in non_root:
            if fingerprint(o) == fingerprint(leaf):
                continue
            if crl_status(o)[0] != "REVOKED":
                continue
            replacement = next((c for c in chain_inter
                                if ski(c) and ski(c) == ski(o)
                                and c.serial_number != o.serial_number), None)
            if replacement is not None:
                report["swaps"].append({
                    "subject": o.subject.rfc4514_string(),
                    "old_serial": hex(o.serial_number),
                    "new_serial": hex(replacement.serial_number),
                    "ski": ski(o),
                })
                add("error", f"Served intermediate {o.subject.rfc4514_string()} "
                             f"(serial {hex(o.serial_number)}) is REVOKED — replaced with "
                             f"valid same-key reissue {hex(replacement.serial_number)}. "
                             f"Server must redeploy.")
            else:
                report["fatal"].append(
                    f"revoked intermediate {o.subject.rfc4514_string()} "
                    f"(serial {hex(o.serial_number)}) has no valid replacement")
                add("error", f"Served intermediate {o.subject.rfc4514_string()} "
                             f"(serial {hex(o.serial_number)}) is REVOKED and no valid "
                             f"replacement is available.")

    for i, cert in enumerate(chain):
        issuer = chain[i + 1] if i + 1 < len(chain) else None
        label = "LEAF" if i == 0 else ("ROOT" if is_self_signed(cert) else "INT")
        vstat = validity_status(cert)
        sig = None if issuer is None else verify_signed_by(cert, issuer)
        if issuer is not None and not sig:
            report["linkage_ok"] = False
        crl = ocsp = ("SKIP", "root")
        if not is_self_signed(cert):
            crl = crl_status(cert)
            ocsp = ocsp_status(cert, issuer)
        revoked = crl[0] == "REVOKED" or ocsp[0] == "REVOKED"
        info = {
            "label": label, "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "fp": fingerprint(cert), "serial": hex(cert.serial_number),
            "validity": vstat, "sig": sig, "crl": crl, "ocsp": ocsp,
            "revoked": revoked,
        }
        report["certs"].append(info)

        # Fatal gates (root excluded -- it is the trust anchor, not shipped).
        if label != "ROOT":
            subj = cert.subject.rfc4514_string()
            if revoked:
                report["fatal"].append(f"{label} {subj} is REVOKED")
                add("error", f"{label} {subj} is REVOKED.")
            if vstat != "OK":
                report["fatal"].append(f"{label} {subj} is {vstat}")
                add("error", f"{label} {subj} is {vstat}.")
            elif (cert.not_valid_after_utc - now_utc()).days < EXPIRY_WARN_DAYS:
                add("warn", f"{label} {subj} expires in "
                            f"{(cert.not_valid_after_utc - now_utc()).days} days.")
            if sig is False:
                report["fatal"].append(
                    f"{label} signature does not verify against its issuer")
                add("error", f"{label} signature does not verify against its issuer.")

    # Served-but-not-used certs: intermediates the server presented that are not
    # in the corrected chain (revoked or mismatched). Shown so the operator sees
    # exactly what to replace.
    report["served_rejected"] = []
    if observed:
        built_fps = {fingerprint(c) for c in chain}
        for c in observed:
            f = fingerprint(c)
            if f == fingerprint(leaf) or is_self_signed(c) or f in built_fps:
                continue
            issuer_cert = next((x for x in chain if x.subject == c.issuer), None)
            crl = crl_status(c)
            ocsp = ocsp_status(c, issuer_cert) if issuer_cert else ("UNKNOWN", "no issuer")
            report["served_rejected"].append({
                "label": "INT (served — not used)",
                "subject": c.subject.rfc4514_string(),
                "issuer": c.issuer.rfc4514_string(),
                "not_before": c.not_valid_before_utc,
                "not_after": c.not_valid_after_utc,
                "fp": f, "serial": hex(c.serial_number),
                "validity": validity_status(c),
                "sig": verify_signed_by(c, issuer_cert) if issuer_cert else None,
                "crl": crl, "ocsp": ocsp,
                "reason": ("REVOKED" if (crl[0] == "REVOKED" or ocsp[0] == "REVOKED")
                           else "not part of the valid path"),
            })

    # Need at least leaf + one issuer to ship a usable chain.
    if len([c for c in chain if not is_self_signed(c)]) < 2 and not is_self_signed(leaf):
        report["fatal"].append(
            "could not complete chain (no intermediate found via input or AIA)")
        add("error", "Could not complete the chain — no valid intermediate found "
                     "via input or AIA.")

    report["fixable"] = not report["fatal"]
    if all(f["level"] == "note" for f in report["findings"]) and report["fixable"]:
        add("ok", "Chain is correctly configured.")
    report["grade"] = ("ERROR" if any(f["level"] == "error" for f in report["findings"])
                       else "WARN" if any(f["level"] == "warn" for f in report["findings"])
                       else "OK")
    return report


def bundle_bytes(chain):
    """leaf + intermediates, root excluded -- the standard server fullchain."""
    return b"".join(c.public_bytes(PEM) for c in chain if not is_self_signed(c))


# --------------------------------------------------------------------------- #
# Text reporting (CLI)
# --------------------------------------------------------------------------- #
_LEVEL_TAG = {"error": "ERROR", "warn": "WARN ", "note": "NOTE ", "ok": "OK   "}


def format_text(report):
    out = []
    out.append(f"GRADE: {report['grade']}")
    chain = report["chain"]
    out.append(f"Chain: {len(chain)} certs "
               f"({sum(1 for c in chain if not is_self_signed(c))} shippable, "
               f"root excluded)")
    out.append("")
    out.append("FINDINGS")
    if not report["findings"]:
        out.append("  (none)")
    for f in report["findings"]:
        out.append(f"  {_LEVEL_TAG[f['level']]}  {f['text']}")
    for c in report["certs"]:
        out.append(f"\n--- {c['label']} ---")
        out.append(f"Subject: {c['subject']}")
        out.append(f"Issuer:  {c['issuer']}")
        out.append(f"Valid:   {c['not_before']} -> {c['not_after']}  [{c['validity']}]")
        out.append(f"Serial:  {c['serial']}")
        out.append(f"SHA256:  {c['fp']}")
        if c["label"] != "ROOT":
            out.append(f"CRL:     {c['crl'][0]} ({c['crl'][1]})")
            out.append(f"OCSP:    {c['ocsp'][0]} ({c['ocsp'][1]})")
        if c["sig"] is not None:
            out.append(f"Sig:     {'VALID' if c['sig'] else 'INVALID'}")
    for c in report.get("served_rejected", []):
        out.append(f"\n--- {c['label']} — {c['reason']} ---")
        out.append(f"Subject: {c['subject']}")
        out.append(f"Issuer:  {c['issuer']}")
        out.append(f"Valid:   {c['not_before']} -> {c['not_after']}  [{c['validity']}]")
        out.append(f"Serial:  {c['serial']}")
        out.append(f"SHA256:  {c['fp']}")
        out.append(f"CRL:     {c['crl'][0]} ({c['crl'][1]})")
        out.append(f"OCSP:    {c['ocsp'][0]} ({c['ocsp'][1]})")
        if c["sig"] is not None:
            out.append(f"Sig:     {'VALID' if c['sig'] else 'INVALID'}")
    out.append("")
    if not report["fixable"]:
        out.append("RESULT:  CANNOT FIX — see ERROR findings above")
    elif report["grade"] == "OK":
        out.append("RESULT:  OK — chain is correctly configured, nothing to fix")
    else:
        out.append("RESULT:  FIXABLE — corrected bundle (leaf + intermediate, root excluded)")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# HTML reporting (web UI)
# --------------------------------------------------------------------------- #
PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Bundle Fixer</title>
<style>
body{font-family:system-ui;background:#0b1220;color:#e2e8f0;padding:20px}
.card{background:#111827;padding:20px;border-radius:12px;max-width:1200px;margin:auto}
textarea,input,button{width:100%;padding:8px;margin:6px 0;background:#1f2937;color:#e2e8f0;border:1px solid #374151;border-radius:6px;box-sizing:border-box}
button{background:#2563eb;cursor:pointer}
pre{background:#0f172a;padding:14px;border-radius:8px;overflow:auto;white-space:pre-wrap;font-size:12px;line-height:1.4}
.ok{color:#10b981;font-weight:600}.bad{color:#ef4444;font-weight:700;background:#450a0a;padding:1px 4px;border-radius:3px}.warn{color:#f59e0b}
.fix{background:#1e3a8a;padding:12px;border-radius:8px;margin:12px 0}
a.dl{background:#10b981;color:#000;padding:6px 10px;border-radius:5px;text-decoration:none;font-weight:600}
</style></head><body><div class="card">
<h1>Certificate Bundle Fixer</h1>
<form method="post">
<label>Leaf PEM or full chain:</label><textarea name="pem" rows="8"></textarea>
<label>Or hostname:</label><input name="host" placeholder="example.com">
<button>Fix &amp; Validate</button>
</form>
<pre>RESULT</pre>
</div></body></html>"""

_STATUS_CLASS = {"GOOD": "ok", "REVOKED": "bad", "VALID": "ok", "INVALID": "bad",
                 "OK": "ok", "EXPIRED": "bad", "NOT_YET_VALID": "bad"}
_LEVEL_CLASS = {"error": "bad", "warn": "warn", "note": "ok", "ok": "ok"}
_GRADE_CLASS = {"OK": "ok", "WARN": "warn", "ERROR": "bad"}


def _span(status):
    cls = _STATUS_CLASS.get(status, "warn")
    return f"<span class={cls}>{status}</span>"


def format_html(report):
    out = []
    out.append(f"GRADE: <span class={_GRADE_CLASS[report['grade']]}>{report['grade']}</span>")
    chain = report["chain"]
    out.append(f"Chain: {len(chain)} certs\n")
    for f in report["findings"]:
        tag = {"error": "ERROR", "warn": "WARN ", "note": "NOTE ", "ok": "OK   "}[f["level"]]
        out.append(f"<span class={_LEVEL_CLASS[f['level']]}>{tag}  "
                   f"{html_mod.escape(f['text'])}</span>")
    for c in report["certs"]:
        out.append(f"\n--- {c['label']} ---")
        out.append(f"Subject: {html_mod.escape(c['subject'])}")
        out.append(f"Issuer:  {html_mod.escape(c['issuer'])}")
        out.append(f"Valid:   {c['not_before']} -> {c['not_after']} {_span(c['validity'])}")
        out.append(f"SHA256:  {c['fp']}")
        if c["label"] != "ROOT":
            out.append(f"CRL:     {_span(c['crl'][0])} {html_mod.escape(c['crl'][1])}")
            out.append(f"OCSP:    {_span(c['ocsp'][0])} {html_mod.escape(c['ocsp'][1])}")
        if c["sig"] is not None:
            out.append(f"Sig:     {_span('VALID' if c['sig'] else 'INVALID')}")
    if report.get("served_rejected"):
        out.append("\n<span class=bad>SERVED — NOT USED (replace these):</span>")
        for c in report["served_rejected"]:
            out.append(f"\n--- {html_mod.escape(c['label'])} — "
                       f"<span class=bad>{html_mod.escape(c['reason'])}</span> ---")
            out.append(f"Subject: {html_mod.escape(c['subject'])}")
            out.append(f"Issuer:  {html_mod.escape(c['issuer'])}")
            out.append(f"Valid:   {c['not_before']} -> {c['not_after']} {_span(c['validity'])}")
            out.append(f"SHA256:  {c['fp']}")
            out.append(f"CRL:     {_span(c['crl'][0])} {html_mod.escape(c['crl'][1])}")
            out.append(f"OCSP:    {_span(c['ocsp'][0])} {html_mod.escape(c['ocsp'][1])}")
            if c["sig"] is not None:
                out.append(f"Sig:     {_span('VALID' if c['sig'] else 'INVALID')}")
    out.append("")
    if not report["fixable"]:
        out.append("<span class=bad>CANNOT FIX — see ERROR findings above</span>")
    else:
        ok = report["grade"] == "OK"
        fname = "fullchain.pem" if ok else "fullchain-fixed.pem"
        title = ("Chain is correctly configured" if ok
                 else "Corrected bundle (leaf + intermediate, root excluded)")
        b64 = base64.b64encode(bundle_bytes(chain)).decode()
        out.append(f"<div class=fix><b>{title}:</b><br>"
                   f"<a class=dl href='data:application/x-pem-file;base64,{b64}' "
                   f"download='{fname}'>Download {fname}</a></div>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Web server
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._send(PAGE.replace("RESULT", ""))

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode())
        pem = data.get("pem", [""])[0]
        host = data.get("host", [""])[0].strip()
        try:
            if pem:
                certs = load_certs(pem.encode())
                result = format_html(evaluate(pick_leaf(certs), certs))
            elif host:
                leaf, sent = get_host_chain(host)
                result = format_html(evaluate(leaf, sent))
            else:
                result = "Enter PEM or host"
        except Exception as e:
            result = f"<span class=bad>Error: {html_mod.escape(str(e))}</span>"
        self._send(PAGE.replace("RESULT", result))

    def log_message(self, *args):
        pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def default_out_name(leaf):
    try:
        cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        cn = "fullchain"
    return cn.replace("*", "wildcard").replace(".", "") + "-bundle.crt"


def run_cli(args):
    if args.fix:
        print(f"Fetching leaf from {args.fix}:443 ...", file=sys.stderr)
        leaf, observed = get_host_chain(args.fix)
    else:
        with open(args.file, "rb") as f:
            certs = load_certs(f.read())
        leaf, observed = pick_leaf(certs), certs

    report = evaluate(leaf, observed)
    print(format_text(report))

    if args.check:
        return 0 if report["fixable"] else 1
    if not report["fixable"]:
        print("\nRefusing to write a bundle with known-bad certs.", file=sys.stderr)
        return 1

    out = args.out or default_out_name(leaf)
    with open(out, "wb") as f:
        f.write(bundle_bytes(report["chain"]))
    print(f"\nWrote fixed bundle -> {out}", file=sys.stderr)
    return 0


def main():
    try:  # ensure em-dashes etc. render on Windows cp1252 consoles
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    p = argparse.ArgumentParser(description="Certificate bundle fixer + validator")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--fix", metavar="HOST", help="fetch leaf from host:443")
    src.add_argument("--file", metavar="PATH", help="read leaf/bundle from PEM/DER file")
    src.add_argument("--serve", action="store_true", help="run web UI on :8080")
    p.add_argument("-o", "--out", metavar="PATH", help="output bundle path")
    p.add_argument("--check", action="store_true",
                   help="report only; exit 1 if not fixable, write nothing")
    args = p.parse_args()

    if args.serve:
        print("http://localhost:8080")
        HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
        return 0
    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
