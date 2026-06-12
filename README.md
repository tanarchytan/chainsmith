# chainsmith — TLS certificate chain auditor & bundle fixer

`cert-check.py` — a single-file tool that audits a TLS certificate chain and emits a **correct, non-revoked** server bundle. CA-agnostic: every endpoint it checks comes from the certificate's own extensions.

It only ever talks to the **issuer's own endpoints** — AIA (CA-Issuers), CRL, and OCSP. No certificate-transparency logs, no third-party proxies.

## Why this exists

A common, hard-to-spot outage: a CA **revokes an intermediate** and publishes a **same-key reissue** — a new certificate with the **same Subject and same key (same SKI)** but a new serial and validity window. Because revocation is keyed on **serial number, not key**:

- A leaf signed before the reissue still verifies against the new intermediate.
- But any server still **serving the old, revoked** intermediate now fails revocation checks → *"Not trusted (certificate revoked)"*, even though nothing about the leaf changed.

This tool detects that case, swaps the revoked intermediate for the valid same-key reissue (fetched from the issuer's AIA), and writes a deployable bundle — refusing to emit anything that still contains a revoked, expired, or wrongly-signed cert. It also handles the everyday cases: incomplete chains (missing intermediate), a wrongly-bundled intermediate, and a needlessly-shipped root anchor.

## Requirements

```
pip install cryptography requests
```

Python 3.13+ (uses `ssl.SSLSocket.get_unverified_chain`).

## Usage

```bash
# Audit a live host and write the fixed bundle
python cert-check.py --fix example.com -o example-bundle.crt

# Audit a host, report only (exit 1 if not fixable), write nothing
python cert-check.py --fix example.com --check

# Fix a bundle file you already have (e.g. an old chain with a revoked intermediate)
python cert-check.py --file old-chain.crt -o fixed.crt

# Local web UI on http://localhost:8080
python cert-check.py --serve
```

If `-o` is omitted, the bundle is written to `<cn>-bundle.crt`.

## What it checks

For the leaf and every intermediate (root excluded from the output bundle):

| Check | Detail |
|---|---|
| Validity | not expired / not yet valid; warns < 30 days |
| **CRL** | fetched from the cert's CRL distribution point, matched by serial |
| **OCSP** | POSTed to the AIA OCSP responder |
| Revocation gate | a cert is treated **revoked if *either* CRL or OCSP says so** |
| Signature | each link verified against its issuer (RSA PKCS#1 v1.5, then PSS) |
| Chain shape | flags incomplete (missing intermediate), extra/mismatched certs, and a sent root anchor |
| **Same-key swap** | a revoked intermediate whose key (SKI) reappears as a valid different-serial cert is swapped for the good one, and reported |

The output bundle is `leaf + intermediate(s)`, **root excluded** (the standard server `fullchain`). The tool **exits non-zero and writes nothing** if the resulting chain would still contain a revoked / expired / bad-signature cert.

## How it builds the chain

1. Pick the leaf (the end-entity cert — the one not acting as a CA).
2. Build a candidate intermediate pool from the **input certs** *plus* everything reachable by walking **AIA CA-Issuers** URLs.
3. Link leaf → root, at each hop preferring a candidate that is **not revoked** and **not expired** — so a revoked cert always loses to its valid same-key reissue.

## Example — a host serving a revoked intermediate

```
python cert-check.py --fix logius.nl --check
```

Grades **ERROR**, lists the corrected chain, and — under **SERVED — NOT USED** —
shows the exact revoked intermediate the server is still sending (so you know
what to replace), then offers the corrected bundle. (Snapshot: `logius.nl` was
serving the revoked intermediate at the time of writing; a fixed host grades OK.)

## Verifying a generated bundle

Proof a fix is real, using openssl with full CRL checking against the issuer's CRLs:

```
# a chain that still serves a revoked intermediate
openssl verify -crl_check_all ...  ->  error 23: certificate revoked

# the generated bundle
openssl verify -crl_check_all ...  ->  OK
```

## Files

```
cert-check.py    the CLI tool (+ local web UI), incl. live host scanning
worker/          console-styled web app (client-side fixer + thin CF Worker relay)
CLAUDE.md        notes for AI assistants working in this repo
```

### Web app — `worker/`

A console-styled, SSL-Labs-lite web tool. **All cert logic runs client-side** (pkijs + WebCrypto); the Cloudflare Worker is a thin same-origin relay: `/proxy` fetches the certificate's `http(s)` AIA/CRL/OCSP (a browser can't — CORS + mixed content), and `/chain` opens a raw TLS 1.2 socket to read the chain a host actually presents. Both are SSRF-guarded. Enter a **hostname** to scan a live host, or **paste** a chain. Same verdicts as this CLI: 🟢 OK / 🟡 WARN (leaf-only/incomplete) / 🔴 ERROR (revoked/expired/bad-sig), plus a corrected `fullchain-fixed.pem` download generated in-browser. See `worker/README.md`.

## Notes

- Revocation gating needs the issuer's CRL/OCSP endpoints to be reachable. If they are blocked, those checks return `UNKNOWN` (never a false `GOOD`); the tool degrades to chain-completion + validity only.
- Regenerate a bundle whenever the leaf is reissued (its fingerprint changes) or the CA cycles intermediates again.
