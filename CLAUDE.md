# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file X.509 **certificate bundle fixer**, plus a client-side web app. CA-agnostic. It fetches/loads a leaf, builds the chain from input certs + AIA, checks revocation (CRL + OCSP), validity, and signature linkage, and emits a corrected server bundle. Its headline trick is the **same-key reissue swap** (below). User-facing docs live in `README.md`.

Keep all product copy and comments **generic** — no CA/customer names. The tool is universally usable; concrete deployment facts (specific fingerprints/hosts) live in memory, not the repo.

## Layout

```
cert-check.py    the CLI tool (+ local web UI), incl. live host scanning
worker/          console-styled web app: client-side fixer (pkijs+WebCrypto) +
                 a thin Cloudflare Worker /proxy relay for the CA's http endpoints
README.md        user-facing docs + the bug background
CLAUDE.md        this file
```

Generated bundles are not committed — produce them on demand with `--fix HOST -o ...`.

## The tool — `cert-check.py`

CLI and web (`--serve` → `localhost:8080`). Given a host (`--fix HOST`) or a PEM/DER file (`--file PATH`): picks the leaf, builds a candidate pool from input certs **plus** AIA CA-Issuers fetches, links leaf→root preferring certs that are **not revoked and not expired**. Per cert: validity, CRL + OCSP (revoked if *either* says so), signature linkage. Key behavior: **same-key reissue swap** — a REVOKED intermediate whose key (SKI) reappears as a valid different-serial cert is swapped in and the swap is reported. It **refuses to write** a bundle containing any revoked/expired/bad-sig cert (exits non-zero). Output = leaf+intermediates, root excluded, to `-o PATH` (default `<cn>-bundle.crt`); `--check` reports only.

```bash
pip install cryptography requests          # only deps

python cert-check.py --fix example.com -o example-bundle.crt
python cert-check.py --file old-bundle.crt --check     # report only
python cert-check.py --serve                           # web UI :8080
```

## The same-key reissue swap (the core trick)

When a CA **revokes an intermediate** and publishes a **reissue with the same key** (same Subject Key Identifier, new serial + validity), revocation — keyed on **serial, not key** — applies only to the old certificate. So:

- A leaf signed before the reissue still verifies against the new intermediate.
- A server still *serving* the revoked intermediate fails revocation checks, even though the leaf is fine.

The fixer pools both (input + AIA), links the chain preferring non-revoked/unexpired certs (so the revoked one loses to its reissue), reports the swap, and emits a clean bundle. This generalises to any CA.

## Conventions specific to this repo

- **Issuer-only sources.** Only ever fetch from the certificate's own AIA / CRL / OCSP endpoints (from its extensions). **Never a CT log or third-party proxy** — flaky and not authoritative.
- **TLS fetches intentionally skip verification** (`check_hostname=False`, `verify_mode=CERT_NONE`) — the point is to inspect broken/untrusted chains. Deliberate, not a bug.
- **`get_unverified_chain()` returns DER bytes** on this build (Py 3.14 / OpenSSL 3.0.18), not cert objects. `get_host_chain` handles both. Do **not** re-introduce a broad `except` that swallows the resulting `AttributeError` — that silently misreported every host as "leaf-only" once already.
- **Exceptions are typed, not bare.** Catch `requests.RequestException` / `ValueError` / `x509.ExtensionNotFound` so a single unreachable CRL/OCSP hop degrades to `UNKNOWN` instead of aborting — but never mask programming errors.
- **Revocation gate is fail-safe:** a cert counts as revoked if CRL **or** OCSP says so; network failure yields `UNKNOWN`, never a false `GOOD`. Keep it that way.
- Anchor/root detection relies on `cert.subject == cert.issuer`; output bundles exclude self-signed roots.
- Web UI (`--serve`) builds HTML from the same `evaluate()` report via `_span()` and the `ok`/`bad`/`warn` CSS classes — preserve those when editing output.

## `worker/` (the web app)

- **All cert logic is client-side** (`src/core.js`, `pkijs` + WebCrypto, bundled to `public/app.js` by `build.mjs`). The Worker (`src/worker.js`) is *only* a `/proxy` relay for the certificate's own `http(s)` AIA/CRL/OCSP — a browser can't fetch those (CORS + mixed content). Keep the SSRF guard (`isBlockedHost`, blocks private/loopback/metadata) intact — it must stay generic (any public issuer), not an allowlist.
- `src/core.js` is the JS port of `cert-check.py`'s logic with the **network layer injected** (`createCore(transport)`), so the same code runs in the browser (transport = `/proxy`) and the Node parity test (transport = direct fetch). Keep behaviour in step with the Python `evaluate()`.
- Grading rule (per David): 🟡 WARN only for leaf-only/incomplete; 🔴 ERROR for an actual issue (revoked/expired/bad-sig/unfixable); sent-root is a blue NOTE.
- **`/proxy` is public-safe:** SSRF denylist (`isBlockedHost`) + an anti-abuse guard (`originAllowed`) requiring the client's `X-Chainsmith: 1` header so other sites can't use the relay. `client.js` sends that header on every call — keep them in sync; any programmatic `/proxy` client must send it too. Don't weaken to Origin/Referer checks (browsers omit those on same-origin GETs → breaks the app).
- `public/app.js` is a build artifact (gitignored); run `npm run build` after editing `src/`.
