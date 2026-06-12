# chainsmith — client-side TLS chain auditor & bundle fixer (Cloudflare Worker)

A console-styled web tool that audits a TLS certificate chain (simple SSL-Labs style) and emits a corrected, non-revoked server bundle. CA-agnostic — every endpoint it checks comes from the certificate's own extensions.

**All certificate logic runs client-side, in the browser** (parsing, chain-building, CRL/OCSP/signature checks, and — when an intermediate has been revoked but the issuer published a same-key reissue — the swap, plus bundle generation; `pkijs` + WebCrypto, bundled into `public/app.js`). The Worker is a thin **same-origin relay** (`/proxy`) that fetches the certificate's `http(s)` AIA/CRL/OCSP endpoints, which a browser cannot reach directly (CORS + http mixed-content). The relay refuses private/loopback/metadata targets, so it can't be used to probe internal networks.

Same logic and verdicts as the Python `cert-check.py`; only the network layer is swapped (browser → `/proxy`).

## Grading

| Grade | Meaning |
|---|---|
| 🟢 **OK** | Server sends leaf + correct intermediate(s); valid path. (A sent root is a blue NOTE only.) |
| 🟡 **WARN** | Incomplete — leaf only, or the correct intermediate isn't sent. |
| 🔴 **ERROR** | An actual problem — a served cert is **revoked**, expired, has a bad signature, or no valid chain can be built. |

A corrected `fullchain-fixed.pem` download is offered whenever the chain is fixable (generated in-browser via a Blob).

## Scope

Paste/upload a PEM cert or chain. A browser (and a Worker) can't read the chain a remote server *presents*, so live host scanning stays in the Python CLI.

## Safe to deploy publicly

The `/proxy` relay is guarded two ways so it can be exposed on the open internet:

- **SSRF:** only public `http(s)` targets; private / loopback / link-local / CGNAT / cloud-metadata addresses are refused (and responses are capped at 5 MB).
- **Anti-abuse:** `/proxy` only serves requests from this app's own page. The client sends an `X-Chainsmith: 1` header; a cross-site browser request can't set it without a CORS preflight the Worker never approves, so other websites can't use the relay as a free proxy. (This does not stop a determined server-side caller — add Cloudflare Access or a rate-limit binding if you need hard auth.) Any programmatic client of `/proxy` must send `X-Chainsmith: 1`.

## Develop

```bash
npm install
npm run build        # esbuild -> public/app.js
npm run dev          # build + wrangler dev (http://127.0.0.1:8787)
npm test             # offline self-test; `node test.mjs <host>` for a live audit
```

## Deploy

**Recommended — Cloudflare Workers Builds (Git integration, no secrets):**
Dashboard → Workers & Pages → Create → Import `tanarchytan/chainsmith`, then set:

| Field | Value |
|---|---|
| Root directory | `worker` |
| Build command | `npm run build` |
| Deploy command | `npx wrangler deploy` |

Cloudflare auto-installs deps (incl. the wrangler version pinned in `package.json`), builds `public/app.js`, and deploys on every push to `main`. No API token needed.

**Or manually:**
```bash
npx wrangler login
npm run deploy       # builds public/app.js, then wrangler deploy
```

No bindings or secrets. `wrangler.toml` serves `public/` as static assets and runs `src/worker.js` for `/proxy`.

## Files

```
public/index.html  console UI
public/app.js       built client bundle (core + client + pkijs)  [gitignored, built]
src/core.js         transport-injected fixer logic (shared by browser + node test)
src/client.js       browser entry: /proxy transport + console rendering
src/worker.js       Worker: /proxy relay (SSRF-guarded against private targets)
build.mjs           esbuild bundler
test.mjs            node test harness (offline self-test + optional live audit)
```

## Verified

`npm test` runs an offline pipeline self-test. The full client-side flow was also
driven in a real headless browser against `wrangler dev`: pasting a chain that
contained a revoked intermediate, the in-browser app round-tripped AIA/CRL/OCSP
through `/proxy`, graded ERROR, detected the same-key reissue swap, and offered
the corrected download — no page or console errors.
