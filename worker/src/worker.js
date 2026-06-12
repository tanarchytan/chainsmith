// Thin Worker. The only server-side job is /proxy: relay an http(s) fetch to a
// certificate's AIA / CRL / OCSP endpoint, which a browser cannot reach directly
// (CORS + http mixed content). Works with any CA — the target URL comes from the
// pasted certificate's own extensions, not a hardcoded list.
//
// SSRF guard: only public http(s) targets are allowed. Private, loopback,
// link-local and cloud-metadata addresses are refused so the relay cannot be
// used to probe internal networks. Responses are size-capped.
//
// Anti-abuse guard: /proxy is only for this app's own page. The client sets a
// custom header on every call; a cross-site browser request cannot set it
// without a CORS preflight that we never approve, so other websites can't use
// the relay as a free proxy. (Not a hard boundary against a server-side caller
// -- pair with Cloudflare Access / rate limiting if you need that -- but it
// stops drive-by browser abuse without depending on Origin/Referer, which
// browsers omit on same-origin GETs.)
const MAX_BYTES = 5 * 1024 * 1024;
const APP_HEADER = "x-chainsmith";

function originAllowed(request) {
  const self = new URL(request.url).origin;
  const origin = request.headers.get("Origin");
  if (origin && origin !== self) return false; // explicit cross-origin -> block
  return request.headers.get(APP_HEADER) === "1"; // app marker required
}

function isBlockedHost(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".home.arpa")
  )
    return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127) return true; // this-host, private, loopback
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80"))
    return true; // IPv6 loopback / ULA / link-local
  return false;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/proxy") {
      // Not the relay -> static asset routing handles /, /app.js, etc.
      return new Response("Not found", { status: 404 });
    }
    if (!originAllowed(request)) return new Response("forbidden", { status: 403 });

    const target = url.searchParams.get("url");
    if (!target) return new Response("missing url", { status: 400 });
    let t;
    try {
      t = new URL(target);
    } catch {
      return new Response("bad url", { status: 400 });
    }
    if (!/^https?:$/.test(t.protocol) || isBlockedHost(t.hostname))
      return new Response("forbidden target", { status: 403 });

    const init = { method: request.method, headers: {}, redirect: "follow" };
    const ct = request.headers.get("content-type");
    if (ct) init.headers["content-type"] = ct;
    if (request.method === "POST") init.body = await request.arrayBuffer();

    let resp;
    try {
      resp = await fetch(t.toString(), init);
    } catch (e) {
      return new Response(`upstream fetch failed: ${e}`, { status: 502 });
    }
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > MAX_BYTES)
      return new Response("response too large", { status: 502 });
    return new Response(buf, {
      status: resp.status,
      headers: {
        "Content-Type": resp.headers.get("content-type") || "application/octet-stream",
        "Cache-Control": "no-store",
      },
    });
  },
};
