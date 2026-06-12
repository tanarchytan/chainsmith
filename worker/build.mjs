// Bundle the client-side app (core.js + client.js + pkijs/asn1js) into a single
// browser ESM module served as a static asset. No external CDN dependency.
import { build } from "esbuild";

await build({
  entryPoints: ["src/client.js"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  outfile: "public/app.js",
  minify: true,
  legalComments: "none",
});
console.log("built public/app.js");
