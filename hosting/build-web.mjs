import { access, readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";

for (const name of [
  "index.html",
  "styles.css",
  "favicon.svg",
  "service.json",
  "src/app.js",
  "src/api.js",
  "src/view.js",
  "src/crypto.js",
  "src/config.js",
  "src/icons.js",
  "src/lifecycle.js",
  "assets/vault-art.svg",
  "assets/fonts/BeVietnamPro-Regular.ttf",
]) {
  await access("web/" + name);
  if (name.endsWith(".js"))
    execFileSync(process.execPath, ["--check", "web/" + name]);
}
const view = await readFile("web/src/view.js", "utf8");
await access("web/delivery.css");
await access("web/loading.css");
execFileSync(process.execPath, ["--check", "web/src/loading.js"]);
execFileSync(process.execPath, ["--check", "web/src/remember.js"]);
for (const term of [
  "fingerprint",
  "ElGamal",
  "DH-3072",
  "Crypto Inspector",
  "private key",
  "public key",
]) {
  if (view.toLowerCase().includes(term.toLowerCase()))
    throw new Error("Technical key material in normal product UI: " + term);
}
console.log("SecretVault web assets validated. Static output: web/");
