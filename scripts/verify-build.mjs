import { readFile, readdir } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const packageJson = JSON.parse(
  await readFile(new URL("package.json", root), "utf8"),
);
if (
  packageJson.dependencies &&
  Object.keys(packageJson.dependencies).length !== 0
) {
  throw new Error(
    "The static lesson must not ship runtime package dependencies.",
  );
}

const dist = new URL("dist/", root);
const index = await readFile(new URL("index.html", dist), "utf8");
if (!index.includes("/crypto-lab-ipsec-ike/assets/")) {
  throw new Error("Built assets do not use the GitHub Pages base path.");
}
if (index.includes("sourceMappingURL")) {
  throw new Error("Production index unexpectedly exposes a source map.");
}

const assetsUrl = new URL("assets/", dist);
const assets = await readdir(assetsUrl);
const scripts = assets.filter((name) => name.endsWith(".js"));
const styles = assets.filter((name) => name.endsWith(".css"));
if (scripts.length !== 1 || styles.length !== 1) {
  throw new Error(
    `Expected one JavaScript and one CSS asset, found ${assets.join(", ")}.`,
  );
}
for (const asset of assets) {
  if (asset.endsWith(".map"))
    throw new Error(`Unexpected source map: ${asset}`);
  const bytes = await readFile(new URL(asset, assetsUrl));
  if (bytes.length === 0) throw new Error(`Empty production asset: ${asset}`);
}

const script = await readFile(new URL(`assets/${scripts[0]}`, dist), "utf8");
for (const requiredClaim of [
  "Lookup, precheck, authenticate, then commit",
  "protected Delete",
  "Exact protected bytes",
  "Load fixed evidence",
]) {
  if (!script.includes(requiredClaim)) {
    throw new Error(
      `Production bundle is missing learner claim: ${requiredClaim}`,
    );
  }
}

console.info(
  `verified static build: 1 HTML, ${scripts.length} JS, ${styles.length} CSS`,
);
