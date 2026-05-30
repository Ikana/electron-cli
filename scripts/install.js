#!/usr/bin/env node

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const packageJson = require(path.join(root, "package.json"));
const version = packageJson.version;
const installDir = path.join(root, "bin", "downloaded");
const exe = process.platform === "win32" ? "electron-cli.exe" : "electron-cli";
const destination = path.join(installDir, exe);
const target = resolveTarget();

if (process.env.ELECTRON_CLI_SKIP_DOWNLOAD === "1") {
  process.exit(0);
}

if (!target) {
  warn(`No prebuilt binary is available for ${process.platform}/${process.arch}; Cargo fallback remains available.`);
  process.exit(0);
}

const assetName = `electron-cli-v${version}-${target}${process.platform === "win32" ? ".exe" : ""}`;
const baseUrl = process.env.ELECTRON_CLI_DOWNLOAD_BASE_URL || "https://github.com/Ikana/electron-cli/releases/download";
const url = `${baseUrl}/v${version}/${assetName}`;
const tempFile = path.join(os.tmpdir(), `${assetName}.${process.pid}.tmp`);

main().catch((error) => {
  warn(`Could not install prebuilt binary: ${error.message}`);

  if (process.env.ELECTRON_CLI_STRICT_INSTALL === "1") {
    process.exit(1);
  }

  warn("Install completed with Cargo fallback enabled.");
});

async function main() {
  fs.mkdirSync(installDir, { recursive: true });

  await download(url, tempFile);
  fs.renameSync(tempFile, destination);

  if (process.platform !== "win32") {
    fs.chmodSync(destination, 0o755);
  }

  const result = spawnSync(destination, ["--version"], { encoding: "utf8" });
  if (result.error || result.status !== 0) {
    fs.rmSync(destination, { force: true });
    throw new Error(result.error ? result.error.message : result.stderr.trim() || "downloaded binary failed verification");
  }

  console.error(`electron-cli installed prebuilt binary ${assetName}`);
}

function resolveTarget() {
  const key = `${process.platform}-${process.arch}`;

  return {
    "darwin-arm64": "darwin-arm64",
    "darwin-x64": "darwin-x64",
    "linux-x64": "linux-x64",
    "win32-x64": "win32-x64",
  }[key];
}

function download(url, destinationPath) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        response.resume();
        download(response.headers.location, destinationPath).then(resolve, reject);
        return;
      }

      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`download failed with HTTP ${response.statusCode}: ${url}`));
        return;
      }

      const file = fs.createWriteStream(destinationPath, { mode: 0o755 });
      response.pipe(file);
      file.on("finish", () => file.close(resolve));
      file.on("error", reject);
    });

    request.on("error", reject);
    request.setTimeout(30_000, () => {
      request.destroy(new Error("download timed out"));
    });
  });
}

function warn(message) {
  console.error(`electron-cli postinstall: ${message}`);
}
