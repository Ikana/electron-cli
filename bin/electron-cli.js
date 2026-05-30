#!/usr/bin/env node

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const exe = process.platform === "win32" ? "electron-cli.exe" : "electron-cli";
const args = process.argv.slice(2);
const envBinary = process.env.ELECTRON_CLI_BINARY;

const candidates = [
  envBinary,
  path.join(root, "bin", "downloaded", exe),
  path.join(root, "target", "release", exe),
  path.join(root, "target", "debug", exe),
].filter(Boolean);

const binary = candidates.find((candidate) => fs.existsSync(candidate));

if (binary) {
  exitWith(spawnSync(binary, args, { stdio: "inherit" }));
}

const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
const manifest = path.join(root, "Cargo.toml");

if (!fs.existsSync(manifest)) {
  console.error("electron-cli could not find its Rust sources.");
  console.error("Reinstall the package or build a release binary before running this command.");
  process.exit(1);
}

console.error("electron-cli could not find a prebuilt binary for this install.");
console.error("Building/running through Cargo fallback; install Rust from https://rustup.rs if this fails.");

exitWith(
  spawnSync(cargo, ["run", "--quiet", "--manifest-path", manifest, "--", ...args], {
    stdio: "inherit",
  }),
);

function exitWith(result) {
  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }

  process.exit(result.status ?? 1);
}
