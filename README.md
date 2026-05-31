# electron-cli

`electron-cli` is an experimental Rust CLI for Electron project diagnostics and workflow automation.

This is an independent learning project. It is not affiliated with Electron, Electron Forge, the OpenJS Foundation, or GitHub. The project may wrap existing Electron ecosystem tools while exploring what a Rust-native Electron workflow could feel like.

## Status

This repository is intentionally small and public-learning friendly. The first useful surface area is inspection and diagnostics, because those commands are valuable for humans and easy for agents to consume safely. The next surface area is a Rust-owned version of the main Electron Forge flow: initialize, start, package, make, and eventually publish.

Current commands:

```sh
electron-cli inspect
electron-cli doctor
electron-cli plan
electron-cli init my-app
electron-cli start
electron-cli package
electron-cli make
electron-cli publish
electron-cli inspect --json
electron-cli doctor --json
electron-cli plan --json
electron-cli init my-app --dry-run --json
electron-cli start --dry-run --json
electron-cli package --dry-run --json
electron-cli make --dry-run --json
electron-cli publish --dry-run --json
```

The default `init` template is `minimal`, a built-in starter written by this project. Non-native template names are still passed to `create-electron-app` as an escape hatch while this project grows.

The Rust-native flow currently owns:

- `init --template minimal`: writes a local Electron starter without Electron Forge.
- `start`: launches the installed Electron runtime directly.
- `package`: copies the installed Electron runtime, app files, installed production dependency closure, app metadata, macOS icon, and extra resources into a local app bundle for the current platform and architecture.
- `make`: runs `package` and writes distributables under `out/make/<target>/<platform>/<arch>/`; it reads JSON-shaped `config.forge.makers` / `electronCli.makers` arrays when `--target` is omitted, and `--target` still forces one maker. ZIP works on all platforms, `--target dmg` writes a basic macOS disk image, `--target deb` / `--target rpm` write Linux packages, and `--target msi` writes a basic Windows Installer package.
- `publish`: runs `make` and publishes the distributable to a local directory with a manifest or to GitHub Releases.

The GitHub publisher creates or reuses a release, uploads the selected make artifact, and can replace an existing asset with `--force`. It reads `GITHUB_TOKEN` or `GH_TOKEN` and can infer `OWNER/REPO` from `package.json` `repository`, or you can pass `--github-repo`.

The DMG maker is currently a pure-Rust FAT32 image with the app bundle and an Applications entry. The MSI maker writes a compressed embedded CAB, Windows Installer database tables, and a Start Menu shortcut when the packaged executable is present. HFS+/APFS DMG layout customization, installer UI customization, Windows/Linux icon embedding, signing, and notarization are still TODO.

Package metadata can be configured in `package.json`:

```json
{
  "productName": "My App",
  "electronCli": {
    "packagerConfig": {
      "appBundleId": "com.example.my-app",
      "appCategoryType": "public.app-category.developer-tools",
      "icon": "assets/icon",
      "extraResource": "assets/config.json"
    },
    "makers": [
      { "name": "@electron-forge/maker-zip" },
      { "name": "@electron-forge/maker-dmg", "platforms": ["darwin"] },
      { "name": "@electron-forge/maker-deb", "platforms": ["linux"] },
      { "name": "@electron-forge/maker-rpm", "platforms": ["linux"] },
      { "name": "@electron-forge/maker-wix", "platforms": ["win32"] }
    ]
  },
  "config": {
    "forge": {
      "makers": [
        { "name": "@electron-forge/maker-zip" }
      ]
    }
  }
}
```

The package command also reads JSON-shaped `config.forge.packagerConfig` and `electronPackagerConfig` entries for the same fields. The make command maps JSON-shaped Forge maker names to the Rust-native targets it supports: zip, dmg, deb, rpm, and wix/msi. JavaScript Forge config files are not evaluated.

## Install

During the experimental phase, the npm package downloads a prebuilt binary from GitHub Releases when one is available. If a prebuilt binary is not available for your platform, it falls back to running from Rust source.

```sh
npm install -g electron-cli@alpha
electron-cli doctor
```

To skip binary download and use the Cargo fallback:

```sh
ELECTRON_CLI_SKIP_DOWNLOAD=1 npm install -g electron-cli@alpha
```

For local development:

```sh
npm install
npm run build
npm test
npm run dev -- doctor
```

Or use Cargo directly:

```sh
cargo run -- doctor
cargo run -- inspect --json
cargo run -- init my-app
cargo run -- start --dry-run
cargo run -- package --dry-run
cargo run -- make --dry-run
cargo run -- make --target dmg --dry-run
cargo run -- make --target deb --dry-run
cargo run -- make --target rpm --dry-run
cargo run -- make --target msi --platform win32 --dry-run
cargo run -- publish --dry-run
cargo run -- publish --publisher github --dry-run
cargo run -- publish --publisher github --github-repo OWNER/REPO --github-tag v0.1.0
```

## Design Goals

- Learn Rust through a real developer tool.
- Make Electron project state easy to inspect.
- Prefer structured output for agentic workflows.
- Replace the main Forge-style app flow with narrow Rust-owned pieces.
- Keep the project clearly independent and experimental.

## Non-Goals

- This is not an official Electron project.
- This is not an Electron Forge fork or drop-in replacement today.
- This will not claim Forge parity until the behavior is tested and documented.

## JSON Output

The inspection and planning commands support `--json` so agents and scripts can consume project state without scraping terminal output.
`plan` is designed around that workflow: it recommends stable commands and reports missing project conventions as structured data.
`init --dry-run --json` shows whether the CLI will write native template files or delegate to `create-electron-app`.
`start --dry-run --json` shows the Electron executable that will be launched.
`package --dry-run --json` shows the runtime, app file, metadata, icon, and extra-resource copy plan.
`make --dry-run --json` shows the package prerequisite and selected maker artifact path.
`publish --dry-run --json` shows the make prerequisite plus either the local destination/manifest path or the GitHub release/upload plan.

```sh
electron-cli plan --json
```

## License

MIT
