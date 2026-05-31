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
- `package`: copies the installed Electron runtime, app files, installed production dependency closure by default, app metadata, macOS icon, and extra resources into a local app bundle for the current platform and architecture; it reads package metadata, dependency pruning, ignore rules, and ASAR settings from `package.json`, JSON-shaped Forge config, and static Forge config files, and can apply experimental Rust-native ad-hoc macOS bundle signatures.
- `make`: runs `package` and writes distributables under `out/make/<target>/<platform>/<arch>/`; it reads JSON-shaped `config.forge.makers` / `electronCli.makers` arrays and static Forge config files when `--target` is omitted, and `--target` still forces one maker. ZIP works on all platforms, `--target dmg` writes a basic macOS disk image, `--target deb` / `--target rpm` write Linux packages, and `--target msi` writes a basic Windows Installer package.
- `publish`: runs `make` and publishes distributables to a local directory with a manifest or to GitHub Releases; it reads JSON-shaped `config.forge.publishers` / `electronCli.publishers` arrays and static Forge config files when `--publisher` is omitted, and `--publisher` still forces one publisher.

The GitHub publisher creates or reuses a release, uploads selected make artifacts, and can replace an existing asset with `--force`. It reads `GITHUB_TOKEN` or `GH_TOKEN` and can infer `OWNER/REPO` from package metadata, Forge GitHub publisher config, or `package.json` `repository`. You can also pass `--github-repo`.

The package command recognizes macOS `packagerConfig.osxSign` and `packagerConfig.osxNotarize` options and reports the signing/notarization plan without serializing credential values. When `osxSign` is enabled on macOS and no certificate identity is configured, or the identity is `"-"`, `package` writes an experimental Rust-native ad-hoc signature for the generated `.app` bundle. When `osxSign.p12File` points at a `.p12`/PFX certificate export, `package` can sign the bundle with that certificate and can request a CMS timestamp token for notarization-compatible signatures. With p12 signing and App Store Connect API key auth, `package` can submit to Apple notarization, wait for the result, and staple the ticket natively in Rust. macOS keychain identity lookup and keychain/Apple ID notarization auth are not implemented yet.

The DMG maker is currently a pure-Rust FAT32 image with the app bundle and an Applications entry. The MSI maker writes a compressed embedded CAB, Windows Installer database tables, and a Start Menu shortcut when the packaged executable is present. HFS+/APFS DMG layout customization, ASAR ordering/transform options, installer UI customization, Windows/Linux icon embedding, macOS keychain signing, and additional notarization auth modes are still TODO.

Package metadata can be configured in `package.json`:

```json
{
  "productName": "My App",
  "electronCli": {
    "packagerConfig": {
      "appBundleId": "com.example.my-app",
      "appCategoryType": "public.app-category.developer-tools",
      "extendInfo": {
        "LSMinimumSystemVersion": "12.0"
      },
      "protocols": [
        { "name": "My App Links", "schemes": ["myapp"] }
      ],
      "usageDescription": {
        "Camera": "Needed for video calls"
      },
      "icon": "assets/icon",
      "extraResource": "assets/config.json",
      "prune": true,
      "asar": {
        "unpack": "**/*.node",
        "unpackDir": "assets/native"
      },
      "ignore": [
        "^/coverage(?:/|$)",
        "^/dist-dev(?:/|$)",
        "/^\\/fixtures(?:\\/|$)/"
      ],
      "osxSign": {
        "p12File": "certs/developer-id.p12",
        "p12PasswordEnv": "ELECTRON_CLI_P12_PASSWORD",
        "timestamp": true,
        "entitlements": "assets/entitlements.plist",
        "hardenedRuntime": true
      },
      "osxNotarize": {
        "appleApiKey": "certs/AuthKey_ABC123DEFG.p8",
        "appleApiKeyId": "ABC123DEFG",
        "appleApiIssuer": "00000000-0000-0000-0000-000000000000",
        "maxWaitSeconds": 600
      }
    },
    "makers": [
      { "name": "@electron-forge/maker-zip" },
      { "name": "@electron-forge/maker-dmg", "platforms": ["darwin"] },
      { "name": "@electron-forge/maker-deb", "platforms": ["linux"] },
      { "name": "@electron-forge/maker-rpm", "platforms": ["linux"] },
      { "name": "@electron-forge/maker-wix", "platforms": ["win32"] }
    ],
    "publishers": [
      { "name": "local", "config": { "to": "out/publish/local", "channel": "alpha" } },
      {
        "name": "@electron-forge/publisher-github",
        "config": {
          "repository": { "owner": "example", "name": "my-app" },
          "draft": true,
          "prerelease": true
        }
      }
    ]
  },
  "config": {
    "forge": {
      "makers": [
        { "name": "@electron-forge/maker-zip" }
      ],
      "publishers": [
        { "name": "@electron-forge/publisher-github" }
      ]
    }
  }
}
```

Use `p12PasswordEnv`, `p12PasswordFile`, or `p12Password` for the `.p12` password; password values are not serialized in package reports. Set `osxSign.timestamp` to a timestamp server URL, `true` for Apple's default `http://timestamp.apple.com/ts01`, or `"none"` / `false` to disable timestamping. When `osxNotarize` is enabled with p12 signing, `electron-cli` automatically enables notarization-compatible signing and uses Apple's timestamp server unless timestamping is disabled explicitly. Rust-native notarization execution currently requires `appleApiKey`, `appleApiKeyId`, and `appleApiIssuer`; `appleApiKey` may point at the `.p8` file from App Store Connect or a unified API key JSON file. It waits up to `maxWaitSeconds` or 600 seconds by default and staples by default. Set `staple: false` to skip stapling, or set both `staple: false` and `wait: false` to submit without waiting. Set `identity` to a Developer ID certificate name when you want the plan to reflect Forge-style keychain release signing, but this project will report it as not executable until Rust-native keychain lookup exists. Use `identity: "-"` or omit `identity` for the current ad-hoc signing path.

The package command also reads JSON-shaped `config.forge.packagerConfig` and `electronPackagerConfig` entries for the same fields. On macOS, `packagerConfig.extendInfo` can be an object or plist file path merged into the main app `Info.plist` before explicit options such as `appBundleId`, while `protocols` writes `CFBundleURLTypes` and `usageDescription` writes `NS*UsageDescription` entries. `packagerConfig.prune` defaults to `true`, copying only the installed runtime dependency closure; `prune: false` copies installed `node_modules` into the app while still applying Packager-style default ignores such as lockfiles, `node_modules/.bin`, object files, and `node_gyp_bins`. `packagerConfig.asar: true` writes `resources/app.asar` natively in Rust and removes the loose `resources/app` staging directory before signing or making artifacts. ASAR option objects support `unpack` file globs and `unpackDir` directory globs/prefixes, writing matched content to `resources/app.asar.unpacked`; `ordering`, `transform`, and other ASAR options are reported as not implemented yet. `packagerConfig.ignore` accepts regex strings or JavaScript-style regex literal strings such as `"/^\\/coverage/i"`; patterns are matched against project-relative paths with and without a leading slash, plus the absolute source path. The ignore filter applies to copied app files and copied `node_modules` content, but not to the Electron runtime, icons, or explicit `extraResource` entries. The make command maps JSON-shaped Forge maker names to the Rust-native targets it supports: zip, dmg, deb, rpm, and wix/msi. The publish command maps JSON-shaped publisher names to local and GitHub.

Static `forge.config.js`, `forge.config.cjs`, `forge.config.mjs`, and `forge.config.ts` files are parsed in Rust when they export an object literal directly or via a local `const`/`let`/`var` identifier. Dynamic JavaScript config that calls functions, reads environment state, or computes the config at runtime is not evaluated.

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
`package --dry-run --json` shows the runtime, app file, metadata, ASAR, icon, and extra-resource copy plan.
`make --dry-run --json` shows the package prerequisite and selected maker artifact path.
`publish --dry-run --json` shows the make prerequisite plus either the local destination/manifest path or the GitHub release/upload plan. When multiple configured makers or publishers apply, the JSON output contains a `publishes` array.

```sh
electron-cli plan --json
```

## License

MIT
