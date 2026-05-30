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

Planned commands:

```sh
electron-cli publish --publisher github
```

The default `init` template is `minimal`, a built-in starter written by this project. Non-native template names are still passed to `create-electron-app` as an escape hatch while this project grows.

The Rust-native flow currently owns:

- `init --template minimal`: writes a local Electron starter without Electron Forge.
- `start`: launches the installed Electron runtime directly.
- `package`: copies the installed Electron runtime, app files, and installed production dependency closure into a local app bundle for the current platform and architecture.
- `make`: runs `package` and writes a ZIP distributable under `out/make/zip/<platform>/<arch>/`.
- `publish`: runs `make` and publishes the distributable to a local directory with a manifest.

Remote publishers such as GitHub Releases are not implemented yet. Platform-specific makers, app metadata, signing, and notarization are also still TODO.

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
cargo run -- publish --dry-run
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
`package --dry-run --json` shows the runtime and app file copy plan.
`make --dry-run --json` shows the package prerequisite and ZIP artifact path.
`publish --dry-run --json` shows the make prerequisite, destination artifact, and manifest path.

```sh
electron-cli plan --json
```

## License

MIT
