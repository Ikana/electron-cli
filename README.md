# electron-cli

`electron-cli` is an experimental Rust CLI for Electron project diagnostics and workflow automation.

This is an independent learning project. It is not affiliated with Electron, Electron Forge, the OpenJS Foundation, or GitHub. The project may wrap existing Electron ecosystem tools while exploring what a Rust-native Electron workflow could feel like.

## Status

This repository is intentionally small and public-learning friendly. The first useful surface area is inspection and diagnostics, because those commands are valuable for humans and easy for agents to consume safely.

Current commands:

```sh
electron-cli inspect
electron-cli doctor
electron-cli plan
electron-cli inspect --json
electron-cli doctor --json
electron-cli plan --json
```

Planned commands:

```sh
electron-cli dev
electron-cli init
electron-cli package
electron-cli make
```

The planned workflow commands may start by wrapping Electron Forge or other established tools. Rust-native implementations can replace narrow pieces over time when there is a clear reason.

## Install

During the experimental phase, the npm package downloads a prebuilt binary from GitHub Releases when one is available. If a prebuilt binary is not available for your platform, it falls back to running from Rust source.

```sh
npm install -g electron-cli
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
```

## Design Goals

- Learn Rust through a real developer tool.
- Make Electron project state easy to inspect.
- Prefer structured output for agentic workflows.
- Wrap proven ecosystem tools before replacing them.
- Keep the project clearly independent and experimental.

## Non-Goals

- This is not an official Electron project.
- This is not an Electron Forge fork or drop-in replacement today.
- This will not claim Forge parity until the behavior is tested and documented.

## JSON Output

Both initial commands support `--json` so agents and scripts can consume project state without scraping terminal output.
`plan` is designed around that workflow: it recommends stable commands and reports missing project conventions as structured data.

```sh
electron-cli plan --json
```

## License

MIT
