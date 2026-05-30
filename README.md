# electron-cli

`electron-cli` is an experimental Rust CLI for Electron project diagnostics and workflow automation.

This is an independent learning project. It is not affiliated with Electron, Electron Forge, the OpenJS Foundation, or GitHub. The project may wrap existing Electron ecosystem tools while exploring what a Rust-native Electron workflow could feel like.

## Status

This repository is intentionally small and public-learning friendly. The first useful surface area is inspection and diagnostics, because those commands are valuable for humans and easy for agents to consume safely.

Current commands:

```sh
electron-cli inspect
electron-cli doctor
electron-cli inspect --json
electron-cli doctor --json
```

Planned commands:

```sh
electron-cli init
electron-cli dev
electron-cli package
electron-cli make
```

The planned workflow commands may start by wrapping Electron Forge or other established tools. Rust-native implementations can replace narrow pieces over time when there is a clear reason.

## Install

During the experimental phase, the npm package runs from Rust source when a prebuilt binary is not available. You need Node.js and Rust installed.

```sh
npm install -g electron-cli
electron-cli doctor
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

```sh
electron-cli doctor --json
```

## License

MIT
