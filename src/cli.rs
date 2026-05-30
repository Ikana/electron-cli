use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "electron-cli",
    version,
    about = "Experimental Rust CLI for Electron project diagnostics and workflow automation",
    long_about = "electron-cli is an independent learning project for exploring Rust-native Electron tooling. It is not affiliated with Electron or Electron Forge."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Check whether the current project looks ready for Electron development.
    Doctor(CommandArgs),
    /// Print a structured snapshot of the current JavaScript/Electron project.
    Inspect(CommandArgs),
    /// Recommend next commands and risks from the project snapshot.
    Plan(CommandArgs),
}

#[derive(Debug, Clone, Args)]
pub struct CommandArgs {
    /// Project directory to inspect.
    #[arg(long, default_value = ".", value_name = "PATH")]
    pub cwd: PathBuf,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}
