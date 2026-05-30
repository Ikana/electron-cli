use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Bootstrap a new Electron app through the Electron Forge create tooling.
    Init(InitArgs),
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

#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// Directory to initialize. Defaults to the current directory.
    #[arg(default_value = ".", value_name = "DIR")]
    pub dir: PathBuf,

    /// Directory to run the create command from.
    #[arg(long, default_value = ".", value_name = "PATH")]
    pub cwd: PathBuf,

    /// Forge template to use.
    #[arg(long, short = 't', default_value = "vite-typescript")]
    pub template: String,

    /// Package manager command strategy to use.
    #[arg(long, value_enum)]
    pub package_manager: Option<PackageManager>,

    /// Set a specific Electron version, or use latest/beta/nightly.
    #[arg(long, value_name = "VERSION")]
    pub electron_version: Option<String>,

    /// Copy template CI files when the Forge template supports them.
    #[arg(long)]
    pub copy_ci_files: bool,

    /// Overwrite an existing target directory.
    #[arg(long)]
    pub force: bool,

    /// Skip initializing a git repository in the created project.
    #[arg(long)]
    pub skip_git: bool,

    /// Print the command and metadata without creating files.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "lower")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl PackageManager {
    pub fn as_str(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Yarn => "yarn",
            PackageManager::Bun => "bun",
        }
    }
}
