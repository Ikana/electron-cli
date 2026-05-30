mod cli;
mod commands;
mod output;
mod project;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor(args) => commands::doctor::run(args),
        Commands::Init(args) => commands::init::run(args),
        Commands::Inspect(args) => commands::inspect::run(args),
        Commands::Make(args) => commands::make::run(args),
        Commands::Package(args) => commands::package::run(args),
        Commands::Plan(args) => commands::plan::run(args),
        Commands::Publish(args) => commands::publish::run(args),
        Commands::Start(args) => commands::start::run(args),
    }
}
