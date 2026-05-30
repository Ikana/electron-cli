use anyhow::Result;

use crate::{cli::CommandArgs, output, project};

pub fn run(args: CommandArgs) -> Result<()> {
    let snapshot = project::inspect(&args.cwd)?;

    if args.json {
        output::json(&snapshot)
    } else {
        println!("electron-cli inspect");
        println!();
        println!("Project");
        println!("  root: {}", snapshot.root);

        match &snapshot.package_json {
            Some(path) => println!("  package.json: {path}"),
            None => println!("  package.json: not found"),
        }

        if let Some(package) = snapshot.package_label() {
            println!("  package: {package}");
        }

        if let Some(package_manager) = &snapshot.package_manager {
            println!("  package manager: {package_manager}");
        }

        println!();
        println!("Electron");
        match &snapshot.electron_dependency {
            Some(version) => println!("  electron: {version}"),
            None => println!("  electron: not declared"),
        }

        if snapshot.forge_dependencies.is_empty() {
            println!("  forge: not declared");
        } else {
            println!("  forge:");
            for (name, version) in &snapshot.forge_dependencies {
                println!("    {name}: {version}");
            }
        }

        if !snapshot.scripts.is_empty() {
            println!();
            println!("Scripts");
            for (name, script) in &snapshot.scripts {
                println!("  {name}: {script}");
            }
        }

        if !snapshot.signals.is_empty() {
            println!();
            println!("Signals");
            for signal in &snapshot.signals {
                println!("  {signal}");
            }
        }

        Ok(())
    }
}
