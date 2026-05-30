use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;

use crate::{
    cli::{InitArgs, PackageManager},
    output,
};

#[derive(Debug, Serialize)]
struct InitReport {
    cwd: Utf8PathBuf,
    target_dir: Utf8PathBuf,
    target_arg: String,
    template: String,
    package_manager: String,
    dry_run: bool,
    command: Vec<String>,
    command_display: String,
    post_create_files: Vec<String>,
    next_steps: Vec<String>,
    warnings: Vec<String>,
    status: InitStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InitStatus {
    Planned,
    Created,
}

#[derive(Debug, Serialize)]
struct ElectronCliConfig {
    version: &'static str,
    generator: &'static str,
    template: String,
    package_manager: String,
}

pub fn run(args: InitArgs) -> Result<()> {
    let plan = build_plan(&args)?;

    if args.dry_run {
        return print_report(&plan, args.json);
    }

    ensure_target_can_be_created(&plan, args.force)?;
    execute_plan(&plan)?;
    write_project_config(&plan)?;

    let report = InitReport {
        status: InitStatus::Created,
        ..plan
    };

    print_report(&report, args.json)
}

fn build_plan(args: &InitArgs) -> Result<InitReport> {
    let cwd = args
        .cwd
        .canonicalize()
        .with_context(|| format!("Could not resolve {}", args.cwd.display()))?;

    let target_dir = if args.dir.is_absolute() {
        args.dir.clone()
    } else {
        cwd.join(&args.dir)
    };

    let target_arg = path_arg(&args.dir);
    let package_manager = args
        .package_manager
        .unwrap_or_else(|| detect_package_manager(&cwd));
    let command = create_command(package_manager, &target_arg, args);
    let command_display = display_command(&command);
    let target_label = target_arg.clone();

    let mut warnings = Vec::new();
    if target_dir.exists() {
        warnings.push(format!(
            "Target directory already exists: {}",
            target_dir.display()
        ));
    }

    if target_dir.exists() && !args.force {
        warnings
            .push("Use --force to allow create-electron-app to overwrite the target.".to_string());
    }

    Ok(InitReport {
        cwd: utf8_path(cwd)?,
        target_dir: utf8_path(target_dir)?,
        target_arg,
        template: args.template.clone(),
        package_manager: package_manager.as_str().to_string(),
        dry_run: args.dry_run,
        command,
        command_display,
        post_create_files: vec![".electron-cli.json".to_string()],
        next_steps: vec![
            format!("cd {target_label}"),
            start_command(package_manager),
            "electron-cli doctor --json".to_string(),
        ],
        warnings,
        status: InitStatus::Planned,
    })
}

fn create_command(
    package_manager: PackageManager,
    target_arg: &str,
    args: &InitArgs,
) -> Vec<String> {
    let mut command = match package_manager {
        PackageManager::Npm => vec![
            "npx".to_string(),
            "-y".to_string(),
            "create-electron-app@latest".to_string(),
            target_arg.to_string(),
        ],
        PackageManager::Pnpm => vec![
            "pnpm".to_string(),
            "dlx".to_string(),
            "create-electron-app@latest".to_string(),
            target_arg.to_string(),
        ],
        PackageManager::Yarn => vec![
            "yarn".to_string(),
            "dlx".to_string(),
            "create-electron-app@latest".to_string(),
            target_arg.to_string(),
        ],
        PackageManager::Bun => vec![
            "bunx".to_string(),
            "create-electron-app@latest".to_string(),
            target_arg.to_string(),
        ],
    };

    command.push("--template".to_string());
    command.push(args.template.clone());

    if args.copy_ci_files {
        command.push("--copy-ci-files".to_string());
    }

    if args.force {
        command.push("--force".to_string());
    }

    if args.skip_git {
        command.push("--skip-git".to_string());
    }

    if let Some(electron_version) = &args.electron_version {
        command.push("--electron-version".to_string());
        command.push(electron_version.clone());
    }

    command
}

fn execute_plan(plan: &InitReport) -> Result<()> {
    let (program, args) = plan
        .command
        .split_first()
        .context("Init command could not be constructed")?;

    let status = Command::new(program)
        .args(args)
        .current_dir(&plan.cwd)
        .status()
        .with_context(|| format!("Could not execute {}", plan.command_display))?;

    if !status.success() {
        bail!(
            "Init command failed with {status}: {}",
            plan.command_display
        );
    }

    Ok(())
}

fn ensure_target_can_be_created(plan: &InitReport, force: bool) -> Result<()> {
    let target = Path::new(plan.target_dir.as_str());

    if target.exists() && !force {
        bail!(
            "Target directory already exists: {}. Use --force to overwrite it.",
            plan.target_dir
        );
    }

    Ok(())
}

fn write_project_config(plan: &InitReport) -> Result<()> {
    let config = ElectronCliConfig {
        version: env!("CARGO_PKG_VERSION"),
        generator: "create-electron-app@latest",
        template: plan.template.clone(),
        package_manager: plan.package_manager.clone(),
    };
    let config_path = Path::new(plan.target_dir.as_str()).join(".electron-cli.json");
    let json = serde_json::to_string_pretty(&config)?;

    fs::write(&config_path, format!("{json}\n"))
        .with_context(|| format!("Could not write {}", config_path.display()))?;

    Ok(())
}

fn print_report(report: &InitReport, json: bool) -> Result<()> {
    if json {
        return output::json(report);
    }

    println!("electron-cli init");
    println!();
    println!("Project");
    println!("  cwd: {}", report.cwd);
    println!("  target: {}", report.target_dir);
    println!("  template: {}", report.template);
    println!("  package manager: {}", report.package_manager);
    println!("  status: {}", report.status.as_str());

    println!();
    println!("Command");
    println!("  {}", report.command_display);

    if !report.post_create_files.is_empty() {
        println!();
        println!("Post-Create Files");
        for file in &report.post_create_files {
            println!("  {file}");
        }
    }

    if !report.next_steps.is_empty() {
        println!();
        println!("Next Steps");
        for step in &report.next_steps {
            println!("  {step}");
        }
    }

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings");
        for warning in &report.warnings {
            println!("  {warning}");
        }
    }

    Ok(())
}

fn detect_package_manager(cwd: &Path) -> PackageManager {
    if cwd.join("pnpm-lock.yaml").exists() {
        PackageManager::Pnpm
    } else if cwd.join("yarn.lock").exists() {
        PackageManager::Yarn
    } else if cwd.join("bun.lock").exists() || cwd.join("bun.lockb").exists() {
        PackageManager::Bun
    } else {
        PackageManager::Npm
    }
}

fn start_command(package_manager: PackageManager) -> String {
    match package_manager {
        PackageManager::Npm => "npm start".to_string(),
        PackageManager::Pnpm => "pnpm start".to_string(),
        PackageManager::Yarn => "yarn start".to_string(),
        PackageManager::Bun => "bun run start".to_string(),
    }
}

fn display_command(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|char| char.is_ascii_alphanumeric() || matches!(char, '.' | '/' | '-' | '_' | '@'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn utf8_path(path: PathBuf) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path).map_err(|path| {
        anyhow::anyhow!(
            "Path contains invalid UTF-8 and cannot be represented in JSON: {}",
            path.display()
        )
    })
}

impl InitStatus {
    fn as_str(&self) -> &'static str {
        match self {
            InitStatus::Planned => "planned",
            InitStatus::Created => "created",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_default_npm_init_plan() {
        let args = InitArgs {
            dir: PathBuf::from("my-app"),
            cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            template: "vite-typescript".to_string(),
            package_manager: Some(PackageManager::Npm),
            electron_version: None,
            copy_ci_files: false,
            force: false,
            skip_git: true,
            dry_run: true,
            json: true,
        };

        let plan = build_plan(&args).expect("plan should build");

        assert_eq!(
            plan.command,
            vec![
                "npx",
                "-y",
                "create-electron-app@latest",
                "my-app",
                "--template",
                "vite-typescript",
                "--skip-git",
            ]
        );
        assert_eq!(plan.package_manager, "npm");
        assert_eq!(
            plan.next_steps.first().map(String::as_str),
            Some("cd my-app")
        );
    }

    #[test]
    fn includes_optional_create_flags() {
        let args = InitArgs {
            dir: PathBuf::from("desktop app"),
            cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            template: "webpack".to_string(),
            package_manager: Some(PackageManager::Pnpm),
            electron_version: Some("latest".to_string()),
            copy_ci_files: true,
            force: true,
            skip_git: true,
            dry_run: true,
            json: false,
        };

        let plan = build_plan(&args).expect("plan should build");

        assert_eq!(plan.command[0], "pnpm");
        assert!(plan.command.contains(&"--copy-ci-files".to_string()));
        assert!(plan.command.contains(&"--force".to_string()));
        assert!(plan.command.contains(&"--electron-version".to_string()));
        assert!(plan.command_display.contains("'desktop app'"));
        assert_eq!(
            plan.next_steps.get(1).map(String::as_str),
            Some("pnpm start")
        );
    }
}
