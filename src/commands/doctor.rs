use std::process::Command;

use anyhow::Result;
use serde::Serialize;

use crate::{cli::CommandArgs, output, project::ProjectSnapshot};

#[derive(Debug, Serialize)]
struct DoctorReport {
    project: ProjectSnapshot,
    summary: DoctorSummary,
    checks: Vec<Check>,
}

#[derive(Debug, Serialize)]
struct DoctorSummary {
    pass: usize,
    warn: usize,
    fail: usize,
    info: usize,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    level: CheckLevel,
    message: String,
    detail: Option<String>,
    remedy: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum CheckLevel {
    Pass,
    Warn,
    Fail,
    Info,
}

pub fn run(args: CommandArgs) -> Result<()> {
    let snapshot = crate::project::inspect(&args.cwd)?;
    let report = build_report(snapshot);

    if args.json {
        output::json(&report)
    } else {
        print_report(&report);
        Ok(())
    }
}

fn build_report(snapshot: ProjectSnapshot) -> DoctorReport {
    let mut checks = Vec::new();

    checks.push(match &snapshot.package_json {
        Some(path) => Check::pass(
            "package-json",
            "Found package.json",
            Some(format!("Using {path}")),
        ),
        None => Check::fail(
            "package-json",
            "No package.json found",
            Some("Run this command inside an Electron or JavaScript project.".to_string()),
            Some("Create a package.json or pass --cwd PATH to an existing project.".to_string()),
        ),
    });

    checks.push(match &snapshot.electron_dependency {
        Some(version) => Check::pass(
            "electron-dependency",
            "Electron dependency is declared",
            Some(format!("electron {version}")),
        ),
        None if snapshot.package_json.is_some() => Check::warn(
            "electron-dependency",
            "Electron dependency is not declared",
            Some(
                "This may be a generic JavaScript project, or Electron may be installed elsewhere."
                    .to_string(),
            ),
            Some(
                "Install Electron with your package manager if this is an Electron app."
                    .to_string(),
            ),
        ),
        None => Check::info(
            "electron-dependency",
            "Electron dependency could not be checked",
            Some("No package.json was found.".to_string()),
        ),
    });

    checks.push(match &snapshot.main {
        Some(main) => Check::pass(
            "main-entry",
            "Main process entry is declared",
            Some(format!("package.json main: {main}")),
        ),
        None if snapshot.electron_dependency.is_some() => Check::warn(
            "main-entry",
            "No package.json main field found",
            Some("Electron apps usually need a main process entry.".to_string()),
            Some(
                "Add a main field, or document why your tooling supplies it another way."
                    .to_string(),
            ),
        ),
        None => Check::info(
            "main-entry",
            "Main process entry is not declared",
            Some("This only matters for Electron apps.".to_string()),
        ),
    });

    checks.push(if snapshot.scripts.contains_key("start") || snapshot.scripts.contains_key("dev") {
        Check::pass(
            "dev-script",
            "Development script is declared",
            snapshot
                .scripts
                .get("start")
                .or_else(|| snapshot.scripts.get("dev"))
                .map(|script| format!("script: {script}")),
        )
    } else if snapshot.package_json.is_some() {
        Check::warn(
            "dev-script",
            "No start or dev script found",
            Some("A predictable development script makes the project easier for people and agents to run.".to_string()),
            Some("Add a start or dev script to package.json.".to_string()),
        )
    } else {
        Check::info(
            "dev-script",
            "Development scripts could not be checked",
            Some("No package.json was found.".to_string()),
        )
    });

    checks.push(if snapshot.package_manager.is_some() {
        Check::pass(
            "lockfile",
            "Package manager lockfile detected",
            snapshot.package_manager.clone(),
        )
    } else if snapshot.package_json.is_some() && snapshot.has_javascript_dependencies() {
        Check::warn(
            "lockfile",
            "No package manager lockfile detected",
            Some("Installs may not be reproducible without a lockfile.".to_string()),
            Some("Run npm install, pnpm install, yarn install, or bun install.".to_string()),
        )
    } else if snapshot.package_json.is_some() {
        Check::info(
            "lockfile",
            "No package manager lockfile detected",
            Some("No JavaScript dependencies are declared, so a lockfile is optional.".to_string()),
        )
    } else {
        Check::info(
            "lockfile",
            "Lockfile could not be checked",
            Some("No package.json was found.".to_string()),
        )
    });

    checks.push(if snapshot.forge_dependencies.is_empty() {
        Check::info(
            "forge",
            "Electron Forge is not declared",
            Some(
                "That is fine; electron-cli can inspect projects that use other tooling."
                    .to_string(),
            ),
        )
    } else {
        Check::pass(
            "forge",
            "Electron Forge dependency detected",
            Some(
                snapshot
                    .forge_dependencies
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        )
    });

    checks.push(command_check(
        "node",
        &["--version"],
        "node-runtime",
        "Node.js is available",
    ));
    checks.push(command_check(
        "npm",
        &["--version"],
        "npm-cli",
        "npm is available",
    ));

    let summary = DoctorSummary {
        pass: checks
            .iter()
            .filter(|check| check.level == CheckLevel::Pass)
            .count(),
        warn: checks
            .iter()
            .filter(|check| check.level == CheckLevel::Warn)
            .count(),
        fail: checks
            .iter()
            .filter(|check| check.level == CheckLevel::Fail)
            .count(),
        info: checks
            .iter()
            .filter(|check| check.level == CheckLevel::Info)
            .count(),
    };

    DoctorReport {
        project: snapshot,
        summary,
        checks,
    }
}

fn command_check(
    command: &'static str,
    args: &[&str],
    id: &'static str,
    success_message: &'static str,
) -> Check {
    match Command::new(command).args(args).output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Check::pass(id, success_message, Some(format!("{command} {version}")))
        }
        Ok(output) => Check::fail(
            id,
            format!("{command} returned a non-zero exit code"),
            Some(format!("exit status: {}", output.status)),
            Some(format!("Install or repair {command}.")),
        ),
        Err(error) => Check::fail(
            id,
            format!("{command} could not be executed"),
            Some(error.to_string()),
            Some(format!("Install {command} and make sure it is on PATH.")),
        ),
    }
}

fn print_report(report: &DoctorReport) {
    println!("electron-cli doctor");
    println!();
    println!("Project");
    println!("  root: {}", report.project.root);
    match report.project.package_label() {
        Some(label) => println!("  package: {label}"),
        None => println!("  package: not found"),
    }

    println!();
    println!(
        "Summary: {} pass, {} warn, {} fail, {} info",
        report.summary.pass, report.summary.warn, report.summary.fail, report.summary.info
    );
    println!();
    println!("Checks");

    for check in &report.checks {
        println!(
            "  {:<4} {:<20} {}",
            check.level.as_str(),
            check.id,
            check.message
        );

        if let Some(detail) = &check.detail {
            println!("       detail: {detail}");
        }

        if let Some(remedy) = &check.remedy {
            println!("       remedy: {remedy}");
        }
    }
}

impl Check {
    fn pass(id: &'static str, message: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            id,
            level: CheckLevel::Pass,
            message: message.into(),
            detail,
            remedy: None,
        }
    }

    fn warn(
        id: &'static str,
        message: impl Into<String>,
        detail: Option<String>,
        remedy: Option<String>,
    ) -> Self {
        Self {
            id,
            level: CheckLevel::Warn,
            message: message.into(),
            detail,
            remedy,
        }
    }

    fn fail(
        id: &'static str,
        message: impl Into<String>,
        detail: Option<String>,
        remedy: Option<String>,
    ) -> Self {
        Self {
            id,
            level: CheckLevel::Fail,
            message: message.into(),
            detail,
            remedy,
        }
    }

    fn info(id: &'static str, message: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            id,
            level: CheckLevel::Info,
            message: message.into(),
            detail,
            remedy: None,
        }
    }
}

impl CheckLevel {
    fn as_str(&self) -> &'static str {
        match self {
            CheckLevel::Pass => "PASS",
            CheckLevel::Warn => "WARN",
            CheckLevel::Fail => "FAIL",
            CheckLevel::Info => "INFO",
        }
    }
}
