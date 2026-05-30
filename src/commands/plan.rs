use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;

use crate::{cli::CommandArgs, output, project};

#[derive(Debug, Serialize)]
struct PlanReport {
    project_type: ProjectType,
    recommended_commands: BTreeMap<String, String>,
    missing: Vec<String>,
    risks: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ProjectType {
    ElectronForge,
    Electron,
    JavaScript,
    Unknown,
}

pub fn run(args: CommandArgs) -> Result<()> {
    let snapshot = project::inspect(&args.cwd)?;
    let report = build_report(&snapshot);

    if args.json {
        output::json(&report)
    } else {
        println!("electron-cli plan");
        println!();
        println!("Project");
        println!("  root: {}", snapshot.root);
        match snapshot.package_label() {
            Some(label) => println!("  package: {label}"),
            None => println!("  package: not found"),
        }
        println!("  type: {}", report.project_type.as_str());

        if !report.recommended_commands.is_empty() {
            println!();
            println!("Recommended Commands");
            for (name, command) in &report.recommended_commands {
                println!("  {name}: {command}");
            }
        }

        if !report.missing.is_empty() {
            println!();
            println!("Missing");
            for item in &report.missing {
                println!("  {item}");
            }
        }

        if !report.risks.is_empty() {
            println!();
            println!("Risks");
            for risk in &report.risks {
                println!("  {risk}");
            }
        }

        if !report.notes.is_empty() {
            println!();
            println!("Notes");
            for note in &report.notes {
                println!("  {note}");
            }
        }

        Ok(())
    }
}

fn build_report(snapshot: &project::ProjectSnapshot) -> PlanReport {
    let project_type = detect_project_type(snapshot);
    let mut recommended_commands = BTreeMap::new();
    let mut missing = Vec::new();
    let mut risks = Vec::new();
    let mut notes = Vec::new();

    if matches!(project_type, ProjectType::Electron) && snapshot.main.is_some() {
        recommended_commands.insert("dev".to_string(), "electron-cli start".to_string());
    } else if let Some(script) = first_script(snapshot, &["start", "dev"]) {
        recommended_commands.insert("dev".to_string(), run_script(snapshot, script));
    } else if snapshot.electron_dependency.is_some() && snapshot.main.is_some() {
        recommended_commands.insert("dev".to_string(), package_exec(snapshot, "electron ."));
        missing.push(
            "Add a start or dev script so humans and agents have a stable entrypoint.".to_string(),
        );
    } else {
        missing.push("No start or dev script was found.".to_string());
    }

    if matches!(project_type, ProjectType::Electron) && snapshot.main.is_some() {
        recommended_commands.insert("package".to_string(), "electron-cli package".to_string());
    } else if let Some(script) = first_script(snapshot, &["package", "pack"]) {
        recommended_commands.insert("package".to_string(), run_script(snapshot, script));
    } else if matches!(project_type, ProjectType::ElectronForge) {
        missing.push(
            "No package script was found even though Electron Forge is declared.".to_string(),
        );
    }

    if let Some(script) = first_script(snapshot, &["make", "dist"]) {
        recommended_commands.insert("make".to_string(), run_script(snapshot, script));
    }

    recommended_commands.insert(
        "diagnostics".to_string(),
        "electron-cli doctor --json".to_string(),
    );
    recommended_commands.insert(
        "inspect".to_string(),
        "electron-cli inspect --json".to_string(),
    );

    if snapshot.package_json.is_none() {
        risks.push(
            "No package.json was found, so Electron project detection is limited.".to_string(),
        );
    }

    if snapshot.electron_dependency.is_none() {
        risks.push("Electron is not declared in package dependencies.".to_string());
    }

    if snapshot.electron_dependency.is_some() && snapshot.main.is_none() {
        risks.push("Electron is declared, but package.json has no main process entry.".to_string());
    }

    if snapshot.has_javascript_dependencies() && snapshot.package_manager.is_none() {
        risks.push("JavaScript dependencies are declared, but no lockfile was found.".to_string());
    }

    if matches!(project_type, ProjectType::ElectronForge) {
        notes.push("Electron Forge was detected; its scripts remain the safest path for Forge-managed apps today.".to_string());
    } else if snapshot.electron_dependency.is_some() {
        notes.push("Electron was detected without Forge; electron-cli can start and package the current-platform app directly.".to_string());
    } else {
        notes.push("This does not currently look like an Electron app.".to_string());
    }

    PlanReport {
        project_type,
        recommended_commands,
        missing,
        risks,
        notes,
    }
}

fn detect_project_type(snapshot: &project::ProjectSnapshot) -> ProjectType {
    if !snapshot.forge_dependencies.is_empty()
        || snapshot
            .scripts
            .values()
            .any(|script| script.contains("electron-forge"))
    {
        ProjectType::ElectronForge
    } else if snapshot.electron_dependency.is_some() {
        ProjectType::Electron
    } else if snapshot.package_json.is_some() {
        ProjectType::JavaScript
    } else {
        ProjectType::Unknown
    }
}

fn first_script<'a>(snapshot: &project::ProjectSnapshot, names: &'a [&'a str]) -> Option<&'a str> {
    names
        .iter()
        .copied()
        .find(|name| snapshot.scripts.contains_key(*name))
}

fn run_script(snapshot: &project::ProjectSnapshot, script: &str) -> String {
    match snapshot.package_manager.as_deref() {
        Some("bun") => format!("bun run {script}"),
        Some("pnpm") => format!("pnpm run {script}"),
        Some("yarn") => format!("yarn run {script}"),
        Some("npm") | None => format!("npm run {script}"),
        Some(package_manager) => format!("{package_manager} run {script}"),
    }
}

fn package_exec(snapshot: &project::ProjectSnapshot, command: &str) -> String {
    match snapshot.package_manager.as_deref() {
        Some("bun") => format!("bunx {command}"),
        Some("pnpm") => format!("pnpm exec {command}"),
        Some("yarn") => format!("yarn {command}"),
        Some("npm") | None => format!("npx {command}"),
        Some(package_manager) => format!("{package_manager} exec {command}"),
    }
}

impl ProjectType {
    fn as_str(&self) -> &'static str {
        match self {
            ProjectType::ElectronForge => "electron-forge",
            ProjectType::Electron => "electron",
            ProjectType::JavaScript => "javascript",
            ProjectType::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn plans_for_electron_forge_fixture() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/electron-forge");
        let snapshot = project::inspect(&fixture).expect("fixture should inspect");

        let report = build_report(&snapshot);

        assert!(matches!(report.project_type, ProjectType::ElectronForge));
        assert_eq!(
            report.recommended_commands.get("dev").map(String::as_str),
            Some("npm run start")
        );
        assert_eq!(
            report
                .recommended_commands
                .get("package")
                .map(String::as_str),
            Some("npm run package")
        );
        assert!(report.risks.is_empty());
    }

    #[test]
    fn plans_native_electron_cli_flow_for_plain_electron_app() {
        let snapshot = project::ProjectSnapshot {
            root: camino::Utf8PathBuf::from("/tmp/native-app"),
            package_json: Some(camino::Utf8PathBuf::from("/tmp/native-app/package.json")),
            name: Some("native-app".to_string()),
            version: Some("0.1.0".to_string()),
            main: Some("src/main.js".to_string()),
            package_manager: Some("npm".to_string()),
            scripts: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            dev_dependencies: BTreeMap::from([("electron".to_string(), "30.0.0".to_string())]),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
            electron_dependency: Some("30.0.0".to_string()),
            forge_dependencies: BTreeMap::new(),
            signals: vec!["electron dependency declared".to_string()],
        };

        let report = build_report(&snapshot);

        assert!(matches!(report.project_type, ProjectType::Electron));
        assert_eq!(
            report.recommended_commands.get("dev").map(String::as_str),
            Some("electron-cli start")
        );
        assert_eq!(
            report
                .recommended_commands
                .get("package")
                .map(String::as_str),
            Some("electron-cli package")
        );
    }
}
