use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;

use crate::{cli::StartArgs, output, project::ProjectSnapshot};

#[derive(Debug, Serialize)]
struct StartReport {
    project: ProjectSnapshot,
    electron_path: Option<Utf8PathBuf>,
    command: Vec<String>,
    command_display: String,
    passthrough_args: Vec<String>,
    dry_run: bool,
    status: StartStatus,
    exit_code: Option<i32>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum StartStatus {
    Planned,
    Exited,
}

pub fn run(args: StartArgs) -> Result<()> {
    let snapshot = crate::project::inspect(&args.cwd)?;
    let mut report = build_report(snapshot, &args)?;

    if args.dry_run {
        return print_report(&report, args.json);
    }

    let exit_code = execute_start(&report)?;
    report.status = StartStatus::Exited;
    report.exit_code = exit_code;

    if args.json {
        output::json(&report)?;
    }

    if let Some(code) = exit_code {
        bail!("Electron exited with status code {code}");
    } else {
        Ok(())
    }
}

fn build_report(snapshot: ProjectSnapshot, args: &StartArgs) -> Result<StartReport> {
    let root = Path::new(snapshot.root.as_str());
    let electron_path = find_electron_executable(root);
    let mut warnings = Vec::new();

    if snapshot.package_json.is_none() {
        warnings.push("No package.json found.".to_string());
    }

    if snapshot.electron_dependency.is_none() {
        warnings.push("No electron dependency is declared in package.json.".to_string());
    }

    if electron_path.is_none() {
        warnings.push(
            "Electron executable was not found under node_modules/electron/dist.".to_string(),
        );
    }

    let mut command = Vec::new();
    if let Some(path) = &electron_path {
        command.push(path_arg(path));
        command.push(snapshot.root.to_string());
        command.extend(args.electron_args.clone());
    }

    let command_display = if command.is_empty() {
        "electron executable not found".to_string()
    } else {
        display_command(&command)
    };

    Ok(StartReport {
        project: snapshot,
        electron_path: electron_path.map(utf8_path).transpose()?,
        command,
        command_display,
        passthrough_args: args.electron_args.clone(),
        dry_run: args.dry_run,
        status: StartStatus::Planned,
        exit_code: None,
        warnings,
    })
}

fn execute_start(report: &StartReport) -> Result<Option<i32>> {
    if report.project.package_json.is_none() {
        bail!("No package.json found. Run electron-cli start inside an Electron project.");
    }

    if report.project.electron_dependency.is_none() {
        bail!("No electron dependency found. Install Electron before starting the app.");
    }

    let (program, args) = report
        .command
        .split_first()
        .context("Electron executable was not found. Run your package manager install first.")?;

    let status = Command::new(program)
        .args(args)
        .current_dir(report.project.root.as_str())
        .status()
        .with_context(|| format!("Could not execute {}", report.command_display))?;

    if status.success() {
        Ok(None)
    } else {
        Ok(status.code())
    }
}

fn print_report(report: &StartReport, json: bool) -> Result<()> {
    if json {
        return output::json(report);
    }

    println!("electron-cli start");
    println!();
    println!("Project");
    println!("  root: {}", report.project.root);
    match report.project.package_label() {
        Some(label) => println!("  package: {label}"),
        None => println!("  package: not found"),
    }

    println!();
    println!("Command");
    println!("  {}", report.command_display);

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings");
        for warning in &report.warnings {
            println!("  {warning}");
        }
    }

    Ok(())
}

fn find_electron_executable(root: &Path) -> Option<PathBuf> {
    let dist = root.join("node_modules/electron/dist");
    let candidates = electron_executable_candidates(&dist);

    candidates.into_iter().find(|path| path.exists())
}

fn electron_executable_candidates(dist: &Path) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![
            dist.join("Electron.app/Contents/MacOS/Electron"),
            dist.join("electron"),
        ]
    } else if cfg!(target_os = "windows") {
        vec![dist.join("electron.exe")]
    } else {
        vec![dist.join("electron")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn plans_start_command_when_electron_dist_exists() {
        let root = unique_temp_dir();
        write_package_json(&root);
        write_fake_electron(&root);

        let args = StartArgs {
            cwd: root.clone(),
            dry_run: true,
            json: true,
            electron_args: vec!["--trace-warnings".to_string()],
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.electron_path.is_some());
        assert!(report.command_display.contains("--trace-warnings"));
        assert!(report.warnings.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reports_missing_electron_dist_as_warning() {
        let root = unique_temp_dir();
        write_package_json(&root);

        let args = StartArgs {
            cwd: root.clone(),
            dry_run: true,
            json: true,
            electron_args: Vec::new(),
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.electron_path.is_none());
        assert!(report.warnings.contains(
            &"Electron executable was not found under node_modules/electron/dist.".to_string()
        ));

        let _ = fs::remove_dir_all(root);
    }

    fn write_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
    }

    fn write_fake_electron(root: &Path) {
        let path = electron_executable_candidates(&root.join("node_modules/electron/dist"))
            .into_iter()
            .next()
            .expect("candidate should exist");
        fs::create_dir_all(path.parent().expect("candidate should have parent"))
            .expect("electron parent should be created");
        fs::write(path, "").expect("electron executable should be written");
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "electron-cli-start-test-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }
}
