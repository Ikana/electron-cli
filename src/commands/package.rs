use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;

use crate::{cli::PackageArgs, output, project::ProjectSnapshot};

#[derive(Debug, Serialize)]
pub(crate) struct PackageReport {
    project: ProjectSnapshot,
    app_name: String,
    executable_name: String,
    platform: String,
    arch: String,
    electron_dist: Utf8PathBuf,
    output_dir: Utf8PathBuf,
    bundle_dir: Utf8PathBuf,
    app_resources_dir: Utf8PathBuf,
    dry_run: bool,
    status: PackageStatus,
    create_dirs: Vec<Utf8PathBuf>,
    copy_steps: Vec<CopyStep>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CopyStep {
    from: Utf8PathBuf,
    to: Utf8PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PackageStatus {
    Planned,
    Packaged,
}

pub fn run(args: PackageArgs) -> Result<()> {
    let snapshot = crate::project::inspect(&args.cwd)?;
    let mut report = build_report(snapshot, &args)?;

    if args.dry_run {
        return print_report(&report, args.json);
    }

    execute_package(&report, args.force)?;
    report.status = PackageStatus::Packaged;

    print_report(&report, args.json)
}

pub(crate) fn build_report(snapshot: ProjectSnapshot, args: &PackageArgs) -> Result<PackageReport> {
    let root = Path::new(snapshot.root.as_str());
    let platform = args.platform.clone().unwrap_or_else(current_platform);
    let arch = args.arch.clone().unwrap_or_else(current_arch);
    let app_name = clean_app_name(
        &args
            .name
            .clone()
            .or_else(|| snapshot.name.clone())
            .unwrap_or_else(|| "electron-app".to_string()),
    );
    let executable_name = executable_name(&app_name, &platform);
    let artifact_name = sanitize_artifact_name(&app_name);
    let output_dir = resolve_output_dir(root, &args.out_dir);
    let package_root = output_dir.join(format!("{artifact_name}-{platform}-{arch}"));
    let bundle_dir = bundle_dir(&package_root, &app_name, &platform);
    let app_resources_dir = app_resources_dir(&bundle_dir, &platform);
    let electron_dist = root.join("node_modules/electron/dist");
    let electron_source = electron_source(&electron_dist, &platform);

    let mut warnings = Vec::new();
    if snapshot.package_json.is_none() {
        warnings.push("No package.json found.".to_string());
    }

    if snapshot.electron_dependency.is_none() {
        warnings.push("No electron dependency is declared in package.json.".to_string());
    }

    if snapshot.main.is_none() {
        warnings.push("No package.json main field found.".to_string());
    }

    if has_runtime_dependencies(&snapshot) {
        warnings.push(
            "Packaging production node_modules is not implemented yet; this project declares runtime dependencies."
                .to_string(),
        );
    }

    if !electron_source.exists() {
        warnings.push(format!(
            "Electron runtime was not found at {}.",
            electron_source.display()
        ));
    }

    if platform != current_platform() {
        warnings.push(format!(
            "Cross-platform packaging is not implemented yet; this host can package {}.",
            current_platform()
        ));
    }

    if arch != current_arch() {
        warnings.push(format!(
            "Cross-architecture packaging is not implemented yet; this host can package {}.",
            current_arch()
        ));
    }

    let create_dirs = vec![package_root.clone(), app_resources_dir.clone()];
    let copy_steps = [
        (electron_source, bundle_dir.clone()),
        (root.to_path_buf(), app_resources_dir.join("app")),
    ];

    Ok(PackageReport {
        project: snapshot,
        app_name,
        executable_name,
        platform,
        arch,
        electron_dist: utf8_path(electron_dist)?,
        output_dir: utf8_path(output_dir)?,
        bundle_dir: utf8_path(bundle_dir)?,
        app_resources_dir: utf8_path(app_resources_dir)?,
        dry_run: args.dry_run,
        status: PackageStatus::Planned,
        create_dirs: create_dirs
            .into_iter()
            .map(utf8_path)
            .collect::<Result<Vec<_>>>()?,
        copy_steps: copy_steps
            .into_iter()
            .map(|(from, to)| {
                Ok(CopyStep {
                    from: utf8_path(from)?,
                    to: utf8_path(to)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        warnings,
    })
}

pub(crate) fn execute_package(report: &PackageReport, force: bool) -> Result<()> {
    if report.project.package_json.is_none() {
        bail!("No package.json found. Run electron-cli package inside an Electron project.");
    }

    if report.project.electron_dependency.is_none() {
        bail!("No electron dependency found. Install Electron before packaging the app.");
    }

    if has_runtime_dependencies(&report.project) {
        bail!(
            "Packaging production node_modules is not implemented yet. Remove runtime dependencies or wait for dependency pruning support."
        );
    }

    if report.platform != current_platform() {
        bail!(
            "Cross-platform packaging is not implemented yet. Requested {}, host is {}.",
            report.platform,
            current_platform()
        );
    }

    if report.arch != current_arch() {
        bail!(
            "Cross-architecture packaging is not implemented yet. Requested {}, host is {}.",
            report.arch,
            current_arch()
        );
    }

    let bundle_dir = Path::new(report.bundle_dir.as_str());
    let package_root = package_root(bundle_dir, &report.platform);
    let app_resources_dir = Path::new(report.app_resources_dir.as_str());
    let app_dir = app_resources_dir.join("app");

    if package_root.exists() {
        if force {
            fs::remove_dir_all(&package_root)
                .with_context(|| format!("Could not remove {}", package_root.display()))?;
        } else {
            bail!(
                "Package output already exists: {}. Use --force to overwrite it.",
                package_root.display()
            );
        }
    }

    let electron_source = Path::new(report.copy_steps[0].from.as_str());
    if !electron_source.exists() {
        bail!(
            "Electron runtime was not found at {}. Run your package manager install first.",
            electron_source.display()
        );
    }

    fs::create_dir_all(&package_root)
        .with_context(|| format!("Could not create {}", package_root.display()))?;
    copy_recursively(electron_source, bundle_dir).with_context(|| {
        format!(
            "Could not copy Electron runtime to {}",
            bundle_dir.display()
        )
    })?;
    rename_runtime_executable(bundle_dir, &report.executable_name, &report.platform)?;

    fs::create_dir_all(&app_dir)
        .with_context(|| format!("Could not create {}", app_dir.display()))?;
    copy_project_files(
        Path::new(report.project.root.as_str()),
        &app_dir,
        Path::new(report.output_dir.as_str()),
    )?;

    Ok(())
}

fn print_report(report: &PackageReport, json: bool) -> Result<()> {
    if json {
        return output::json(report);
    }

    println!("electron-cli package");
    println!();
    println!("Project");
    println!("  root: {}", report.project.root);
    match report.project.package_label() {
        Some(label) => println!("  package: {label}"),
        None => println!("  package: not found"),
    }
    println!("  app name: {}", report.app_name);
    println!("  executable: {}", report.executable_name);
    println!("  target: {} {}", report.platform, report.arch);
    println!("  status: {}", report.status.as_str());

    println!();
    println!("Output");
    println!("  {}", report.bundle_dir);

    println!();
    println!("Copy");
    for step in &report.copy_steps {
        println!("  {} -> {}", step.from, step.to);
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

fn copy_project_files(source: &Path, destination: &Path, output_dir: &Path) -> Result<()> {
    for entry in
        fs::read_dir(source).with_context(|| format!("Could not read {}", source.display()))?
    {
        let entry = entry?;
        let source_path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if should_skip_project_entry(&source_path, &file_name, output_dir) {
            continue;
        }

        let destination_path = destination.join(file_name.as_ref());
        if source_path.is_dir() {
            copy_project_files(&source_path, &destination_path, output_dir)?;
        } else {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Could not create {}", parent.display()))?;
            }
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "Could not copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        }
    }

    Ok(())
}

fn copy_recursively(source: &Path, destination: &Path) -> Result<()> {
    if source.is_dir() {
        fs::create_dir_all(destination)
            .with_context(|| format!("Could not create {}", destination.display()))?;

        for entry in
            fs::read_dir(source).with_context(|| format!("Could not read {}", source.display()))?
        {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            copy_recursively(&source_path, &destination_path)?;
        }
    } else {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        fs::copy(source, destination).with_context(|| {
            format!(
                "Could not copy {} to {}",
                source.display(),
                destination.display()
            )
        })?;
    }

    Ok(())
}

fn should_skip_project_entry(source_path: &Path, file_name: &str, output_dir: &Path) -> bool {
    if matches!(file_name, ".git" | "node_modules" | "target") {
        return true;
    }

    same_path_or_inside(source_path, output_dir)
}

fn same_path_or_inside(path: &Path, parent: &Path) -> bool {
    match (path.canonicalize(), parent.canonicalize()) {
        (Ok(path), Ok(parent)) => path == parent || path.starts_with(parent),
        _ => false,
    }
}

fn rename_runtime_executable(
    bundle_dir: &Path,
    executable_name: &str,
    platform: &str,
) -> Result<()> {
    if platform == "darwin" {
        return Ok(());
    }

    let current = if platform == "win32" {
        bundle_dir.join("electron.exe")
    } else {
        bundle_dir.join("electron")
    };
    let target = bundle_dir.join(executable_name);

    if current.exists() && current != target {
        fs::rename(&current, &target).with_context(|| {
            format!(
                "Could not rename {} to {}",
                current.display(),
                target.display()
            )
        })?;
    }

    Ok(())
}

fn resolve_output_dir(root: &Path, out_dir: &Path) -> PathBuf {
    if out_dir.is_absolute() {
        out_dir.to_path_buf()
    } else {
        root.join(out_dir)
    }
}

fn electron_source(electron_dist: &Path, platform: &str) -> PathBuf {
    if platform == "darwin" {
        electron_dist.join("Electron.app")
    } else {
        electron_dist.to_path_buf()
    }
}

fn bundle_dir(package_root: &Path, app_name: &str, platform: &str) -> PathBuf {
    if platform == "darwin" {
        package_root.join(format!("{app_name}.app"))
    } else {
        package_root.to_path_buf()
    }
}

fn package_root(bundle_dir: &Path, platform: &str) -> PathBuf {
    if platform == "darwin" {
        bundle_dir
            .parent()
            .expect("macOS bundle should have package parent")
            .to_path_buf()
    } else {
        bundle_dir.to_path_buf()
    }
}

fn app_resources_dir(bundle_dir: &Path, platform: &str) -> PathBuf {
    if platform == "darwin" {
        bundle_dir.join("Contents/Resources")
    } else {
        bundle_dir.join("resources")
    }
}

fn executable_name(app_name: &str, platform: &str) -> String {
    let mut name = sanitize_artifact_name(app_name);
    if platform == "win32" {
        name.push_str(".exe");
    }
    name
}

fn clean_app_name(name: &str) -> String {
    let cleaned = name
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, ' ' | '-' | '_' | '.') {
                char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches([' ', '-', '.', '_'])
        .to_string();

    if cleaned.is_empty() {
        "electron-app".to_string()
    } else {
        cleaned
    }
}

fn sanitize_artifact_name(name: &str) -> String {
    let sanitized = name
        .to_ascii_lowercase()
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '-' | '_' | '.') {
                char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(['-', '.', '_'])
        .to_string();

    if sanitized.is_empty() {
        "electron-app".to_string()
    } else {
        sanitized
    }
}

fn has_runtime_dependencies(snapshot: &ProjectSnapshot) -> bool {
    !snapshot.dependencies.is_empty() || !snapshot.optional_dependencies.is_empty()
}

fn current_platform() -> String {
    if cfg!(target_os = "macos") {
        "darwin".to_string()
    } else if cfg!(target_os = "windows") {
        "win32".to_string()
    } else {
        "linux".to_string()
    }
}

fn current_arch() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "arm64".to_string(),
        "x86_64" => "x64".to_string(),
        arch => arch.to_string(),
    }
}

fn utf8_path(path: PathBuf) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path).map_err(|path| {
        anyhow::anyhow!(
            "Path contains invalid UTF-8 and cannot be represented in JSON: {}",
            path.display()
        )
    })
}

impl PackageStatus {
    fn as_str(&self) -> &'static str {
        match self {
            PackageStatus::Planned => "planned",
            PackageStatus::Packaged => "packaged",
        }
    }
}

impl PackageReport {
    pub(crate) fn project(&self) -> &ProjectSnapshot {
        &self.project
    }

    pub(crate) fn mark_packaged(&mut self) {
        self.status = PackageStatus::Packaged;
    }

    pub(crate) fn app_name(&self) -> &str {
        &self.app_name
    }

    pub(crate) fn artifact_stem(&self) -> String {
        sanitize_artifact_name(&self.app_name)
    }

    pub(crate) fn platform(&self) -> &str {
        &self.platform
    }

    pub(crate) fn arch(&self) -> &str {
        &self.arch
    }

    pub(crate) fn output_dir(&self) -> &Utf8PathBuf {
        &self.output_dir
    }

    pub(crate) fn bundle_dir(&self) -> &Utf8PathBuf {
        &self.bundle_dir
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_package_output_for_current_platform() {
        let root = unique_temp_dir("plan");
        write_package_json(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert_eq!(report.app_name, "starter-app");
        assert_eq!(report.platform, current_platform());
        assert_eq!(report.arch, current_arch());
        assert!(report.warnings.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn packages_fake_electron_runtime_and_app_files() {
        let root = unique_temp_dir("execute");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);
        fs::create_dir_all(root.join("node_modules/ignored"))
            .expect("node_modules should be created");
        fs::write(root.join("node_modules/ignored/file.js"), "")
            .expect("ignored node module should be written");

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: Some("Starter App".to_string()),
            platform: None,
            arch: None,
            force: false,
            dry_run: false,
            json: false,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        execute_package(&report, false).expect("package should succeed");

        let app_dir = Path::new(report.app_resources_dir.as_str()).join("app");
        assert!(app_dir.join("package.json").exists());
        assert!(app_dir.join("src/main.js").exists());
        assert!(!app_dir.join("node_modules").exists());

        if current_platform() == "darwin" {
            assert!(Path::new(report.bundle_dir.as_str())
                .join("Contents")
                .exists());
        } else {
            assert!(Path::new(report.bundle_dir.as_str())
                .join(report.executable_name)
                .exists());
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_runtime_dependencies_until_pruning_exists() {
        let root = unique_temp_dir("runtime-deps");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","dependencies":{"left-pad":"1.3.0"},"devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            force: false,
            dry_run: false,
            json: false,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report
            .warnings
            .contains(&"Packaging production node_modules is not implemented yet; this project declares runtime dependencies.".to_string()));
        assert!(execute_package(&report, false).is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cleans_scoped_package_names_for_bundle_paths() {
        assert_eq!(clean_app_name("@scope/app"), "scope-app");
        assert_eq!(sanitize_artifact_name("Starter App"), "starter-app");
    }

    fn write_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
    }

    fn write_app_file(root: &Path) {
        fs::create_dir_all(root.join("src")).expect("src should be created");
        fs::write(root.join("src/main.js"), "console.log('hello');")
            .expect("main file should be written");
    }

    fn write_fake_electron_dist(root: &Path) {
        let dist = root.join("node_modules/electron/dist");
        if current_platform() == "darwin" {
            let app = dist.join("Electron.app/Contents/MacOS");
            fs::create_dir_all(&app).expect("fake macOS electron app should be created");
            fs::write(app.join("Electron"), "").expect("fake macOS binary should be written");
        } else if current_platform() == "win32" {
            fs::create_dir_all(&dist).expect("fake electron dist should be created");
            fs::write(dist.join("electron.exe"), "").expect("fake exe should be written");
        } else {
            fs::create_dir_all(&dist).expect("fake electron dist should be created");
            fs::write(dist.join("electron"), "").expect("fake binary should be written");
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "electron-cli-package-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }
}
