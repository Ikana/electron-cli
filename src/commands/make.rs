use std::{
    fs,
    fs::File,
    io::{self, BufWriter},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::{
    cli::{MakeArgs, PackageArgs},
    commands::package::{self, PackageReport},
    output,
};

#[derive(Debug, Serialize)]
struct MakeReport {
    package: PackageReport,
    target: String,
    skip_package: bool,
    dry_run: bool,
    make_dir: Utf8PathBuf,
    artifact: Utf8PathBuf,
    artifact_size: Option<u64>,
    status: MakeStatus,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MakeStatus {
    Planned,
    Made,
}

pub fn run(args: MakeArgs) -> Result<()> {
    let mut report = build_report(&args)?;

    if args.dry_run {
        return print_report(&report, args.json);
    }

    execute_make(&mut report, &args)?;
    report.status = MakeStatus::Made;
    report.artifact_size = Some(
        fs::metadata(report.artifact.as_str())
            .with_context(|| format!("Could not stat {}", report.artifact))?
            .len(),
    );

    print_report(&report, args.json)
}

fn build_report(args: &MakeArgs) -> Result<MakeReport> {
    let package_args = PackageArgs {
        cwd: args.cwd.clone(),
        out_dir: args.out_dir.clone(),
        name: args.name.clone(),
        platform: args.platform.clone(),
        arch: args.arch.clone(),
        force: args.force,
        dry_run: false,
        json: false,
    };
    let snapshot = crate::project::inspect(&package_args.cwd)?;
    let package = package::build_report(snapshot, &package_args)?;
    let make_dir = Path::new(package.output_dir().as_str())
        .join("make")
        .join(args.target.as_str())
        .join(package.platform())
        .join(package.arch());
    let artifact = make_dir.join(format!(
        "{}-{}-{}.zip",
        package.artifact_stem(),
        package.platform(),
        package.arch()
    ));

    let mut warnings = package.warnings().to_vec();
    if args.skip_package && !Path::new(package.bundle_dir().as_str()).exists() {
        warnings.push(format!(
            "Package output does not exist: {}.",
            package.bundle_dir()
        ));
    }

    if artifact.exists() && !args.force {
        warnings.push(format!(
            "Make artifact already exists: {}. Use --force to overwrite it.",
            artifact.display()
        ));
    }

    Ok(MakeReport {
        package,
        target: args.target.as_str().to_string(),
        skip_package: args.skip_package,
        dry_run: args.dry_run,
        make_dir: utf8_path(make_dir)?,
        artifact: utf8_path(artifact)?,
        artifact_size: None,
        status: MakeStatus::Planned,
        warnings,
    })
}

fn execute_make(report: &mut MakeReport, args: &MakeArgs) -> Result<()> {
    if !args.skip_package {
        package::execute_package(&report.package, args.force)?;
        report.package.mark_packaged();
    } else if !Path::new(report.package.bundle_dir().as_str()).exists() {
        bail!(
            "Package output does not exist: {}. Run without --skip-package or run electron-cli package first.",
            report.package.bundle_dir()
        );
    }

    let artifact = Path::new(report.artifact.as_str());
    if artifact.exists() {
        if args.force {
            fs::remove_file(artifact)
                .with_context(|| format!("Could not remove {}", artifact.display()))?;
        } else {
            bail!(
                "Make artifact already exists: {}. Use --force to overwrite it.",
                artifact.display()
            );
        }
    }

    fs::create_dir_all(report.make_dir.as_str())
        .with_context(|| format!("Could not create {}", report.make_dir))?;
    write_zip_archive(Path::new(report.package.bundle_dir().as_str()), artifact)?;

    Ok(())
}

fn print_report(report: &MakeReport, json: bool) -> Result<()> {
    if json {
        return output::json(report);
    }

    println!("electron-cli make");
    println!();
    println!("Project");
    println!("  root: {}", report.package.project().root);
    match report.package.project().package_label() {
        Some(label) => println!("  package: {label}"),
        None => println!("  package: not found"),
    }
    println!("  app name: {}", report.package.app_name());
    println!(
        "  target: {} {} {}",
        report.target,
        report.package.platform(),
        report.package.arch()
    );
    println!("  status: {}", report.status.as_str());

    println!();
    println!("Artifact");
    println!("  {}", report.artifact);
    if let Some(size) = report.artifact_size {
        println!("  size: {size} bytes");
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

fn write_zip_archive(source: &Path, artifact: &Path) -> Result<()> {
    if !source.exists() {
        bail!("Package output does not exist: {}", source.display());
    }

    let parent = artifact
        .parent()
        .with_context(|| format!("Artifact path has no parent: {}", artifact.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;

    let file = File::create(artifact)
        .with_context(|| format!("Could not create {}", artifact.display()))?;
    let mut writer = ZipWriter::new(BufWriter::new(file));
    let base = source
        .parent()
        .with_context(|| format!("Package output has no parent: {}", source.display()))?;

    add_path_to_zip(source, base, &mut writer)?;
    writer
        .finish()
        .with_context(|| format!("Could not finish {}", artifact.display()))?;

    Ok(())
}

fn add_path_to_zip(
    path: &Path,
    base: &Path,
    writer: &mut ZipWriter<BufWriter<File>>,
) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("Could not stat {}", path.display()))?;
    let relative_path = zip_relative_path(path, base)?;

    if metadata.is_dir() {
        if !relative_path.is_empty() {
            let directory_name = format!("{relative_path}/");
            writer
                .add_directory(directory_name, directory_options(&metadata))
                .with_context(|| format!("Could not add {} to archive", path.display()))?;
        }

        let mut entries = fs::read_dir(path)
            .with_context(|| format!("Could not read {}", path.display()))?
            .collect::<Result<Vec<_>, io::Error>>()?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            add_path_to_zip(&entry.path(), base, writer)?;
        }
    } else {
        writer
            .start_file(relative_path, file_options(&metadata))
            .with_context(|| format!("Could not add {} to archive", path.display()))?;
        let mut file =
            File::open(path).with_context(|| format!("Could not open {}", path.display()))?;
        io::copy(&mut file, writer)
            .with_context(|| format!("Could not write {} to archive", path.display()))?;
    }

    Ok(())
}

fn zip_relative_path(path: &Path, base: &Path) -> Result<String> {
    let relative = path.strip_prefix(base).with_context(|| {
        format!(
            "Could not make {} relative to {}",
            path.display(),
            base.display()
        )
    })?;
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn file_options(metadata: &fs::Metadata) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(unix_mode(metadata, 0o644))
}

fn directory_options(metadata: &fs::Metadata) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(unix_mode(metadata, 0o755))
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata, _fallback: u32) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata, fallback: u32) -> u32 {
    fallback
}

fn utf8_path(path: PathBuf) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path).map_err(|path| {
        anyhow::anyhow!(
            "Path contains invalid UTF-8 and cannot be represented in JSON: {}",
            path.display()
        )
    })
}

impl MakeStatus {
    fn as_str(&self) -> &'static str {
        match self {
            MakeStatus::Planned => "planned",
            MakeStatus::Made => "made",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::ZipArchive;

    #[test]
    fn builds_make_report_for_zip_target() {
        let root = unique_temp_dir("plan");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: crate::cli::MakeTarget::Zip,
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.target, "zip");
        let expected_suffix = PathBuf::from("out")
            .join("make")
            .join("zip")
            .join(report.package.platform())
            .join(report.package.arch())
            .join(format!(
                "starter-app-{}-{}.zip",
                report.package.platform(),
                report.package.arch()
            ));
        assert!(Path::new(report.artifact.as_str()).ends_with(expected_suffix));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn makes_zip_artifact_after_packaging() {
        let root = unique_temp_dir("execute");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: crate::cli::MakeTarget::Zip,
            skip_package: false,
            force: false,
            dry_run: false,
            json: false,
        };
        let mut report = build_report(&args).expect("report should build");

        execute_make(&mut report, &args).expect("make should succeed");

        let file = File::open(report.artifact.as_str()).expect("artifact should exist");
        let mut archive = ZipArchive::new(file).expect("zip should open");
        let app_entry = if report.package.platform() == "darwin" {
            "starter-app.app/Contents/Resources/app/package.json".to_string()
        } else {
            format!(
                "starter-app-{}-{}/resources/app/package.json",
                report.package.platform(),
                report.package.arch()
            )
        };

        archive
            .by_name(&app_entry)
            .expect("app package.json should be archived");

        let _ = fs::remove_dir_all(root);
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
        if cfg!(target_os = "macos") {
            let app = dist.join("Electron.app/Contents/MacOS");
            fs::create_dir_all(&app).expect("fake macOS electron app should be created");
            fs::write(app.join("Electron"), "").expect("fake macOS binary should be written");
        } else if cfg!(target_os = "windows") {
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
            "electron-cli-make-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }
}
