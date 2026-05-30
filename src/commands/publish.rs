use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;

use crate::{
    cli::{MakeArgs, PublishArgs},
    commands::make::{self, MakeReport},
    output,
};

#[derive(Debug, Serialize)]
struct PublishReport {
    make: MakeReport,
    publisher: String,
    channel: String,
    destination_dir: Utf8PathBuf,
    destination_artifact: Utf8PathBuf,
    manifest: Utf8PathBuf,
    skip_make: bool,
    dry_run: bool,
    status: PublishStatus,
    published_at_unix_seconds: Option<u64>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublishStatus {
    Planned,
    Published,
}

#[derive(Debug, Serialize)]
struct PublishManifest {
    schema_version: u8,
    publisher: String,
    channel: String,
    app_name: String,
    package_name: Option<String>,
    package_version: Option<String>,
    platform: String,
    arch: String,
    target: String,
    published_at_unix_seconds: u64,
    artifacts: Vec<PublishedArtifact>,
}

#[derive(Debug, Serialize)]
struct PublishedArtifact {
    file: String,
    path: Utf8PathBuf,
    size: u64,
}

pub fn run(args: PublishArgs) -> Result<()> {
    let mut report = build_report(&args)?;

    if args.dry_run {
        return print_report(&report, args.json);
    }

    execute_publish(&mut report, &args)?;
    report.status = PublishStatus::Published;

    print_report(&report, args.json)
}

fn build_report(args: &PublishArgs) -> Result<PublishReport> {
    let make_args = MakeArgs {
        cwd: args.cwd.clone(),
        out_dir: args.out_dir.clone(),
        name: args.name.clone(),
        platform: args.platform.clone(),
        arch: args.arch.clone(),
        target: args.target,
        skip_package: false,
        force: args.force,
        dry_run: false,
        json: false,
    };
    let make = make::build_report(&make_args)?;
    let root = Path::new(make.package().project().root.as_str());
    let publish_root = resolve_destination(root, &args.to);
    let destination_dir = publish_root
        .join(&args.channel)
        .join(make.package().platform())
        .join(make.package().arch());
    let artifact_name = make
        .artifact()
        .file_name()
        .context("Make artifact path has no file name")?;
    let destination_artifact = destination_dir.join(artifact_name);
    let manifest = destination_dir.join("manifest.json");

    let mut warnings = make.warnings().to_vec();
    if args.skip_make && !Path::new(make.artifact().as_str()).exists() {
        warnings.push(format!(
            "Make artifact does not exist: {}.",
            make.artifact()
        ));
    }
    if destination_artifact.exists() && !args.force {
        warnings.push(format!(
            "Publish artifact already exists: {}. Use --force to overwrite it.",
            destination_artifact.display()
        ));
    }
    if manifest.exists() && !args.force {
        warnings.push(format!(
            "Publish manifest already exists: {}. Use --force to overwrite it.",
            manifest.display()
        ));
    }

    Ok(PublishReport {
        make,
        publisher: args.publisher.as_str().to_string(),
        channel: args.channel.clone(),
        destination_dir: utf8_path(destination_dir)?,
        destination_artifact: utf8_path(destination_artifact)?,
        manifest: utf8_path(manifest)?,
        skip_make: args.skip_make,
        dry_run: args.dry_run,
        status: PublishStatus::Planned,
        published_at_unix_seconds: None,
        warnings,
    })
}

fn execute_publish(report: &mut PublishReport, args: &PublishArgs) -> Result<()> {
    if !args.skip_make {
        let make_args = MakeArgs {
            cwd: args.cwd.clone(),
            out_dir: args.out_dir.clone(),
            name: args.name.clone(),
            platform: args.platform.clone(),
            arch: args.arch.clone(),
            target: args.target,
            skip_package: false,
            force: args.force,
            dry_run: false,
            json: false,
        };
        make::execute_make(&mut report.make, &make_args)?;
        report.make.mark_made()?;
    } else if !Path::new(report.make.artifact().as_str()).exists() {
        bail!(
            "Make artifact does not exist: {}. Run without --skip-make or run electron-cli make first.",
            report.make.artifact()
        );
    }

    let destination_artifact = Path::new(report.destination_artifact.as_str());
    let manifest = Path::new(report.manifest.as_str());

    for path in [destination_artifact, manifest] {
        if path.exists() {
            if args.force {
                fs::remove_file(path)
                    .with_context(|| format!("Could not remove {}", path.display()))?;
            } else {
                bail!(
                    "Publish output already exists: {}. Use --force to overwrite it.",
                    path.display()
                );
            }
        }
    }

    fs::create_dir_all(report.destination_dir.as_str())
        .with_context(|| format!("Could not create {}", report.destination_dir))?;
    fs::copy(report.make.artifact().as_str(), destination_artifact).with_context(|| {
        format!(
            "Could not publish {} to {}",
            report.make.artifact(),
            destination_artifact.display()
        )
    })?;

    let published_at_unix_seconds = now_unix_seconds()?;
    report.published_at_unix_seconds = Some(published_at_unix_seconds);
    let manifest_json =
        serde_json::to_string_pretty(&build_manifest(report, published_at_unix_seconds)?)?;
    fs::write(manifest, format!("{manifest_json}\n"))
        .with_context(|| format!("Could not write {}", manifest.display()))?;

    Ok(())
}

fn build_manifest(
    report: &PublishReport,
    published_at_unix_seconds: u64,
) -> Result<PublishManifest> {
    let destination_artifact = Path::new(report.destination_artifact.as_str());
    let artifact_size = fs::metadata(destination_artifact)
        .with_context(|| format!("Could not stat {}", destination_artifact.display()))?
        .len();
    let artifact_file = destination_artifact
        .file_name()
        .and_then(|name| name.to_str())
        .context("Published artifact path has no UTF-8 file name")?
        .to_string();

    Ok(PublishManifest {
        schema_version: 1,
        publisher: report.publisher.clone(),
        channel: report.channel.clone(),
        app_name: report.make.package().app_name().to_string(),
        package_name: report.make.package().project().name.clone(),
        package_version: report.make.package().project().version.clone(),
        platform: report.make.package().platform().to_string(),
        arch: report.make.package().arch().to_string(),
        target: report.make.target().to_string(),
        published_at_unix_seconds,
        artifacts: vec![PublishedArtifact {
            file: artifact_file,
            path: report.destination_artifact.clone(),
            size: artifact_size,
        }],
    })
}

fn print_report(report: &PublishReport, json: bool) -> Result<()> {
    if json {
        return output::json(report);
    }

    println!("electron-cli publish");
    println!();
    println!("Project");
    println!("  root: {}", report.make.package().project().root);
    match report.make.package().project().package_label() {
        Some(label) => println!("  package: {label}"),
        None => println!("  package: not found"),
    }
    println!("  app name: {}", report.make.package().app_name());
    println!(
        "  target: {} {} {}",
        report.make.target(),
        report.make.package().platform(),
        report.make.package().arch()
    );
    println!("  publisher: {}", report.publisher);
    println!("  channel: {}", report.channel);
    println!("  status: {}", report.status.as_str());

    println!();
    println!("Publish");
    println!("  artifact: {}", report.destination_artifact);
    println!("  manifest: {}", report.manifest);

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings");
        for warning in &report.warnings {
            println!("  {warning}");
        }
    }

    Ok(())
}

fn resolve_destination(root: &Path, destination: &Path) -> PathBuf {
    if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        root.join(destination)
    }
}

fn now_unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_secs())
}

fn utf8_path(path: PathBuf) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path).map_err(|path| {
        anyhow::anyhow!(
            "Path contains invalid UTF-8 and cannot be represented in JSON: {}",
            path.display()
        )
    })
}

impl PublishStatus {
    fn as_str(&self) -> &'static str {
        match self {
            PublishStatus::Planned => "planned",
            PublishStatus::Published => "published",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_local_publish_report() {
        let root = unique_temp_dir("plan");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = publish_args(root.clone(), true);
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.publisher, "local");
        assert_eq!(report.channel, "default");
        assert!(Path::new(report.destination_artifact.as_str()).ends_with(
            PathBuf::from("out")
                .join("publish")
                .join("local")
                .join("default")
                .join(report.make.package().platform())
                .join(report.make.package().arch())
                .join(format!(
                    "starter-app-{}-{}.zip",
                    report.make.package().platform(),
                    report.make.package().arch()
                ))
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn publishes_make_artifact_to_local_directory() {
        let root = unique_temp_dir("execute");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = publish_args(root.clone(), false);
        let mut report = build_report(&args).expect("report should build");

        execute_publish(&mut report, &args).expect("publish should succeed");

        assert!(Path::new(report.destination_artifact.as_str()).exists());
        assert!(Path::new(report.manifest.as_str()).exists());
        let manifest =
            fs::read_to_string(report.manifest.as_str()).expect("manifest should be readable");
        assert!(manifest.contains("\"publisher\": \"local\""));
        assert!(manifest.contains("\"app_name\": \"starter-app\""));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn skip_make_requires_existing_artifact() {
        let root = unique_temp_dir("skip-make");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let mut args = publish_args(root.clone(), false);
        args.skip_make = true;
        let mut report = build_report(&args).expect("report should build");

        assert!(execute_publish(&mut report, &args).is_err());

        let _ = fs::remove_dir_all(root);
    }

    fn publish_args(root: PathBuf, dry_run: bool) -> PublishArgs {
        PublishArgs {
            cwd: root,
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: crate::cli::MakeTarget::Zip,
            publisher: crate::cli::PublishTarget::Local,
            to: PathBuf::from("out/publish/local"),
            channel: "default".to_string(),
            skip_make: false,
            force: false,
            dry_run,
            json: true,
        }
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
            "electron-cli-publish-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }
}
