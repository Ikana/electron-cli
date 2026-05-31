use std::{
    collections::BTreeMap,
    fs,
    fs::File,
    io::{self, BufWriter, Cursor, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use cab::{CabinetBuilder, CompressionType as CabCompressionType};
use camino::Utf8PathBuf;
use fatfs::{Dir as FatDir, FileSystem, FormatVolumeOptions, FsOptions, ReadWriteSeek};
use flate2::{write::GzEncoder, Compression};
use fscommon::BufStream;
use msi::{Column, Insert, Language, Package, PackageType, Value};
use rpm::{BuildConfig, CompressionType, FileOptions, PackageBuilder};
use serde::Serialize;
use serde_json::Value as JsonValue;
use tar::{Builder as TarBuilder, Header as TarHeader};
use uuid::Uuid;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::{
    cli::{MakeArgs, MakeTarget, PackageArgs},
    commands::package::{self, PackageReport},
    output,
    project::ProjectSnapshot,
};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MakeReport {
    package: PackageReport,
    target: String,
    #[serde(skip)]
    target_kind: MakeTarget,
    linux_icon: Option<MakeIconResource>,
    skip_package: bool,
    dry_run: bool,
    make_dir: Utf8PathBuf,
    artifact: Utf8PathBuf,
    artifact_size: Option<u64>,
    status: MakeStatus,
    warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MakeStatus {
    Planned,
    Made,
}

struct ResolvedMakeTargets {
    targets: Vec<ResolvedMakeTarget>,
    warnings: Vec<String>,
}

struct ResolvedMakeTarget {
    target: MakeTarget,
    linux_icon: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct MakeIconResource {
    from: Utf8PathBuf,
    to: String,
}

#[derive(Debug, Serialize)]
struct MakeRunReport<'a> {
    targets: &'a [MakeReport],
    dry_run: bool,
    status: MakeStatus,
    warnings: Vec<String>,
}

pub fn run(args: MakeArgs) -> Result<()> {
    let mut reports = build_reports(&args)?;

    if args.dry_run {
        return print_reports(&reports, args.json, MakeStatus::Planned);
    }

    execute_make_reports(&mut reports, &args)?;

    print_reports(&reports, args.json, MakeStatus::Made)
}

#[cfg(test)]
pub(crate) fn build_report(args: &MakeArgs) -> Result<MakeReport> {
    let reports = build_reports(args)?;
    if reports.len() != 1 {
        bail!(
            "Expected one make target, but resolved {}. Pass --target to select one target.",
            reports.len()
        );
    }
    Ok(reports
        .into_iter()
        .next()
        .expect("length was checked above"))
}

pub(crate) fn build_reports(args: &MakeArgs) -> Result<Vec<MakeReport>> {
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
    let resolved = resolve_make_targets(&snapshot, args)?;
    let config_warnings = resolved.warnings;
    resolved
        .targets
        .into_iter()
        .map(|target| {
            let package = package::build_report(snapshot.clone(), &package_args)?;
            build_report_for_target(package, target, args, &config_warnings)
        })
        .collect()
}

fn build_report_for_target(
    package: PackageReport,
    target: ResolvedMakeTarget,
    args: &MakeArgs,
    config_warnings: &[String],
) -> Result<MakeReport> {
    let target_kind = target.target;
    let make_dir = Path::new(package.output_dir().as_str())
        .join("make")
        .join(target_kind.as_str())
        .join(package.platform())
        .join(package.arch());
    let artifact = make_artifact_path(&make_dir, &package, target_kind);

    let mut warnings = package.warnings().to_vec();
    warnings.extend(config_warnings.iter().cloned());
    if matches!(target_kind, MakeTarget::Deb | MakeTarget::Rpm) && package.platform() != "linux" {
        warnings.push(format!(
            "{} maker only supports linux packages; target platform is {}.",
            target_kind.as_str(),
            package.platform()
        ));
    }
    if target_kind == MakeTarget::Dmg && package.platform() != "darwin" {
        warnings.push(format!(
            "dmg maker only supports macOS packages; target platform is {}.",
            package.platform()
        ));
    }
    if target_kind == MakeTarget::Msi && package.platform() != "win32" {
        warnings.push(format!(
            "msi maker only supports Windows packages; target platform is {}.",
            package.platform()
        ));
    }
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
    let linux_icon = linux_icon_plan(
        &package,
        target_kind,
        target.linux_icon.as_deref(),
        &mut warnings,
    )?;

    Ok(MakeReport {
        package,
        target: target_kind.as_str().to_string(),
        target_kind,
        linux_icon,
        skip_package: args.skip_package,
        dry_run: args.dry_run,
        make_dir: utf8_path(make_dir)?,
        artifact: utf8_path(artifact)?,
        artifact_size: None,
        status: MakeStatus::Planned,
        warnings,
    })
}

fn linux_icon_plan(
    package: &PackageReport,
    target: MakeTarget,
    configured_icon: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<Option<MakeIconResource>> {
    if !matches!(target, MakeTarget::Deb | MakeTarget::Rpm) || package.platform() != "linux" {
        return Ok(None);
    }

    let source = if let Some(icon) = configured_icon.filter(|icon| !icon.trim().is_empty()) {
        let source = linux_icon_candidate(Path::new(package.project().root.as_str()), icon);
        if !source.exists() {
            warnings.push(format!(
                "Configured Linux maker icon was not found and will not be installed: {}.",
                source.display()
            ));
            return Ok(None);
        }
        source
    } else if let Some(source) = package.icon_source() {
        Path::new(source.as_str()).to_path_buf()
    } else {
        return Ok(None);
    };

    if !source.exists() {
        warnings.push(format!(
            "Configured Linux package icon was not found and will not be installed: {}.",
            source.display()
        ));
        return Ok(None);
    }

    let package_name = match target {
        MakeTarget::Deb => debian_package_name(&package.artifact_stem()),
        MakeTarget::Rpm => rpm_package_name(&package.artifact_stem()),
        _ => unreachable!("linux icon plan only runs for deb/rpm"),
    };

    Ok(Some(MakeIconResource {
        from: utf8_path(source)?,
        to: format!("/usr/share/pixmaps/{package_name}.png"),
    }))
}

fn linux_icon_candidate(root: &Path, configured_icon: &str) -> PathBuf {
    let path = resolve_project_path(root, configured_icon);
    if path.extension().is_some() {
        path
    } else {
        path.with_extension("png")
    }
}

fn resolve_project_path(root: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

struct ConfiguredMaker {
    label: String,
    target: Option<MakeTarget>,
    platforms: Vec<String>,
    linux_icon: Option<String>,
}

fn resolve_make_targets(
    snapshot: &ProjectSnapshot,
    args: &MakeArgs,
) -> Result<ResolvedMakeTargets> {
    if let Some(target) = args.target {
        return Ok(ResolvedMakeTargets {
            targets: vec![ResolvedMakeTarget {
                target,
                linux_icon: None,
            }],
            warnings: Vec::new(),
        });
    }

    let platform = args.platform.clone().unwrap_or_else(current_platform_label);
    let makers = configured_makers(snapshot)?;
    let mut warnings = Vec::new();
    let mut targets: Vec<ResolvedMakeTarget> = Vec::new();

    for maker in &makers {
        let Some(target) = maker.target else {
            warnings.push(format!(
                "Configured maker is not implemented yet and will be skipped: {}.",
                maker.label
            ));
            continue;
        };
        if !maker_applies_to_platform(maker, &platform) {
            continue;
        }
        if !targets.iter().any(|resolved| resolved.target == target) {
            targets.push(ResolvedMakeTarget {
                target,
                linux_icon: maker.linux_icon.clone(),
            });
        }
    }

    if targets.is_empty() {
        if makers.is_empty() {
            targets.push(ResolvedMakeTarget {
                target: MakeTarget::Zip,
                linux_icon: None,
            });
        } else {
            warnings.push(format!(
                "No supported configured makers apply to {platform}; defaulting to zip. Pass --target to override."
            ));
            targets.push(ResolvedMakeTarget {
                target: MakeTarget::Zip,
                linux_icon: None,
            });
        }
    }

    Ok(ResolvedMakeTargets { targets, warnings })
}

fn configured_makers(snapshot: &ProjectSnapshot) -> Result<Vec<ConfiguredMaker>> {
    let project_config = crate::forge_config::read(snapshot)?;

    let mut makers = Vec::new();
    for value in [
        project_config.forge().and_then(|forge| forge.get("makers")),
        project_config
            .electron_cli()
            .and_then(|config| config.get("makers")),
    ]
    .into_iter()
    .flatten()
    {
        makers.extend(parse_maker_list(value));
    }

    Ok(makers)
}

fn parse_maker_list(value: &JsonValue) -> Vec<ConfiguredMaker> {
    match value {
        JsonValue::Array(values) => values.iter().filter_map(parse_maker).collect(),
        _ => Vec::new(),
    }
}

fn parse_maker(value: &JsonValue) -> Option<ConfiguredMaker> {
    match value {
        JsonValue::String(label) => Some(ConfiguredMaker {
            label: label.clone(),
            target: maker_target(label),
            platforms: Vec::new(),
            linux_icon: None,
        }),
        JsonValue::Object(object) => {
            let label = object
                .get("name")
                .or_else(|| object.get("target"))
                .or_else(|| object.get("maker"))
                .and_then(JsonValue::as_str)?
                .to_string();
            Some(ConfiguredMaker {
                target: maker_target(&label),
                platforms: string_values(object.get("platforms")),
                linux_icon: maker_linux_icon(object),
                label,
            })
        }
        _ => None,
    }
}

fn maker_linux_icon(object: &serde_json::Map<String, JsonValue>) -> Option<String> {
    object
        .get("config")
        .and_then(|config| {
            config
                .get("options")
                .and_then(|options| options.get("icon"))
                .or_else(|| config.get("icon"))
        })
        .or_else(|| {
            object
                .get("options")
                .and_then(|options| options.get("icon"))
        })
        .or_else(|| object.get("icon"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|icon| !icon.is_empty())
        .map(ToOwned::to_owned)
}

fn maker_target(label: &str) -> Option<MakeTarget> {
    let label = label.trim().to_ascii_lowercase();
    let compact = label
        .trim_start_matches("@electron-forge/")
        .trim_start_matches("electron-forge-")
        .trim_start_matches("maker-");

    if matches!(compact, "zip" | "@electron-forge/maker-zip")
        || label.ends_with("/maker-zip")
        || label.ends_with("maker-zip")
    {
        Some(MakeTarget::Zip)
    } else if compact == "dmg" || label.ends_with("/maker-dmg") || label.ends_with("maker-dmg") {
        Some(MakeTarget::Dmg)
    } else if compact == "deb" || label.ends_with("/maker-deb") || label.ends_with("maker-deb") {
        Some(MakeTarget::Deb)
    } else if compact == "rpm" || label.ends_with("/maker-rpm") || label.ends_with("maker-rpm") {
        Some(MakeTarget::Rpm)
    } else if matches!(compact, "msi" | "wix")
        || label.ends_with("/maker-wix")
        || label.ends_with("maker-wix")
    {
        Some(MakeTarget::Msi)
    } else {
        None
    }
}

fn maker_applies_to_platform(maker: &ConfiguredMaker, platform: &str) -> bool {
    maker.platforms.is_empty()
        || maker
            .platforms
            .iter()
            .any(|configured| configured == platform || configured == "*")
}

fn string_values(value: Option<&JsonValue>) -> Vec<String> {
    match value {
        Some(JsonValue::String(value)) => vec![value.clone()],
        Some(JsonValue::Array(values)) => values
            .iter()
            .filter_map(JsonValue::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn current_platform_label() -> String {
    if cfg!(target_os = "macos") {
        "darwin".to_string()
    } else if cfg!(target_os = "windows") {
        "win32".to_string()
    } else {
        "linux".to_string()
    }
}

#[cfg(test)]
pub(crate) fn execute_make(report: &mut MakeReport, args: &MakeArgs) -> Result<()> {
    ensure_package_ready(std::slice::from_mut(report), args)?;
    execute_make_artifact(report, args)?;
    Ok(())
}

pub(crate) fn execute_make_reports(reports: &mut [MakeReport], args: &MakeArgs) -> Result<()> {
    if reports.is_empty() {
        bail!("No make targets were resolved.");
    }
    ensure_package_ready(reports, args)?;
    for report in reports {
        execute_make_artifact(report, args)?;
        report.mark_made()?;
    }
    Ok(())
}

fn ensure_package_ready(reports: &mut [MakeReport], args: &MakeArgs) -> Result<()> {
    let first = reports
        .first_mut()
        .context("No make targets were resolved.")?;
    if !args.skip_package {
        package::execute_package(&first.package, args.force)?;
        for report in reports {
            report.package.mark_packaged();
        }
    } else if !Path::new(first.package.bundle_dir().as_str()).exists() {
        bail!(
            "Package output does not exist: {}. Run without --skip-package or run electron-cli package first.",
            first.package.bundle_dir()
        );
    }

    Ok(())
}

fn execute_make_artifact(report: &mut MakeReport, args: &MakeArgs) -> Result<()> {
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
    match report.target_kind {
        MakeTarget::Zip => {
            write_zip_archive(Path::new(report.package.bundle_dir().as_str()), artifact)?
        }
        MakeTarget::Deb => {
            write_deb_archive(&report.package, report.linux_icon.as_ref(), artifact)?
        }
        MakeTarget::Dmg => write_dmg_archive(&report.package, artifact)?,
        MakeTarget::Msi => write_msi_archive(&report.package, artifact)?,
        MakeTarget::Rpm => {
            write_rpm_archive(&report.package, report.linux_icon.as_ref(), artifact)?
        }
    }

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
    if let Some(icon) = &report.linux_icon {
        println!("  linux icon: {} -> {}", icon.from, icon.to);
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

fn print_reports(reports: &[MakeReport], json: bool, status: MakeStatus) -> Result<()> {
    if reports.len() == 1 {
        return print_report(&reports[0], json);
    }

    let warnings = combined_warnings(reports);
    if json {
        return output::json(&MakeRunReport {
            targets: reports,
            dry_run: reports.iter().any(|report| report.dry_run),
            status,
            warnings,
        });
    }

    println!("electron-cli make");
    println!();
    if let Some(first) = reports.first() {
        println!("Project");
        println!("  root: {}", first.package.project().root);
        match first.package.project().package_label() {
            Some(label) => println!("  package: {label}"),
            None => println!("  package: not found"),
        }
        println!("  app name: {}", first.package.app_name());
        println!(
            "  target platform: {} {}",
            first.package.platform(),
            first.package.arch()
        );
        println!("  status: {}", status.as_str());
    }

    println!();
    println!("Artifacts");
    for report in reports {
        println!("  {}: {}", report.target, report.artifact);
        if let Some(size) = report.artifact_size {
            println!("    size: {size} bytes");
        }
    }

    if !warnings.is_empty() {
        println!();
        println!("Warnings");
        for warning in warnings {
            println!("  {warning}");
        }
    }

    Ok(())
}

fn combined_warnings(reports: &[MakeReport]) -> Vec<String> {
    let mut warnings = Vec::new();
    for warning in reports.iter().flat_map(|report| report.warnings()) {
        if !warnings.contains(warning) {
            warnings.push(warning.clone());
        }
    }
    warnings
}

fn make_artifact_path(make_dir: &Path, package: &PackageReport, target: MakeTarget) -> PathBuf {
    match target {
        MakeTarget::Zip => make_dir.join(format!(
            "{}-{}-{}.zip",
            package.artifact_stem(),
            package.platform(),
            package.arch()
        )),
        MakeTarget::Deb => make_dir.join(format!(
            "{}_{}_{}.deb",
            debian_package_name(&package.artifact_stem()),
            debian_version(package.project().version.as_deref()),
            debian_arch(package.arch())
        )),
        MakeTarget::Dmg => make_dir.join(format!(
            "{}-{}-{}.dmg",
            package.artifact_stem(),
            dmg_version(package.project().version.as_deref()),
            package.arch()
        )),
        MakeTarget::Msi => make_dir.join(format!(
            "{}-{}-{}.msi",
            package.artifact_stem(),
            windows_artifact_version(package.project().version.as_deref()),
            windows_arch(package.arch())
        )),
        MakeTarget::Rpm => make_dir.join(format!(
            "{}-{}-1.{}.rpm",
            rpm_package_name(&package.artifact_stem()),
            rpm_version(package.project().version.as_deref()),
            rpm_arch(package.arch())
        )),
    }
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

fn write_dmg_archive(package: &PackageReport, artifact: &Path) -> Result<()> {
    if package.platform() != "darwin" {
        bail!(
            "DMG maker only supports macOS packages. Requested {}.",
            package.platform()
        );
    }

    let source = Path::new(package.bundle_dir().as_str());
    if !source.exists() {
        bail!("Package output does not exist: {}", source.display());
    }
    if source.extension().and_then(|extension| extension.to_str()) != Some("app") {
        bail!(
            "DMG maker expected a macOS .app bundle: {}",
            source.display()
        );
    }

    let parent = artifact
        .parent()
        .with_context(|| format!("Artifact path has no parent: {}", artifact.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;

    let volume_label = fat_volume_label(package.app_name());
    let fat32 = create_dmg_fat32(source, &volume_label)?;
    apple_dmg::DmgWriter::create(artifact)
        .with_context(|| format!("Could not create {}", artifact.display()))?
        .create_fat32(&fat32)
        .with_context(|| format!("Could not write {}", artifact.display()))
}

const DMG_SECTOR_SIZE: u64 = 512;
const DMG_MIN_BYTES: u64 = 64 * 1024 * 1024;
const DMG_SECTOR_ALIGNMENT: u64 = 2048;

fn create_dmg_fat32(app_bundle: &Path, volume_label: &[u8; 11]) -> Result<Vec<u8>> {
    let total_sectors = dmg_total_sectors(app_bundle)?;
    let mut fat32 = vec![0; total_sectors as usize * DMG_SECTOR_SIZE as usize];

    {
        let volume_options = FormatVolumeOptions::new()
            .volume_label(*volume_label)
            .bytes_per_sector(DMG_SECTOR_SIZE as u16)
            .total_sectors(total_sectors);
        let mut disk = BufStream::new(Cursor::new(&mut fat32));
        fatfs::format_volume(&mut disk, volume_options)
            .context("Could not format DMG FAT32 volume")?;
        drop(disk);

        let disk = BufStream::new(Cursor::new(&mut fat32));
        let fs =
            FileSystem::new(disk, FsOptions::new()).context("Could not open DMG FAT32 volume")?;
        let root = fs.root_dir();
        let app_name = utf8_file_name(app_bundle)?;
        let app_dir = root
            .create_dir(app_name)
            .with_context(|| format!("Could not add {app_name} to DMG"))?;
        add_directory_to_fat(app_bundle, &app_dir)
            .with_context(|| format!("Could not add {} to DMG", app_bundle.display()))?;
        write_fat_symlink(&root, "Applications", "/Applications")
            .context("Could not add Applications link to DMG")?;
    }

    Ok(fat32)
}

fn dmg_total_sectors(app_bundle: &Path) -> Result<u32> {
    let stats = directory_stats(app_bundle)?;
    let cluster_slack_estimate =
        stats.files.saturating_mul(16 * 1024) + stats.directories.saturating_mul(4096);
    let payload_estimate = stats
        .bytes
        .saturating_add(cluster_slack_estimate)
        .saturating_add(16 * 1024 * 1024);
    let required_bytes = payload_estimate
        .saturating_add(payload_estimate / 3)
        .max(DMG_MIN_BYTES);
    let sectors = required_bytes.div_ceil(DMG_SECTOR_SIZE);
    let aligned_sectors = sectors.div_ceil(DMG_SECTOR_ALIGNMENT) * DMG_SECTOR_ALIGNMENT;
    u32::try_from(aligned_sectors).context("DMG contents are too large for a FAT32 image")
}

#[derive(Default)]
struct DirectoryStats {
    bytes: u64,
    files: u64,
    directories: u64,
}

fn directory_stats(path: &Path) -> Result<DirectoryStats> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("Could not stat {}", path.display()))?;
    if metadata.is_file() {
        return Ok(DirectoryStats {
            bytes: metadata.len(),
            files: 1,
            directories: 0,
        });
    }
    if metadata.file_type().is_symlink() {
        return Ok(DirectoryStats {
            bytes: read_link_lossy(path)?.len() as u64,
            files: 1,
            directories: 0,
        });
    }
    if !metadata.is_dir() {
        return Ok(DirectoryStats::default());
    }

    let mut stats = DirectoryStats {
        bytes: 0,
        files: 0,
        directories: 1,
    };
    for entry in fs::read_dir(path).with_context(|| format!("Could not read {}", path.display()))? {
        let entry = entry?;
        let child = directory_stats(&entry.path())?;
        stats.bytes = stats.bytes.saturating_add(child.bytes);
        stats.files = stats.files.saturating_add(child.files);
        stats.directories = stats.directories.saturating_add(child.directories);
    }
    Ok(stats)
}

fn add_directory_to_fat<T: ReadWriteSeek>(
    source: &Path,
    destination: &FatDir<'_, T>,
) -> Result<()> {
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("Could not read {}", source.display()))?
        .collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let source_path = entry.path();
        let file_name = utf8_file_name(&source_path)?;
        let metadata = fs::symlink_metadata(&source_path)
            .with_context(|| format!("Could not stat {}", source_path.display()))?;

        if metadata.is_dir() {
            let child = destination
                .create_dir(file_name)
                .with_context(|| format!("Could not create DMG directory {file_name}"))?;
            add_directory_to_fat(&source_path, &child)?;
        } else if metadata.file_type().is_symlink() {
            let target = read_link_lossy(&source_path)?;
            write_fat_symlink(destination, file_name, &target)?;
        } else if metadata.is_file() {
            let mut source_file = File::open(&source_path)
                .with_context(|| format!("Could not open {}", source_path.display()))?;
            let mut destination_file = destination
                .create_file(file_name)
                .with_context(|| format!("Could not create DMG file {file_name}"))?;
            io::copy(&mut source_file, &mut destination_file)
                .with_context(|| format!("Could not write DMG file {file_name}"))?;
        }
    }

    Ok(())
}

fn write_fat_symlink<T: ReadWriteSeek>(
    directory: &FatDir<'_, T>,
    name: &str,
    target: &str,
) -> Result<()> {
    let bytes = fat_symlink_bytes(target)?;
    let mut file = directory
        .create_file(name)
        .with_context(|| format!("Could not create DMG symlink {name}"))?;
    file.write_all(&bytes)
        .with_context(|| format!("Could not write DMG symlink {name}"))
}

fn fat_symlink_bytes(target: &str) -> Result<Vec<u8>> {
    let mut bytes = format!(
        "XSym\n{:04}\n{:x}\n{}\n",
        target.len(),
        md5::compute(target.as_bytes()),
        target
    )
    .into_bytes();
    anyhow::ensure!(bytes.len() <= 1067, "Symlink target is too long: {target}");
    bytes.resize(1067, b' ');
    Ok(bytes)
}

fn fat_volume_label(name: &str) -> [u8; 11] {
    let mut label = [b' '; 11];
    let sanitized = name
        .to_ascii_uppercase()
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .take(11)
        .collect::<Vec<_>>();
    if sanitized.is_empty() {
        label[..3].copy_from_slice(b"APP");
    } else {
        label[..sanitized.len()].copy_from_slice(&sanitized);
    }
    label
}

fn read_link_lossy(path: &Path) -> Result<String> {
    Ok(fs::read_link(path)
        .with_context(|| format!("Could not read link {}", path.display()))?
        .to_string_lossy()
        .to_string())
}

fn utf8_file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|file_name| file_name.to_str())
        .with_context(|| format!("Path has no UTF-8 file name: {}", path.display()))
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

fn write_deb_archive(
    package: &PackageReport,
    linux_icon: Option<&MakeIconResource>,
    artifact: &Path,
) -> Result<()> {
    if package.platform() != "linux" {
        bail!(
            "Deb maker only supports linux packages. Requested {}.",
            package.platform()
        );
    }

    let source = Path::new(package.bundle_dir().as_str());
    if !source.exists() {
        bail!("Package output does not exist: {}", source.display());
    }

    let parent = artifact
        .parent()
        .with_context(|| format!("Artifact path has no parent: {}", artifact.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;

    let deb_package = debian_package_name(&package.artifact_stem());
    let version = debian_version(package.project().version.as_deref());
    let arch = debian_arch(package.arch());
    let installed_size = directory_size(source)?.div_ceil(1024).max(1);
    let control = debian_control_file(package, &deb_package, &version, &arch, installed_size);
    let control_tar =
        gzip_tar(|builder| append_bytes_to_tar(builder, "./control", control.as_bytes(), 0o644))?;
    let data_tar = gzip_tar(|builder| {
        append_deb_data_tar(builder, package, source, &deb_package, linux_icon)
    })?;

    write_ar_archive(
        artifact,
        &[
            ArMember {
                name: "debian-binary",
                mode: 0o100644,
                data: b"2.0\n".to_vec(),
            },
            ArMember {
                name: "control.tar.gz",
                mode: 0o100644,
                data: control_tar,
            },
            ArMember {
                name: "data.tar.gz",
                mode: 0o100644,
                data: data_tar,
            },
        ],
    )
}

fn write_rpm_archive(
    package: &PackageReport,
    linux_icon: Option<&MakeIconResource>,
    artifact: &Path,
) -> Result<()> {
    if package.platform() != "linux" {
        bail!(
            "RPM maker only supports linux packages. Requested {}.",
            package.platform()
        );
    }

    let source = Path::new(package.bundle_dir().as_str());
    if !source.exists() {
        bail!("Package output does not exist: {}", source.display());
    }

    let parent = artifact
        .parent()
        .with_context(|| format!("Artifact path has no parent: {}", artifact.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;

    let rpm_package = rpm_package_name(&package.artifact_stem());
    let version = rpm_version(package.project().version.as_deref());
    let arch = rpm_arch(package.arch());
    let executable = format!("/opt/{rpm_package}/{}", package.executable_name());
    let mut builder = PackageBuilder::new(
        &rpm_package,
        &version,
        package
            .project()
            .license
            .as_deref()
            .unwrap_or("LicenseRef-unknown"),
        &arch,
        &single_line(package.app_name()),
    );
    builder
        .using_config(
            BuildConfig::v4()
                .compression(CompressionType::Gzip)
                .reserved_space(None)
                .source_date(0),
        )
        .release("1")
        .vendor("electron-cli")
        .packager("electron-cli")
        .description(format!(
            "{} packaged by electron-cli.",
            single_line(package.app_name())
        ))
        .default_file_attrs(None, Some("root".to_string()), Some("root".to_string()))
        .default_dir_attrs(None, Some("root".to_string()), Some("root".to_string()));

    for directory in [
        "/opt",
        "/usr",
        "/usr/bin",
        "/usr/share",
        "/usr/share/applications",
    ] {
        builder.with_dir_entry(FileOptions::dir(directory).permissions(0o755))?;
    }
    if linux_icon.is_some() {
        builder.with_dir_entry(FileOptions::dir("/usr/share/pixmaps").permissions(0o755))?;
    }

    builder.with_dir(source, format!("/opt/{rpm_package}"), |options| options)?;
    builder.with_symlink(FileOptions::symlink(
        format!("/usr/bin/{rpm_package}"),
        &executable,
    ))?;
    builder.with_file_contents(
        rpm_desktop_file(package, &rpm_package, &executable, linux_icon.is_some()),
        FileOptions::new(format!("/usr/share/applications/{rpm_package}.desktop"))
            .permissions(0o644),
    )?;
    if let Some(icon) = linux_icon {
        builder.with_file(
            icon.from.as_str(),
            FileOptions::new(icon.to.clone()).permissions(0o644),
        )?;
    }

    let rpm = builder.build()?;
    rpm.write_file(artifact)
        .with_context(|| format!("Could not write {}", artifact.display()))
}

#[derive(Debug)]
struct MsiPayload {
    directories: Vec<MsiDirectoryEntry>,
    files: Vec<MsiFileEntry>,
    shortcut_component: Option<String>,
    shortcut_target_file: Option<String>,
}

#[derive(Debug)]
struct MsiDirectoryEntry {
    id: String,
    parent_id: String,
    name: String,
}

#[derive(Debug)]
struct MsiFileEntry {
    id: String,
    component_id: String,
    component_guid: String,
    directory_id: String,
    source: PathBuf,
    file_name: String,
    cabinet_name: String,
    size: i32,
    sequence: i32,
}

fn write_msi_archive(package: &PackageReport, artifact: &Path) -> Result<()> {
    if package.platform() != "win32" {
        bail!(
            "MSI maker only supports Windows packages. Requested {}.",
            package.platform()
        );
    }

    let source = Path::new(package.bundle_dir().as_str());
    if !source.exists() {
        bail!("Package output does not exist: {}", source.display());
    }

    let parent = artifact
        .parent()
        .with_context(|| format!("Artifact path has no parent: {}", artifact.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;

    let payload = collect_msi_payload(package, source)?;
    if payload.files.is_empty() {
        bail!(
            "MSI maker requires at least one packaged file in {}",
            source.display()
        );
    }

    let cabinet = create_msi_cabinet(&payload)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(artifact)
        .with_context(|| format!("Could not create {}", artifact.display()))?;
    let mut installer =
        Package::create(PackageType::Installer, file).context("Could not create MSI package")?;

    write_msi_summary(&mut installer, package)?;
    create_msi_tables(&mut installer)?;
    insert_msi_rows(&mut installer, package, &payload)?;
    {
        let mut stream = installer
            .write_stream("app.cab")
            .context("Could not create embedded MSI cabinet stream")?;
        stream
            .write_all(&cabinet)
            .context("Could not write embedded MSI cabinet stream")?;
    }
    installer.flush().context("Could not flush MSI package")?;
    installer
        .into_inner()
        .context("Could not finish MSI package")?;

    Ok(())
}

fn write_msi_summary(installer: &mut Package<File>, package: &PackageReport) -> Result<()> {
    let package_code = deterministic_guid(
        "package-code",
        &[
            package.app_name(),
            package.project().version.as_deref().unwrap_or("0.1.0"),
            package.arch(),
        ],
    );
    let arch = msi_summary_arch(package.arch());
    let language = Language::from_code(1033);
    let summary = installer.summary_info_mut();
    summary.set_title(format!("{} Installer", package.app_name()));
    summary.set_subject(package.app_name().to_string());
    summary.set_author("electron-cli".to_string());
    summary.set_comments(format!(
        "{} packaged by electron-cli.",
        single_line(package.app_name())
    ));
    summary.set_creating_application("electron-cli".to_string());
    summary.set_uuid(package_code);
    summary.set_arch(arch.to_string());
    summary.set_languages(&[language]);
    summary.set_page_count(200);
    summary.set_word_count(2);
    Ok(())
}

fn create_msi_tables(installer: &mut Package<File>) -> Result<()> {
    create_msi_table(
        installer,
        "Property",
        vec![
            Column::build("Property").primary_key().id_string(72),
            Column::build("Value").nullable().formatted_string(0),
        ],
    )?;
    create_msi_table(
        installer,
        "Directory",
        vec![
            Column::build("Directory").primary_key().id_string(72),
            Column::build("Directory_Parent").nullable().id_string(72),
            Column::build("DefaultDir").text_string(255),
        ],
    )?;
    create_msi_table(
        installer,
        "Feature",
        vec![
            Column::build("Feature").primary_key().id_string(38),
            Column::build("Feature_Parent").nullable().id_string(38),
            Column::build("Title").nullable().text_string(64),
            Column::build("Description").nullable().text_string(255),
            Column::build("Display").nullable().int16(),
            Column::build("Level").int16(),
            Column::build("Directory_").nullable().id_string(72),
            Column::build("Attributes").int16(),
        ],
    )?;
    create_msi_table(
        installer,
        "Component",
        vec![
            Column::build("Component").primary_key().id_string(72),
            Column::build("ComponentId").nullable().string(38),
            Column::build("Directory_").id_string(72),
            Column::build("Attributes").int16(),
            Column::build("Condition").nullable().formatted_string(255),
            Column::build("KeyPath").nullable().id_string(72),
        ],
    )?;
    create_msi_table(
        installer,
        "FeatureComponents",
        vec![
            Column::build("Feature_").primary_key().id_string(38),
            Column::build("Component_").primary_key().id_string(72),
        ],
    )?;
    create_msi_table(
        installer,
        "File",
        vec![
            Column::build("File").primary_key().id_string(72),
            Column::build("Component_").id_string(72),
            Column::build("FileName").text_string(255),
            Column::build("FileSize").int32(),
            Column::build("Version").nullable().string(72),
            Column::build("Language").nullable().string(20),
            Column::build("Attributes").nullable().int16(),
            Column::build("Sequence").int16(),
        ],
    )?;
    create_msi_table(
        installer,
        "Media",
        vec![
            Column::build("DiskId").primary_key().int16(),
            Column::build("LastSequence").int16(),
            Column::build("DiskPrompt").nullable().text_string(64),
            Column::build("Cabinet").nullable().string(255),
            Column::build("VolumeLabel").nullable().string(32),
            Column::build("Source").nullable().string(72),
        ],
    )?;
    create_msi_table(
        installer,
        "Shortcut",
        vec![
            Column::build("Shortcut").primary_key().id_string(72),
            Column::build("Directory_").id_string(72),
            Column::build("Name").text_string(128),
            Column::build("Component_").id_string(72),
            Column::build("Target").formatted_string(0),
            Column::build("Arguments").nullable().formatted_string(255),
            Column::build("Description").nullable().text_string(255),
            Column::build("Hotkey").nullable().int16(),
            Column::build("Icon_").nullable().id_string(72),
            Column::build("IconIndex").nullable().int16(),
            Column::build("ShowCmd").nullable().int16(),
            Column::build("WkDir").nullable().id_string(72),
        ],
    )?;
    create_msi_table(
        installer,
        "RemoveFile",
        vec![
            Column::build("FileKey").primary_key().id_string(72),
            Column::build("Component_").id_string(72),
            Column::build("FileName").nullable().text_string(255),
            Column::build("DirProperty").id_string(72),
            Column::build("InstallMode").int16(),
        ],
    )?;
    create_msi_table(
        installer,
        "InstallExecuteSequence",
        vec![
            Column::build("Action").primary_key().id_string(72),
            Column::build("Condition").nullable().formatted_string(255),
            Column::build("Sequence").nullable().int16(),
        ],
    )?;
    create_msi_table(
        installer,
        "ActionText",
        vec![
            Column::build("Action").primary_key().id_string(72),
            Column::build("Description").nullable().text_string(64),
            Column::build("Template").nullable().formatted_string(128),
        ],
    )
}

fn create_msi_table(installer: &mut Package<File>, name: &str, columns: Vec<Column>) -> Result<()> {
    installer
        .create_table(name, columns)
        .with_context(|| format!("Could not create MSI {name} table"))
}

fn insert_msi_rows(
    installer: &mut Package<File>,
    package: &PackageReport,
    payload: &MsiPayload,
) -> Result<()> {
    let product_version = msi_product_version(package.project().version.as_deref());
    let product_code = msi_guid(deterministic_guid(
        "product-code",
        &[package.app_name(), &product_version, package.arch()],
    ));
    let upgrade_code = msi_guid(deterministic_guid(
        "upgrade-code",
        &[
            package.app_name(),
            package.project().name.as_deref().unwrap_or(""),
        ],
    ));
    insert_msi_table_rows(
        installer,
        "Property",
        vec![
            vec![s("ProductCode"), s(product_code)],
            vec![s("ProductLanguage"), s("1033")],
            vec![s("ProductName"), s(package.app_name())],
            vec![s("ProductVersion"), s(product_version)],
            vec![s("Manufacturer"), s("electron-cli")],
            vec![s("UpgradeCode"), s(upgrade_code)],
            vec![s("ALLUSERS"), s("1")],
            vec![s("INSTALLLEVEL"), s("1")],
        ],
    )?;

    let program_files_dir = msi_program_files_directory(package.arch());
    let install_folder = msi_filename("APPDIR", package.app_name());
    insert_msi_table_rows(
        installer,
        "Directory",
        vec![
            vec![s("TARGETDIR"), Value::Null, s("SourceDir")],
            vec![s(program_files_dir), s("TARGETDIR"), s(".")],
            vec![s("INSTALLFOLDER"), s(program_files_dir), s(install_folder)],
            vec![s("ProgramMenuFolder"), s("TARGETDIR"), s(".")],
            vec![
                s("ApplicationProgramsFolder"),
                s("ProgramMenuFolder"),
                s(msi_filename("APPMENU", package.app_name())),
            ],
        ],
    )?;
    insert_msi_table_rows(
        installer,
        "Directory",
        payload
            .directories
            .iter()
            .map(|directory| {
                vec![
                    s(&directory.id),
                    s(&directory.parent_id),
                    s(&directory.name),
                ]
            })
            .collect(),
    )?;

    insert_msi_table_rows(
        installer,
        "Feature",
        vec![vec![
            s("MainFeature"),
            Value::Null,
            s(package.app_name()),
            s(format!("Install {}.", single_line(package.app_name()))),
            Value::from(1),
            Value::from(1),
            s("INSTALLFOLDER"),
            Value::from(0),
        ]],
    )?;

    let component_attributes = msi_component_attributes(package.arch());
    insert_msi_table_rows(
        installer,
        "Component",
        payload
            .files
            .iter()
            .map(|file| {
                vec![
                    s(&file.component_id),
                    s(&file.component_guid),
                    s(&file.directory_id),
                    Value::from(component_attributes),
                    Value::Null,
                    s(&file.id),
                ]
            })
            .collect(),
    )?;
    insert_msi_table_rows(
        installer,
        "FeatureComponents",
        payload
            .files
            .iter()
            .map(|file| vec![s("MainFeature"), s(&file.component_id)])
            .collect(),
    )?;
    insert_msi_table_rows(
        installer,
        "File",
        payload
            .files
            .iter()
            .map(|file| {
                vec![
                    s(&file.id),
                    s(&file.component_id),
                    s(&file.file_name),
                    Value::from(file.size),
                    Value::Null,
                    Value::Null,
                    Value::from(0),
                    Value::from(file.sequence),
                ]
            })
            .collect(),
    )?;
    insert_msi_table_rows(
        installer,
        "Media",
        vec![vec![
            Value::from(1),
            Value::from(payload.files.len() as i32),
            Value::Null,
            s("#app.cab"),
            Value::Null,
            Value::Null,
        ]],
    )?;

    if let (Some(component), Some(target_file)) =
        (&payload.shortcut_component, &payload.shortcut_target_file)
    {
        insert_msi_table_rows(
            installer,
            "Shortcut",
            vec![vec![
                s("ApplicationShortcut"),
                s("ApplicationProgramsFolder"),
                s(msi_filename("SHORTCUT", package.app_name())),
                s(component),
                s(format!("[#{target_file}]")),
                Value::Null,
                s(format!("Launch {}.", single_line(package.app_name()))),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                s("INSTALLFOLDER"),
            ]],
        )?;
        insert_msi_table_rows(
            installer,
            "RemoveFile",
            vec![vec![
                s("RemoveStartMenuFolder"),
                s(component),
                Value::Null,
                s("ApplicationProgramsFolder"),
                Value::from(2),
            ]],
        )?;
    }

    insert_msi_table_rows(
        installer,
        "InstallExecuteSequence",
        vec![
            standard_action("CostInitialize", 800),
            standard_action("FileCost", 900),
            standard_action("CostFinalize", 1000),
            standard_action("InstallValidate", 1400),
            standard_action("InstallInitialize", 1500),
            standard_action("ProcessComponents", 1600),
            standard_action("UnpublishFeatures", 1800),
            standard_action("RemoveShortcuts", 3200),
            standard_action("RemoveFiles", 3500),
            standard_action("InstallFiles", 4000),
            standard_action("CreateShortcuts", 4500),
            standard_action("RegisterUser", 6000),
            standard_action("RegisterProduct", 6100),
            standard_action("PublishFeatures", 6300),
            standard_action("PublishProduct", 6400),
            standard_action("InstallFinalize", 6600),
        ],
    )?;
    insert_msi_table_rows(
        installer,
        "ActionText",
        vec![
            action_text(
                "InstallFiles",
                "Copying new files",
                "File: [1],  Directory: [9],  Size: [6]",
            ),
            action_text("CreateShortcuts", "Creating shortcuts", "Shortcut: [1]"),
            action_text("RemoveFiles", "Removing files", "File: [1], Directory: [9]"),
            action_text("RemoveShortcuts", "Removing shortcuts", "Shortcut: [1]"),
        ],
    )
}

fn insert_msi_table_rows(
    installer: &mut Package<File>,
    table: &str,
    rows: Vec<Vec<Value>>,
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    installer
        .insert_rows(Insert::into(table).rows(rows))
        .with_context(|| format!("Could not insert MSI {table} rows"))
}

fn standard_action(action: &str, sequence: i32) -> Vec<Value> {
    vec![s(action), Value::Null, Value::from(sequence)]
}

fn action_text(action: &str, description: &str, template: &str) -> Vec<Value> {
    vec![s(action), s(description), s(template)]
}

fn collect_msi_payload(package: &PackageReport, source: &Path) -> Result<MsiPayload> {
    let mut payload = MsiPayload {
        directories: Vec::new(),
        files: Vec::new(),
        shortcut_component: None,
        shortcut_target_file: None,
    };
    let mut directory_ids = BTreeMap::from([(PathBuf::new(), "INSTALLFOLDER".to_string())]);
    collect_msi_directory(
        package,
        source,
        Path::new(""),
        "INSTALLFOLDER",
        &mut directory_ids,
        &mut payload,
    )?;

    if payload.files.len() > i16::MAX as usize {
        bail!(
            "MSI maker supports up to {} files; package contains {}.",
            i16::MAX,
            payload.files.len()
        );
    }

    Ok(payload)
}

fn collect_msi_directory(
    package: &PackageReport,
    source: &Path,
    relative_dir: &Path,
    directory_id: &str,
    directory_ids: &mut BTreeMap<PathBuf, String>,
    payload: &mut MsiPayload,
) -> Result<()> {
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("Could not read {}", source.display()))?
        .collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_name = utf8_file_name(&path)?.to_string();
        let relative_path = relative_dir.join(&file_name);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("Could not stat {}", path.display()))?;

        if metadata.file_type().is_symlink() {
            bail!(
                "MSI maker does not support symbolic links yet: {}",
                path.display()
            );
        }

        if metadata.is_dir() {
            let dir_id = format!("D{:04}", directory_ids.len());
            directory_ids.insert(relative_path.clone(), dir_id.clone());
            payload.directories.push(MsiDirectoryEntry {
                id: dir_id.clone(),
                parent_id: directory_id.to_string(),
                name: msi_filename(&dir_id, &file_name),
            });
            collect_msi_directory(
                package,
                &path,
                &relative_path,
                &dir_id,
                directory_ids,
                payload,
            )?;
        } else if metadata.is_file() {
            let sequence = payload.files.len() + 1;
            let size = i32::try_from(metadata.len())
                .with_context(|| format!("MSI file is too large: {}", path.display()))?;
            let file_id = format!("F{sequence:04}");
            let component_id = format!("C{sequence:04}");
            let relative_key = relative_path.to_string_lossy().replace('\\', "/");
            let component_guid = msi_guid(deterministic_guid(
                "component",
                &[
                    package.app_name(),
                    package.project().name.as_deref().unwrap_or(""),
                    &relative_key,
                ],
            ));
            let entry = MsiFileEntry {
                id: file_id.clone(),
                component_id: component_id.clone(),
                component_guid,
                directory_id: directory_id.to_string(),
                source: path.clone(),
                file_name: msi_filename(&file_id, &file_name),
                cabinet_name: file_id.clone(),
                size,
                sequence: sequence as i32,
            };

            if file_name.eq_ignore_ascii_case(package.executable_name()) {
                payload.shortcut_component = Some(component_id);
                payload.shortcut_target_file = Some(file_id);
            }

            payload.files.push(entry);
        }
    }

    Ok(())
}

fn create_msi_cabinet(payload: &MsiPayload) -> Result<Vec<u8>> {
    let mut builder = CabinetBuilder::new();
    {
        let folder = builder.add_folder(CabCompressionType::MsZip);
        for file in &payload.files {
            folder.add_file(&file.cabinet_name);
        }
    }

    let cursor = Cursor::new(Vec::new());
    let mut cabinet = builder
        .build(cursor)
        .context("Could not start MSI cabinet")?;
    for file in &payload.files {
        let mut writer = cabinet
            .next_file()
            .context("Could not open next MSI cabinet file")?
            .context("MSI cabinet writer finished before all files were written")?;
        anyhow::ensure!(
            writer.file_name() == file.cabinet_name,
            "MSI cabinet file order drifted while writing {}",
            file.source.display()
        );
        let mut source = File::open(&file.source)
            .with_context(|| format!("Could not open {}", file.source.display()))?;
        io::copy(&mut source, &mut writer)
            .with_context(|| format!("Could not add {} to MSI cabinet", file.source.display()))?;
    }
    let cursor = cabinet.finish().context("Could not finish MSI cabinet")?;
    Ok(cursor.into_inner())
}

fn debian_control_file(
    package: &PackageReport,
    deb_package: &str,
    version: &str,
    arch: &str,
    installed_size: u64,
) -> String {
    format!(
        "Package: {deb_package}\n\
         Version: {version}\n\
         Section: utils\n\
         Priority: optional\n\
         Architecture: {arch}\n\
         Maintainer: electron-cli <noreply@example.invalid>\n\
         Installed-Size: {installed_size}\n\
         Description: {description}\n\
          Electron application packaged by electron-cli.\n",
        description = single_line(package.app_name())
    )
}

fn append_deb_data_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    package: &PackageReport,
    source: &Path,
    deb_package: &str,
    linux_icon: Option<&MakeIconResource>,
) -> Result<()> {
    for directory in [
        "./",
        "./opt",
        "./usr",
        "./usr/bin",
        "./usr/share",
        "./usr/share/applications",
    ] {
        append_directory_to_tar(builder, directory, 0o755)?;
    }
    if linux_icon.is_some() {
        append_directory_to_tar(builder, "./usr/share/pixmaps", 0o755)?;
    }

    let app_root = format!("./opt/{deb_package}");
    append_directory_to_tar(builder, &app_root, 0o755)?;
    append_directory_contents_to_tar(builder, source, Path::new(&app_root))?;

    let executable = format!("/opt/{deb_package}/{}", package.executable_name());
    append_symlink_to_tar(
        builder,
        format!("./usr/bin/{deb_package}"),
        &executable,
        0o777,
    )?;
    append_bytes_to_tar(
        builder,
        format!("./usr/share/applications/{deb_package}.desktop"),
        debian_desktop_file(package, deb_package, &executable, linux_icon.is_some()).as_bytes(),
        0o644,
    )?;
    if let Some(icon) = linux_icon {
        append_path_to_tar(
            builder,
            Path::new(icon.from.as_str()),
            Path::new(&format!(".{}", icon.to)),
        )?;
    }

    Ok(())
}

fn debian_desktop_file(
    package: &PackageReport,
    deb_package: &str,
    executable: &str,
    has_icon: bool,
) -> String {
    desktop_file(package, deb_package, executable, has_icon)
}

fn rpm_desktop_file(
    package: &PackageReport,
    rpm_package: &str,
    executable: &str,
    has_icon: bool,
) -> String {
    desktop_file(package, rpm_package, executable, has_icon)
}

fn desktop_file(
    package: &PackageReport,
    package_name: &str,
    executable: &str,
    has_icon: bool,
) -> String {
    let icon_line = if has_icon {
        format!("Icon={package_name}\n")
    } else {
        String::new()
    };
    format!(
        "[Desktop Entry]\n\
         Name={name}\n\
         Exec={executable} %U\n\
         {icon_line}\
         Terminal=false\n\
         Type=Application\n\
         StartupWMClass={wm_class}\n\
         Categories=Utility;\n",
        name = single_line(package.app_name()),
        wm_class = package_name
    )
}

fn gzip_tar(
    write_contents: impl FnOnce(&mut TarBuilder<GzEncoder<Vec<u8>>>) -> Result<()>,
) -> Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = TarBuilder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);
    write_contents(&mut builder)?;
    builder.finish().context("Could not finish tar archive")?;
    let encoder = builder
        .into_inner()
        .context("Could not retrieve gzip encoder")?;
    encoder.finish().context("Could not finish gzip archive")
}

fn append_directory_contents_to_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("Could not read {}", source.display()))?
        .collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        append_path_to_tar(builder, &source_path, &destination_path)?;
    }

    Ok(())
}

fn append_path_to_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("Could not stat {}", source.display()))?;

    if metadata.is_dir() {
        append_directory_to_tar(builder, destination, unix_mode(&metadata, 0o755))?;
        append_directory_contents_to_tar(builder, source, destination)?;
    } else if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)
            .with_context(|| format!("Could not read link {}", source.display()))?;
        append_symlink_to_tar(builder, destination, &target, 0o777)?;
    } else if metadata.is_file() {
        append_file_to_tar(builder, source, destination, &metadata)?;
    }

    Ok(())
}

fn append_directory_to_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    path: impl AsRef<Path>,
    mode: u32,
) -> Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_cksum();
    builder
        .append_data(&mut header, path.as_ref(), io::empty())
        .with_context(|| format!("Could not add {} to data tar", path.as_ref().display()))
}

fn append_file_to_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    source: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
) -> Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(metadata.len());
    header.set_mode(unix_mode(metadata, 0o644));
    header.set_mtime(0);
    header.set_cksum();
    let mut file =
        File::open(source).with_context(|| format!("Could not open {}", source.display()))?;
    builder
        .append_data(&mut header, destination, &mut file)
        .with_context(|| format!("Could not add {} to data tar", source.display()))
}

fn append_bytes_to_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    path: impl AsRef<Path>,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(contents.len() as u64);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_cksum();
    builder
        .append_data(&mut header, path.as_ref(), contents)
        .with_context(|| format!("Could not add {} to tar", path.as_ref().display()))
}

fn append_symlink_to_tar(
    builder: &mut TarBuilder<GzEncoder<Vec<u8>>>,
    path: impl AsRef<Path>,
    target: impl AsRef<Path>,
    mode: u32,
) -> Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(mode);
    header.set_mtime(0);
    header
        .set_link_name(target.as_ref())
        .with_context(|| format!("Could not set link target for {}", path.as_ref().display()))?;
    header.set_cksum();
    builder
        .append_data(&mut header, path.as_ref(), io::empty())
        .with_context(|| format!("Could not add {} to tar", path.as_ref().display()))
}

struct ArMember {
    name: &'static str,
    mode: u32,
    data: Vec<u8>,
}

fn write_ar_archive(artifact: &Path, members: &[ArMember]) -> Result<()> {
    let mut file = BufWriter::new(
        File::create(artifact)
            .with_context(|| format!("Could not create {}", artifact.display()))?,
    );
    file.write_all(b"!<arch>\n")
        .with_context(|| format!("Could not write {}", artifact.display()))?;

    for member in members {
        write_ar_member(&mut file, member)
            .with_context(|| format!("Could not add {} to {}", member.name, artifact.display()))?;
    }

    file.flush()
        .with_context(|| format!("Could not finish {}", artifact.display()))
}

fn write_ar_member(writer: &mut impl Write, member: &ArMember) -> Result<()> {
    let name = format!("{}/", member.name);
    if name.len() > 16 {
        bail!("ar member name is too long: {}", member.name);
    }

    let header = format!(
        "{name:<16}{mtime:<12}{uid:<6}{gid:<6}{mode:<8o}{size:<10}`\n",
        mtime = 0,
        uid = 0,
        gid = 0,
        mode = member.mode,
        size = member.data.len()
    );
    debug_assert_eq!(header.len(), 60);
    writer.write_all(header.as_bytes())?;
    writer.write_all(&member.data)?;
    if member.data.len() % 2 == 1 {
        writer.write_all(b"\n")?;
    }

    Ok(())
}

fn directory_size(path: &Path) -> Result<u64> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("Could not stat {}", path.display()))?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }

    let mut size = 0;
    for entry in fs::read_dir(path).with_context(|| format!("Could not read {}", path.display()))? {
        let entry = entry?;
        size += directory_size(&entry.path())?;
    }
    Ok(size)
}

fn debian_package_name(name: &str) -> String {
    package_name(name)
}

fn rpm_package_name(name: &str) -> String {
    package_name(name)
}

fn package_name(name: &str) -> String {
    let mut package = name
        .to_ascii_lowercase()
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '+' | '-' | '.') {
                char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(['+', '-', '.'])
        .to_string();

    if package.len() < 2 {
        package.push_str("app");
    }

    package
}

fn debian_version(version: Option<&str>) -> String {
    let version = version.unwrap_or("0.1.0");
    let sanitized = version
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '.' | '+' | '-' | ':' | '~') {
                char
            } else {
                '~'
            }
        })
        .collect::<String>()
        .trim_matches(['-', '~'])
        .to_string();

    if sanitized.is_empty() {
        "0.1.0".to_string()
    } else {
        sanitized
    }
}

fn dmg_version(version: Option<&str>) -> String {
    let version = version.unwrap_or("0.1.0");
    let sanitized = version
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '.' | '-' | '_') {
                char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(['-', '.', '_'])
        .to_string();

    if sanitized.is_empty() {
        "0.1.0".to_string()
    } else {
        sanitized
    }
}

fn rpm_version(version: Option<&str>) -> String {
    let version = version.unwrap_or("0.1.0");
    let sanitized = version
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '.' | '+' | '_' | '~') {
                char
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches(['_', '~'])
        .to_string();

    if sanitized.is_empty() {
        "0.1.0".to_string()
    } else {
        sanitized
    }
}

fn windows_artifact_version(version: Option<&str>) -> String {
    let version = version.unwrap_or("0.1.0");
    let sanitized = version
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || matches!(char, '.' | '-' | '_') {
                char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(['-', '.', '_'])
        .to_string();

    if sanitized.is_empty() {
        "0.1.0".to_string()
    } else {
        sanitized
    }
}

fn msi_product_version(version: Option<&str>) -> String {
    let mut numbers = version
        .unwrap_or("0.1.0")
        .split(|char: char| !char.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u32>().ok())
        .take(3)
        .collect::<Vec<_>>();
    while numbers.len() < 3 {
        numbers.push(0);
    }
    if numbers.iter().all(|number| *number == 0) {
        numbers = vec![0, 1, 0];
    }

    format!(
        "{}.{}.{}",
        numbers[0].min(255),
        numbers[1].min(255),
        numbers[2].min(65_535)
    )
}

fn debian_arch(arch: &str) -> String {
    match arch {
        "x64" => "amd64".to_string(),
        "ia32" => "i386".to_string(),
        "armv7l" => "armhf".to_string(),
        arch => arch.to_string(),
    }
}

fn rpm_arch(arch: &str) -> String {
    match arch {
        "x64" => "x86_64".to_string(),
        "arm64" => "aarch64".to_string(),
        "ia32" => "i386".to_string(),
        "armv7l" => "armv7hl".to_string(),
        arch => arch.to_string(),
    }
}

fn windows_arch(arch: &str) -> String {
    match arch {
        "ia32" => "x86".to_string(),
        arch => arch.to_string(),
    }
}

fn msi_summary_arch(arch: &str) -> &'static str {
    match arch {
        "x64" => "x64",
        "arm64" => "Arm64",
        _ => "Intel",
    }
}

fn msi_program_files_directory(arch: &str) -> &'static str {
    match arch {
        "x64" | "arm64" => "ProgramFiles64Folder",
        _ => "ProgramFilesFolder",
    }
}

fn msi_component_attributes(arch: &str) -> i32 {
    match arch {
        "x64" | "arm64" => 256,
        _ => 0,
    }
}

fn msi_filename(id: &str, long_name: &str) -> String {
    if is_msi_short_name(long_name) {
        return long_name.to_string();
    }

    let extension = Path::new(long_name)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            extension
                .chars()
                .filter(|char| char.is_ascii_alphanumeric())
                .take(3)
                .collect::<String>()
        })
        .filter(|extension| !extension.is_empty());
    let stem = id
        .chars()
        .filter(|char| char.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>();
    let short = match extension {
        Some(extension) => format!("{stem}.{extension}"),
        None => stem,
    };
    format!("{short}|{long_name}")
}

fn is_msi_short_name(name: &str) -> bool {
    let Some(file_name) = Path::new(name).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if file_name != name || file_name.is_empty() || file_name.contains(' ') {
        return false;
    }

    let mut parts = file_name.split('.');
    let stem = parts.next().unwrap_or_default();
    let extension = parts.next();
    if parts.next().is_some() || stem.is_empty() || stem.len() > 8 {
        return false;
    }
    if extension.is_some_and(|extension| extension.is_empty() || extension.len() > 3) {
        return false;
    }

    file_name
        .chars()
        .all(|char| char.is_ascii_alphanumeric() || matches!(char, '_' | '$' | '~' | '!' | '#'))
}

fn deterministic_guid(kind: &str, parts: &[&str]) -> Uuid {
    let key = format!("electron-cli:{kind}:{}", parts.join(":"));
    Uuid::new_v5(&Uuid::NAMESPACE_URL, key.as_bytes())
}

fn msi_guid(uuid: Uuid) -> String {
    format!("{{{}}}", uuid.hyphenated()).to_ascii_uppercase()
}

fn s(value: impl Into<String>) -> Value {
    Value::from(value.into())
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|char| {
            if char == '\n' || char == '\r' {
                ' '
            } else {
                char
            }
        })
        .collect()
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

impl MakeReport {
    pub(crate) fn mark_made(&mut self) -> Result<()> {
        self.status = MakeStatus::Made;
        self.artifact_size = Some(
            fs::metadata(self.artifact.as_str())
                .with_context(|| format!("Could not stat {}", self.artifact))?
                .len(),
        );
        Ok(())
    }

    pub(crate) fn package(&self) -> &PackageReport {
        &self.package
    }

    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    pub(crate) fn artifact(&self) -> &Utf8PathBuf {
        &self.artifact
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
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
            target: Some(crate::cli::MakeTarget::Zip),
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
    fn builds_make_report_for_deb_target() {
        let root = unique_temp_dir("deb-plan");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: Some(crate::cli::MakeTarget::Deb),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.target, "deb");
        assert!(Path::new(report.artifact.as_str()).ends_with(
            PathBuf::from("out")
                .join("make")
                .join("deb")
                .join("linux")
                .join("x64")
                .join("starter-app_0.1.0_amd64.deb")
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_make_report_for_dmg_target() {
        let root = unique_temp_dir("dmg-plan");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            target: Some(crate::cli::MakeTarget::Dmg),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.target, "dmg");
        assert!(Path::new(report.artifact.as_str()).ends_with(
            PathBuf::from("out")
                .join("make")
                .join("dmg")
                .join("darwin")
                .join("arm64")
                .join("starter-app-0.1.0-arm64.dmg")
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_make_report_for_rpm_target() {
        let root = unique_temp_dir("rpm-plan");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: Some(crate::cli::MakeTarget::Rpm),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.target, "rpm");
        assert!(Path::new(report.artifact.as_str()).ends_with(
            PathBuf::from("out")
                .join("make")
                .join("rpm")
                .join("linux")
                .join("x64")
                .join("starter-app-0.1.0-1.x86_64.rpm")
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_make_report_for_msi_target() {
        let root = unique_temp_dir("msi-plan");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("win32".to_string()),
            arch: Some("x64".to_string()),
            target: Some(crate::cli::MakeTarget::Msi),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.target, "msi");
        assert!(Path::new(report.artifact.as_str()).ends_with(
            PathBuf::from("out")
                .join("make")
                .join("msi")
                .join("win32")
                .join("x64")
                .join("starter-app-0.1.0-x64.msi")
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_make_reports_from_configured_forge_makers() {
        let root = unique_temp_dir("configured-makers");
        write_package_json_with_makers(
            &root,
            r#"[
                {"name":"@electron-forge/maker-zip"},
                {"name":"@electron-forge/maker-deb","platforms":["linux"]},
                {"name":"@electron-forge/maker-rpm","platforms":["darwin"]},
                {"name":"@electron-forge/maker-squirrel","platforms":["linux"]}
            ]"#,
        );
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: None,
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let reports = build_reports(&args).expect("reports should build");

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].target(), "zip");
        assert_eq!(reports[1].target(), "deb");
        assert!(reports[0]
            .warnings()
            .iter()
            .any(|warning| warning.contains("@electron-forge/maker-squirrel")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_make_reports_from_static_forge_config_js() {
        let root = unique_temp_dir("configured-makers-js");
        write_package_json(&root);
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              makers: [
                { name: '@electron-forge/maker-zip' },
                { name: '@electron-forge/maker-rpm', platforms: ['linux'] },
              ],
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: None,
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let reports = build_reports(&args).expect("reports should build");

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].target(), "zip");
        assert_eq!(reports[1].target(), "rpm");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_make_target_overrides_configured_makers() {
        let root = unique_temp_dir("target-override");
        write_package_json_with_makers(
            &root,
            r#"[{"name":"@electron-forge/maker-zip"},{"name":"@electron-forge/maker-deb"}]"#,
        );
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("win32".to_string()),
            arch: Some("x64".to_string()),
            target: Some(crate::cli::MakeTarget::Msi),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.target(), "msi");
        assert!(report
            .warnings()
            .iter()
            .all(|warning| !warning.contains("maker-deb")));

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
            target: Some(crate::cli::MakeTarget::Zip),
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

    #[test]
    fn makes_multiple_configured_artifacts_from_existing_package() {
        let root = unique_temp_dir("configured-execute");
        write_package_json_with_makers(
            &root,
            r#"[
                {"name":"@electron-forge/maker-zip","platforms":["win32"]},
                {"name":"@electron-forge/maker-wix","platforms":["win32"]}
            ]"#,
        );
        write_app_file(&root);
        write_fake_windows_bundle(&root.join("out/starter-app-win32-x64"), "starter-app.exe");

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("win32".to_string()),
            arch: Some("x64".to_string()),
            target: None,
            skip_package: true,
            force: false,
            dry_run: false,
            json: true,
        };
        let mut reports = build_reports(&args).expect("reports should build");

        execute_make_reports(&mut reports, &args).expect("configured makers should execute");

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].target(), "zip");
        assert_eq!(reports[1].target(), "msi");
        assert!(Path::new(reports[0].artifact.as_str()).exists());
        assert!(Path::new(reports[1].artifact.as_str()).exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writes_deb_archive_with_control_and_data_members() {
        let root = unique_temp_dir("deb-archive");
        write_package_json_with_makers(
            &root,
            r#"[{"name":"@electron-forge/maker-deb","config":{"options":{"icon":"assets/icon.png"}}}]"#,
        );
        write_app_file(&root);
        write_fake_electron_dist(&root);
        fs::create_dir_all(root.join("assets")).expect("assets should be created");
        fs::write(root.join("assets/icon.png"), b"png").expect("icon should be written");

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: None,
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");
        assert_eq!(report.target, "deb");
        assert!(report.linux_icon.is_some());
        let bundle_dir = Path::new(report.package.bundle_dir().as_str());
        fs::create_dir_all(bundle_dir.join("resources/app"))
            .expect("fake bundle resources should be created");
        fs::write(bundle_dir.join("starter-app"), "").expect("fake binary should be written");
        fs::write(bundle_dir.join("resources/app/package.json"), "{}")
            .expect("fake app package should be written");

        write_deb_archive(
            &report.package,
            report.linux_icon.as_ref(),
            Path::new(report.artifact.as_str()),
        )
        .expect("deb should be written");

        let members = read_ar_members(Path::new(report.artifact.as_str()));
        assert_eq!(
            members.get("debian-binary").map(Vec::as_slice),
            Some(&b"2.0\n"[..])
        );

        let control = read_tar_file(
            members
                .get("control.tar.gz")
                .expect("control tar should exist"),
            "control",
        );
        assert!(control.contains("Package: starter-app"));
        assert!(control.contains("Architecture: amd64"));

        let data = members.get("data.tar.gz").expect("data tar should exist");
        assert!(tar_contains(
            data,
            "opt/starter-app/resources/app/package.json"
        ));
        assert!(tar_contains(
            data,
            "usr/share/applications/starter-app.desktop"
        ));
        assert!(tar_contains(data, "usr/share/pixmaps/starter-app.png"));
        assert!(tar_contains(data, "usr/bin/starter-app"));
        let desktop = read_tar_file(data, "usr/share/applications/starter-app.desktop");
        assert!(desktop.contains("Icon=starter-app"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writes_dmg_archive_with_app_bundle_and_applications_entry() {
        let root = unique_temp_dir("dmg-archive");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            target: Some(crate::cli::MakeTarget::Dmg),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");
        write_fake_macos_bundle(
            Path::new(report.package.bundle_dir().as_str()),
            "starter-app",
        );

        write_dmg_archive(&report.package, Path::new(report.artifact.as_str()))
            .expect("dmg should be written");

        let mut dmg = apple_dmg::DmgReader::open(Path::new(report.artifact.as_str()))
            .expect("dmg should parse");
        assert_eq!(dmg.plist().partitions().len(), 2);
        let fat32 = dmg.partition_data(1).expect("fat32 partition should read");
        let fs = fatfs::FileSystem::new(Cursor::new(fat32), fatfs::FsOptions::new())
            .expect("fat32 should mount");
        let root_dir = fs.root_dir();
        let entries = root_dir
            .iter()
            .map(|entry| entry.expect("fat entry should read").file_name())
            .collect::<Vec<_>>();
        assert!(entries.contains(&"starter-app.app".to_string()));
        assert!(entries.contains(&"Applications".to_string()));

        let app_dir = root_dir
            .open_dir("starter-app.app")
            .expect("app bundle should exist");
        let contents = app_dir.open_dir("Contents").expect("Contents should exist");
        let resources = contents
            .open_dir("Resources")
            .expect("Resources should exist");
        let app_resources = resources
            .open_dir("app")
            .expect("app resources should exist");
        app_resources
            .open_file("package.json")
            .expect("app package should exist");

        let mut applications = String::new();
        root_dir
            .open_file("Applications")
            .expect("Applications entry should exist")
            .read_to_string(&mut applications)
            .expect("Applications entry should read");
        assert!(applications.starts_with("XSym\n0013\n"));
        assert!(applications.contains("/Applications"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writes_rpm_archive_with_metadata_and_payload_entries() {
        let root = unique_temp_dir("rpm-archive");
        write_package_json_with_packager_config(&root, r#"{"icon":"assets/icon.png"}"#);
        write_app_file(&root);
        write_fake_electron_dist(&root);
        fs::create_dir_all(root.join("assets")).expect("assets should be created");
        fs::write(root.join("assets/icon.png"), b"png").expect("icon should be written");

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: Some(crate::cli::MakeTarget::Rpm),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");
        assert!(report.linux_icon.is_some());
        let bundle_dir = Path::new(report.package.bundle_dir().as_str());
        fs::create_dir_all(bundle_dir.join("resources/app"))
            .expect("fake bundle resources should be created");
        fs::write(bundle_dir.join("starter-app"), "").expect("fake binary should be written");
        fs::write(bundle_dir.join("resources/app/package.json"), "{}")
            .expect("fake app package should be written");

        write_rpm_archive(
            &report.package,
            report.linux_icon.as_ref(),
            Path::new(report.artifact.as_str()),
        )
        .expect("rpm should be written");

        let rpm = rpm::Package::open(report.artifact.as_str()).expect("rpm should parse");
        assert_eq!(
            rpm.metadata.get_name().expect("name should read"),
            "starter-app"
        );
        assert_eq!(
            rpm.metadata.get_version().expect("version should read"),
            "0.1.0"
        );
        assert_eq!(
            rpm.metadata.get_release().expect("release should read"),
            "1"
        );
        assert_eq!(rpm.metadata.get_arch().expect("arch should read"), "x86_64");

        let paths = rpm
            .metadata
            .get_file_paths()
            .expect("file paths should read")
            .into_iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"/opt/starter-app/resources/app/package.json".to_string()));
        assert!(paths.contains(&"/usr/share/applications/starter-app.desktop".to_string()));
        assert!(paths.contains(&"/usr/share/pixmaps/starter-app.png".to_string()));
        assert!(paths.contains(&"/usr/bin/starter-app".to_string()));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writes_msi_archive_with_database_tables_and_embedded_cabinet() {
        let root = unique_temp_dir("msi-archive");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("win32".to_string()),
            arch: Some("x64".to_string()),
            target: Some(crate::cli::MakeTarget::Msi),
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");
        write_fake_windows_bundle(
            Path::new(report.package.bundle_dir().as_str()),
            "starter-app.exe",
        );

        write_msi_archive(&report.package, Path::new(report.artifact.as_str()))
            .expect("msi should be written");

        let mut installer = msi::open(report.artifact.as_str()).expect("msi should parse");
        assert_eq!(installer.summary_info().arch(), Some("x64"));
        assert!(installer.has_table("Property"));
        assert!(installer.has_table("Directory"));
        assert!(installer.has_table("File"));
        assert!(installer.has_table("Media"));
        assert!(installer.has_stream("app.cab"));

        let properties = msi_rows(&mut installer, "Property");
        assert!(properties.contains(&vec![
            Value::from("ProductName"),
            Value::from("starter-app")
        ]));
        assert!(properties.contains(&vec![Value::from("ProductVersion"), Value::from("0.1.0")]));

        let files = msi_rows(&mut installer, "File");
        assert!(files
            .iter()
            .any(|row| row[2] == Value::from("F0001.jso|package.json")));
        assert!(files
            .iter()
            .any(|row| row[2] == Value::from("F0002.exe|starter-app.exe")));

        let mut cabinet_bytes = Vec::new();
        installer
            .read_stream("app.cab")
            .expect("cab stream should open")
            .read_to_end(&mut cabinet_bytes)
            .expect("cab stream should read");
        let mut cabinet =
            cab::Cabinet::new(Cursor::new(cabinet_bytes)).expect("cabinet should parse");
        let mut package_json = String::new();
        cabinet
            .read_file("F0001")
            .expect("package.json cabinet entry should open")
            .read_to_string(&mut package_json)
            .expect("package.json cabinet entry should read");
        assert_eq!(package_json, "{}");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn makes_deb_artifact_after_packaging_on_linux() {
        if !cfg!(target_os = "linux") {
            return;
        }

        let root = unique_temp_dir("deb-execute");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: Some(crate::cli::MakeTarget::Deb),
            skip_package: false,
            force: false,
            dry_run: false,
            json: false,
        };
        let mut report = build_report(&args).expect("report should build");

        execute_make(&mut report, &args).expect("make should succeed");

        assert!(Path::new(report.artifact.as_str()).exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn makes_dmg_artifact_after_packaging_on_macos() {
        if !cfg!(target_os = "macos") {
            return;
        }

        let root = unique_temp_dir("dmg-execute");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: Some(crate::cli::MakeTarget::Dmg),
            skip_package: false,
            force: false,
            dry_run: false,
            json: false,
        };
        let mut report = build_report(&args).expect("report should build");

        execute_make(&mut report, &args).expect("make should succeed");

        assert!(Path::new(report.artifact.as_str()).exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn makes_rpm_artifact_after_packaging_on_linux() {
        if !cfg!(target_os = "linux") {
            return;
        }

        let root = unique_temp_dir("rpm-execute");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: Some(crate::cli::MakeTarget::Rpm),
            skip_package: false,
            force: false,
            dry_run: false,
            json: false,
        };
        let mut report = build_report(&args).expect("report should build");

        execute_make(&mut report, &args).expect("make should succeed");

        assert!(Path::new(report.artifact.as_str()).exists());

        let _ = fs::remove_dir_all(root);
    }

    fn write_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","license":"MIT","main":"src/main.js","devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
    }

    fn write_package_json_with_makers(root: &Path, makers: &str) {
        fs::write(
            root.join("package.json"),
            format!(
                r#"{{
                    "name":"starter-app",
                    "version":"0.1.0",
                    "license":"MIT",
                    "main":"src/main.js",
                    "devDependencies":{{"electron":"30.0.0"}},
                    "config":{{"forge":{{"makers":{makers}}}}}
                }}"#
            ),
        )
        .expect("package.json with makers should be written");
    }

    fn write_package_json_with_packager_config(root: &Path, packager_config: &str) {
        fs::write(
            root.join("package.json"),
            format!(
                r#"{{
                    "name":"starter-app",
                    "version":"0.1.0",
                    "license":"MIT",
                    "main":"src/main.js",
                    "devDependencies":{{"electron":"30.0.0"}},
                    "config":{{"forge":{{"packagerConfig":{packager_config}}}}}
                }}"#
            ),
        )
        .expect("package.json with packager config should be written");
    }

    fn write_app_file(root: &Path) {
        fs::create_dir_all(root.join("src")).expect("src should be created");
        fs::write(root.join("src/main.js"), "console.log('hello');")
            .expect("main file should be written");
    }

    fn write_fake_macos_bundle(bundle_dir: &Path, executable_name: &str) {
        fs::create_dir_all(bundle_dir.join("Contents/MacOS"))
            .expect("fake macOS executable directory should be created");
        fs::create_dir_all(bundle_dir.join("Contents/Resources/app"))
            .expect("fake macOS resources should be created");
        fs::write(
            bundle_dir.join("Contents/MacOS").join(executable_name),
            "#!/bin/sh\n",
        )
        .expect("fake macOS executable should be written");
        fs::write(bundle_dir.join("Contents/Info.plist"), "<plist/>")
            .expect("fake macOS plist should be written");
        fs::write(bundle_dir.join("Contents/Resources/app/package.json"), "{}")
            .expect("fake app package should be written");
    }

    fn write_fake_windows_bundle(bundle_dir: &Path, executable_name: &str) {
        fs::create_dir_all(bundle_dir.join("resources/app"))
            .expect("fake Windows resources should be created");
        fs::write(bundle_dir.join(executable_name), "fake exe")
            .expect("fake Windows executable should be written");
        fs::write(bundle_dir.join("resources/app/package.json"), "{}")
            .expect("fake app package should be written");
    }

    fn write_fake_electron_dist(root: &Path) {
        let dist = root.join("node_modules/electron/dist");
        if cfg!(target_os = "macos") {
            let app = dist.join("Electron.app/Contents/MacOS");
            fs::create_dir_all(&app).expect("fake macOS electron app should be created");
            fs::write(app.join("Electron"), "").expect("fake macOS binary should be written");
        } else if cfg!(target_os = "windows") {
            fs::create_dir_all(&dist).expect("fake electron dist should be created");
            crate::commands::package::write_minimal_pe_executable(&dist.join("electron.exe"));
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

    fn read_ar_members(path: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let bytes = fs::read(path).expect("ar archive should be readable");
        assert_eq!(&bytes[..8], b"!<arch>\n");

        let mut members = std::collections::BTreeMap::new();
        let mut offset = 8;
        while offset < bytes.len() {
            let header = &bytes[offset..offset + 60];
            let name = std::str::from_utf8(&header[0..16])
                .expect("member name should be utf-8")
                .trim()
                .trim_end_matches('/')
                .to_string();
            let size = std::str::from_utf8(&header[48..58])
                .expect("member size should be utf-8")
                .trim()
                .parse::<usize>()
                .expect("member size should parse");
            let data_start = offset + 60;
            let data_end = data_start + size;
            members.insert(name, bytes[data_start..data_end].to_vec());
            offset = data_end + (size % 2);
        }

        members
    }

    fn read_tar_file(archive: &[u8], path: &str) -> String {
        let decoder = flate2::read::GzDecoder::new(archive);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().expect("tar entries should read") {
            let mut entry = entry.expect("tar entry should read");
            let entry_path = entry
                .path()
                .expect("tar path should read")
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string();
            if entry_path == path {
                let mut contents = String::new();
                entry
                    .read_to_string(&mut contents)
                    .expect("tar file should read");
                return contents;
            }
        }

        panic!("tar file was not found: {path}");
    }

    fn tar_contains(archive: &[u8], path: &str) -> bool {
        let decoder = flate2::read::GzDecoder::new(archive);
        let mut archive = tar::Archive::new(decoder);
        archive
            .entries()
            .expect("tar entries should read")
            .any(|entry| {
                entry
                    .expect("tar entry should read")
                    .path()
                    .expect("tar path should read")
                    .to_string_lossy()
                    .trim_start_matches("./")
                    == path
            })
    }

    fn msi_rows(installer: &mut msi::Package<File>, table: &str) -> Vec<Vec<Value>> {
        installer
            .select_rows(msi::Select::table(table))
            .expect("msi rows should select")
            .map(|row| (0..row.len()).map(|index| row[index].clone()).collect())
            .collect()
    }
}
