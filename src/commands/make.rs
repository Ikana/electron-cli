use std::{
    fs,
    fs::File,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use flate2::{write::GzEncoder, Compression};
use rpm::{BuildConfig, CompressionType, FileOptions, PackageBuilder};
use serde::Serialize;
use tar::{Builder as TarBuilder, Header as TarHeader};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::{
    cli::{MakeArgs, MakeTarget, PackageArgs},
    commands::package::{self, PackageReport},
    output,
};

#[derive(Debug, Serialize)]
pub(crate) struct MakeReport {
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
    report.mark_made()?;

    print_report(&report, args.json)
}

pub(crate) fn build_report(args: &MakeArgs) -> Result<MakeReport> {
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
    let artifact = make_artifact_path(&make_dir, &package, args.target);

    let mut warnings = package.warnings().to_vec();
    if matches!(args.target, MakeTarget::Deb | MakeTarget::Rpm) && package.platform() != "linux" {
        warnings.push(format!(
            "{} maker only supports linux packages; target platform is {}.",
            args.target.as_str(),
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

pub(crate) fn execute_make(report: &mut MakeReport, args: &MakeArgs) -> Result<()> {
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
    match args.target {
        MakeTarget::Zip => {
            write_zip_archive(Path::new(report.package.bundle_dir().as_str()), artifact)?
        }
        MakeTarget::Deb => write_deb_archive(&report.package, artifact)?,
        MakeTarget::Rpm => write_rpm_archive(&report.package, artifact)?,
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

    if !report.warnings.is_empty() {
        println!();
        println!("Warnings");
        for warning in &report.warnings {
            println!("  {warning}");
        }
    }

    Ok(())
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

fn write_deb_archive(package: &PackageReport, artifact: &Path) -> Result<()> {
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
    let data_tar = gzip_tar(|builder| append_deb_data_tar(builder, package, source, &deb_package))?;

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

fn write_rpm_archive(package: &PackageReport, artifact: &Path) -> Result<()> {
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

    builder.with_dir(source, format!("/opt/{rpm_package}"), |options| options)?;
    builder.with_symlink(FileOptions::symlink(
        format!("/usr/bin/{rpm_package}"),
        &executable,
    ))?;
    builder.with_file_contents(
        rpm_desktop_file(package, &rpm_package, &executable),
        FileOptions::new(format!("/usr/share/applications/{rpm_package}.desktop"))
            .permissions(0o644),
    )?;

    let rpm = builder.build()?;
    rpm.write_file(artifact)
        .with_context(|| format!("Could not write {}", artifact.display()))
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
        debian_desktop_file(package, deb_package, &executable).as_bytes(),
        0o644,
    )?;

    Ok(())
}

fn debian_desktop_file(package: &PackageReport, deb_package: &str, executable: &str) -> String {
    desktop_file(package, deb_package, executable)
}

fn rpm_desktop_file(package: &PackageReport, rpm_package: &str, executable: &str) -> String {
    desktop_file(package, rpm_package, executable)
}

fn desktop_file(package: &PackageReport, package_name: &str, executable: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Name={name}\n\
         Exec={executable} %U\n\
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
            target: crate::cli::MakeTarget::Deb,
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
            target: crate::cli::MakeTarget::Rpm,
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

    #[test]
    fn writes_deb_archive_with_control_and_data_members() {
        let root = unique_temp_dir("deb-archive");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: crate::cli::MakeTarget::Deb,
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");
        let bundle_dir = Path::new(report.package.bundle_dir().as_str());
        fs::create_dir_all(bundle_dir.join("resources/app"))
            .expect("fake bundle resources should be created");
        fs::write(bundle_dir.join("starter-app"), "").expect("fake binary should be written");
        fs::write(bundle_dir.join("resources/app/package.json"), "{}")
            .expect("fake app package should be written");

        write_deb_archive(&report.package, Path::new(report.artifact.as_str()))
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
        assert!(tar_contains(data, "usr/bin/starter-app"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writes_rpm_archive_with_metadata_and_payload_entries() {
        let root = unique_temp_dir("rpm-archive");
        write_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = MakeArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("linux".to_string()),
            arch: Some("x64".to_string()),
            target: crate::cli::MakeTarget::Rpm,
            skip_package: false,
            force: false,
            dry_run: true,
            json: true,
        };
        let report = build_report(&args).expect("report should build");
        let bundle_dir = Path::new(report.package.bundle_dir().as_str());
        fs::create_dir_all(bundle_dir.join("resources/app"))
            .expect("fake bundle resources should be created");
        fs::write(bundle_dir.join("starter-app"), "").expect("fake binary should be written");
        fs::write(bundle_dir.join("resources/app/package.json"), "{}")
            .expect("fake app package should be written");

        write_rpm_archive(&report.package, Path::new(report.artifact.as_str()))
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
        assert!(paths.contains(&"/usr/bin/starter-app".to_string()));

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
            target: crate::cli::MakeTarget::Deb,
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
            target: crate::cli::MakeTarget::Rpm,
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
}
