use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use plist::{Dictionary as PlistDictionary, Value as PlistValue};
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::{cli::PackageArgs, output, project::ProjectSnapshot};

#[derive(Debug, Serialize)]
pub(crate) struct PackageReport {
    project: ProjectSnapshot,
    app_name: String,
    executable_name: String,
    metadata: PackageMetadata,
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
struct PackageMetadata {
    bundle_identifier: String,
    app_version: Option<String>,
    build_version: Option<String>,
    app_category_type: Option<String>,
    app_copyright: Option<String>,
    icon: Option<IconResource>,
    extra_resources: Vec<CopyStep>,
    darwin_dark_mode_support: bool,
}

#[derive(Debug, Serialize)]
struct IconResource {
    from: Utf8PathBuf,
    to: Utf8PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PackageStatus {
    Planned,
    Packaged,
}

#[derive(Debug, Default)]
struct PackageJsonConfig {
    product_name: Option<String>,
    app_version: Option<String>,
    packager: PackagerConfig,
}

#[derive(Debug, Default)]
struct PackagerConfig {
    name: Option<String>,
    executable_name: Option<String>,
    app_bundle_id: Option<String>,
    app_category_type: Option<String>,
    app_version: Option<String>,
    build_version: Option<String>,
    app_copyright: Option<String>,
    icon: Vec<String>,
    extra_resource: Vec<String>,
    darwin_dark_mode_support: bool,
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
    let package_config = read_package_json_config(&snapshot)?;
    let platform = args.platform.clone().unwrap_or_else(current_platform);
    let arch = args.arch.clone().unwrap_or_else(current_arch);
    let app_name = clean_app_name(
        &args
            .name
            .clone()
            .or_else(|| package_config.packager.name.clone())
            .or_else(|| package_config.product_name.clone())
            .or_else(|| snapshot.name.clone())
            .unwrap_or_else(|| "electron-app".to_string()),
    );
    let executable_base = package_config
        .packager
        .executable_name
        .clone()
        .map(|name| clean_app_name(&name))
        .unwrap_or_else(|| app_name.clone());
    let executable_name = executable_name(&executable_base, &platform);
    let artifact_name = sanitize_artifact_name(&app_name);
    let output_dir = resolve_output_dir(root, &args.out_dir);
    let package_root = output_dir.join(format!("{artifact_name}-{platform}-{arch}"));
    let bundle_dir = bundle_dir(&package_root, &app_name, &platform);
    let app_resources_dir = app_resources_dir(&bundle_dir, &platform);
    let electron_dist = root.join("node_modules/electron/dist");
    let electron_source = electron_source(&electron_dist, &platform);
    let (metadata, metadata_warnings) = package_metadata(
        root,
        &package_config,
        &artifact_name,
        &app_resources_dir,
        &platform,
    )?;

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

    warnings.extend(runtime_dependency_warnings(root, &snapshot));
    warnings.extend(metadata_warnings);

    let create_dirs = vec![package_root.clone(), app_resources_dir.clone()];
    let mut copy_steps = vec![
        (electron_source, bundle_dir.clone()),
        (root.to_path_buf(), app_resources_dir.join("app")),
    ];
    if has_runtime_dependencies(&snapshot) {
        copy_steps.push((
            root.join("node_modules"),
            app_resources_dir.join("app/node_modules"),
        ));
    }
    if let Some(icon) = &metadata.icon {
        copy_steps.push((
            Path::new(icon.from.as_str()).to_path_buf(),
            Path::new(icon.to.as_str()).to_path_buf(),
        ));
    }
    for resource in &metadata.extra_resources {
        copy_steps.push((
            Path::new(resource.from.as_str()).to_path_buf(),
            Path::new(resource.to.as_str()).to_path_buf(),
        ));
    }

    Ok(PackageReport {
        project: snapshot,
        app_name,
        executable_name,
        metadata,
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
    apply_package_metadata(report)?;
    copy_package_resources(report)?;

    fs::create_dir_all(&app_dir)
        .with_context(|| format!("Could not create {}", app_dir.display()))?;
    copy_project_files(
        Path::new(report.project.root.as_str()),
        &app_dir,
        Path::new(report.output_dir.as_str()),
    )?;
    copy_runtime_dependencies(
        Path::new(report.project.root.as_str()),
        &app_dir,
        &report.project,
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
    println!("  bundle id: {}", report.metadata.bundle_identifier);
    if let Some(version) = &report.metadata.app_version {
        println!("  app version: {version}");
    }
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

fn read_package_json_config(snapshot: &ProjectSnapshot) -> Result<PackageJsonConfig> {
    let Some(package_json_path) = &snapshot.package_json else {
        return Ok(PackageJsonConfig::default());
    };

    let package_json_path = Path::new(package_json_path.as_str());
    let raw = fs::read_to_string(package_json_path)
        .with_context(|| format!("Could not read {}", package_json_path.display()))?;
    let package = serde_json::from_str::<JsonValue>(&raw)
        .with_context(|| format!("Could not parse {}", package_json_path.display()))?;

    let mut packager = PackagerConfig::default();
    if let Some(config) = package
        .get("config")
        .and_then(|config| config.get("forge"))
        .and_then(|forge| forge.get("packagerConfig"))
    {
        packager.merge(parse_packager_config(config));
    }
    if let Some(config) = package.get("electronPackagerConfig") {
        packager.merge(parse_packager_config(config));
    }
    if let Some(config) = package
        .get("electronCli")
        .or_else(|| package.get("electron-cli"))
        .and_then(|config| config.get("packagerConfig"))
    {
        packager.merge(parse_packager_config(config));
    }

    Ok(PackageJsonConfig {
        product_name: package
            .get("productName")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        app_version: package
            .get("version")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        packager,
    })
}

fn parse_packager_config(value: &JsonValue) -> PackagerConfig {
    PackagerConfig {
        name: string_value(value, "name"),
        executable_name: string_value(value, "executableName"),
        app_bundle_id: string_value(value, "appBundleId"),
        app_category_type: string_value(value, "appCategoryType"),
        app_version: string_value(value, "appVersion"),
        build_version: string_value(value, "buildVersion"),
        app_copyright: string_value(value, "appCopyright"),
        icon: string_list(value.get("icon")),
        extra_resource: string_list(value.get("extraResource")),
        darwin_dark_mode_support: value
            .get("darwinDarkModeSupport")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
    }
}

fn string_value(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned)
}

fn string_list(value: Option<&JsonValue>) -> Vec<String> {
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

fn package_metadata(
    root: &Path,
    config: &PackageJsonConfig,
    artifact_name: &str,
    app_resources_dir: &Path,
    platform: &str,
) -> Result<(PackageMetadata, Vec<String>)> {
    let mut warnings = Vec::new();
    let icon = resolve_icon_resource(
        root,
        &config.packager.icon,
        artifact_name,
        app_resources_dir,
        platform,
        &mut warnings,
    )?;
    let extra_resources = resolve_extra_resources(
        root,
        &config.packager.extra_resource,
        app_resources_dir,
        &mut warnings,
    )?;
    let app_version = config
        .packager
        .app_version
        .clone()
        .or_else(|| config.app_version.clone());

    Ok((
        PackageMetadata {
            bundle_identifier: config
                .packager
                .app_bundle_id
                .clone()
                .unwrap_or_else(|| default_bundle_identifier(artifact_name)),
            app_version: app_version.clone(),
            build_version: config
                .packager
                .build_version
                .clone()
                .or_else(|| app_version.clone()),
            app_category_type: config.packager.app_category_type.clone(),
            app_copyright: config.packager.app_copyright.clone(),
            icon,
            extra_resources,
            darwin_dark_mode_support: config.packager.darwin_dark_mode_support,
        },
        warnings,
    ))
}

fn resolve_icon_resource(
    root: &Path,
    configured_icons: &[String],
    artifact_name: &str,
    app_resources_dir: &Path,
    platform: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<IconResource>> {
    let candidates = configured_icons
        .iter()
        .filter_map(|icon| icon_candidate(root, icon, platform))
        .collect::<Vec<_>>();
    let source = if platform == "darwin" {
        candidates
            .iter()
            .find(|candidate| candidate.exists() && path_extension(candidate) == Some("icns"))
            .cloned()
            .or_else(|| {
                candidates
                    .iter()
                    .find(|candidate| candidate.exists())
                    .cloned()
            })
    } else {
        candidates
            .iter()
            .find(|candidate| candidate.exists())
            .cloned()
    };
    let Some(source) = source else {
        if let Some(first) = configured_icons.first() {
            let expected = icon_candidate(root, first, platform)
                .unwrap_or_else(|| resolve_project_path(root, first));
            warnings.push(format!(
                "Configured icon was not found for {platform}: {}.",
                expected.display()
            ));
        }
        return Ok(None);
    };

    if platform == "darwin" && path_extension(&source) == Some("icon") {
        warnings.push(
            "macOS .icon files are not applied yet; provide an .icns icon for now.".to_string(),
        );
        return Ok(None);
    }

    if platform == "win32" {
        warnings.push("Windows executable icon embedding is not implemented yet.".to_string());
        return Ok(None);
    }

    if platform == "linux" {
        warnings.push(
            "Linux executable icons are not embedded; set the BrowserWindow icon in app code."
                .to_string(),
        );
        return Ok(None);
    }

    let extension = path_extension(&source).unwrap_or("icns");
    let destination = app_resources_dir.join(format!("{artifact_name}.{extension}"));

    Ok(Some(IconResource {
        from: utf8_path(source)?,
        to: utf8_path(destination)?,
    }))
}

fn path_extension(path: &Path) -> Option<&str> {
    path.extension().and_then(|extension| extension.to_str())
}

fn icon_candidate(root: &Path, configured_icon: &str, platform: &str) -> Option<PathBuf> {
    if configured_icon.trim().is_empty() {
        return None;
    }

    let path = resolve_project_path(root, configured_icon);
    if path.extension().is_some() {
        return Some(path);
    }

    let extension = match platform {
        "darwin" => "icns",
        "win32" => "ico",
        "linux" => "png",
        _ => return Some(path),
    };
    Some(path.with_extension(extension))
}

fn resolve_extra_resources(
    root: &Path,
    extra_resources: &[String],
    app_resources_dir: &Path,
    warnings: &mut Vec<String>,
) -> Result<Vec<CopyStep>> {
    extra_resources
        .iter()
        .filter(|resource| !resource.trim().is_empty())
        .map(|resource| {
            let source = resolve_project_path(root, resource);
            if !source.exists() {
                warnings.push(format!(
                    "Configured extra resource does not exist and packaging will fail: {}.",
                    source.display()
                ));
            }

            let file_name = source
                .file_name()
                .with_context(|| format!("Extra resource has no file name: {}", source.display()))?
                .to_owned();
            Ok(CopyStep {
                from: utf8_path(source)?,
                to: utf8_path(app_resources_dir.join(file_name))?,
            })
        })
        .collect()
}

fn resolve_project_path(root: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn default_bundle_identifier(artifact_name: &str) -> String {
    let component = artifact_name
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() || char == '-' {
                char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim_matches(['.', '-'])
        .to_string();
    let component = if component.is_empty() {
        "electron-app".to_string()
    } else {
        component
    };
    format!("com.electron.{component}")
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

#[derive(Debug)]
struct DependencyRequest {
    name: String,
    requested_by: Option<PathBuf>,
    optional: bool,
}

fn copy_runtime_dependencies(
    root: &Path,
    app_dir: &Path,
    snapshot: &ProjectSnapshot,
) -> Result<()> {
    if !has_runtime_dependencies(snapshot) {
        return Ok(());
    }

    let root_node_modules = root.join("node_modules");
    let app_node_modules = app_dir.join("node_modules");
    let mut queue = VecDeque::new();
    let mut copied_paths = BTreeSet::new();

    for name in snapshot.dependencies.keys() {
        queue.push_back(DependencyRequest {
            name: name.clone(),
            requested_by: None,
            optional: false,
        });
    }

    for name in snapshot.optional_dependencies.keys() {
        queue.push_back(DependencyRequest {
            name: name.clone(),
            requested_by: None,
            optional: true,
        });
    }

    while let Some(request) = queue.pop_front() {
        let Some(package_dir) = resolve_dependency_dir(
            &root_node_modules,
            request.requested_by.as_deref(),
            &request.name,
        ) else {
            if request.optional {
                continue;
            }

            bail!(
                "Runtime dependency '{}' is not installed. Run your package manager install first.",
                request.name
            );
        };

        let canonical_package_dir = package_dir
            .canonicalize()
            .with_context(|| format!("Could not resolve {}", package_dir.display()))?;
        let canonical_root_node_modules = root_node_modules
            .canonicalize()
            .with_context(|| format!("Could not resolve {}", root_node_modules.display()))?;
        if !copied_paths.insert(canonical_package_dir.clone()) {
            continue;
        }

        let relative_path = canonical_package_dir
            .strip_prefix(&canonical_root_node_modules)
            .with_context(|| {
                format!(
                    "Could not make dependency {} relative to {}",
                    canonical_package_dir.display(),
                    canonical_root_node_modules.display()
                )
            })?;
        let destination = app_node_modules.join(relative_path);
        copy_recursively(&canonical_package_dir, &destination).with_context(|| {
            format!(
                "Could not copy runtime dependency {} to {}",
                canonical_package_dir.display(),
                destination.display()
            )
        })?;

        let package_json = read_dependency_package_json(&canonical_package_dir)?;
        for name in string_map(package_json.get("dependencies")).keys() {
            queue.push_back(DependencyRequest {
                name: name.clone(),
                requested_by: Some(canonical_package_dir.clone()),
                optional: false,
            });
        }
        for name in string_map(package_json.get("optionalDependencies")).keys() {
            queue.push_back(DependencyRequest {
                name: name.clone(),
                requested_by: Some(canonical_package_dir.clone()),
                optional: true,
            });
        }
    }

    Ok(())
}

fn apply_package_metadata(report: &PackageReport) -> Result<()> {
    if report.platform == "darwin" {
        apply_macos_metadata(report)?;
    }

    Ok(())
}

fn apply_macos_metadata(report: &PackageReport) -> Result<()> {
    let bundle_dir = Path::new(report.bundle_dir.as_str());
    let info_plist_path = bundle_dir.join("Contents/Info.plist");
    let mut dictionary = if info_plist_path.exists() {
        match PlistValue::from_file(&info_plist_path)
            .with_context(|| format!("Could not read {}", info_plist_path.display()))?
        {
            PlistValue::Dictionary(dictionary) => dictionary,
            _ => bail!("{} is not a plist dictionary", info_plist_path.display()),
        }
    } else {
        PlistDictionary::new()
    };

    set_plist_string(&mut dictionary, "CFBundleName", &report.app_name);
    set_plist_string(&mut dictionary, "CFBundleDisplayName", &report.app_name);
    set_plist_string(
        &mut dictionary,
        "CFBundleExecutable",
        &report.executable_name,
    );
    set_plist_string(
        &mut dictionary,
        "CFBundleIdentifier",
        &report.metadata.bundle_identifier,
    );

    if let Some(version) = &report.metadata.app_version {
        set_plist_string(&mut dictionary, "CFBundleShortVersionString", version);
    }
    if let Some(version) = &report.metadata.build_version {
        set_plist_string(&mut dictionary, "CFBundleVersion", version);
    }
    if let Some(category) = &report.metadata.app_category_type {
        set_plist_string(&mut dictionary, "LSApplicationCategoryType", category);
    }
    if let Some(copyright) = &report.metadata.app_copyright {
        set_plist_string(&mut dictionary, "NSHumanReadableCopyright", copyright);
    }
    if let Some(icon) = &report.metadata.icon {
        let icon_name = Path::new(icon.to.as_str())
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .context("Icon destination has no file name")?;
        set_plist_string(&mut dictionary, "CFBundleIconFile", icon_name);
    }
    if report.metadata.darwin_dark_mode_support {
        dictionary.insert(
            "NSRequiresAquaSystemAppearance".to_string(),
            PlistValue::Boolean(false),
        );
    }

    if let Some(parent) = info_plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    PlistValue::Dictionary(dictionary)
        .to_file_xml(&info_plist_path)
        .with_context(|| format!("Could not write {}", info_plist_path.display()))?;

    Ok(())
}

fn set_plist_string(dictionary: &mut PlistDictionary, key: &str, value: &str) {
    dictionary.insert(key.to_string(), PlistValue::String(value.to_string()));
}

fn copy_package_resources(report: &PackageReport) -> Result<()> {
    if let Some(icon) = &report.metadata.icon {
        copy_recursively(Path::new(icon.from.as_str()), Path::new(icon.to.as_str()))
            .with_context(|| format!("Could not copy icon to {}", icon.to))?;
    }

    for resource in &report.metadata.extra_resources {
        copy_recursively(
            Path::new(resource.from.as_str()),
            Path::new(resource.to.as_str()),
        )
        .with_context(|| format!("Could not copy extra resource to {}", resource.to))?;
    }

    Ok(())
}

fn runtime_dependency_warnings(root: &Path, snapshot: &ProjectSnapshot) -> Vec<String> {
    let mut warnings = Vec::new();
    let root_node_modules = root.join("node_modules");

    for name in snapshot.dependencies.keys() {
        if resolve_dependency_dir(&root_node_modules, None, name).is_none() {
            warnings.push(format!(
                "Runtime dependency is not installed and packaging will fail: {name}."
            ));
        }
    }

    for name in snapshot.optional_dependencies.keys() {
        if resolve_dependency_dir(&root_node_modules, None, name).is_none() {
            warnings.push(format!(
                "Optional runtime dependency is not installed and will be skipped: {name}."
            ));
        }
    }

    warnings
}

fn resolve_dependency_dir(
    root_node_modules: &Path,
    requested_by: Option<&Path>,
    name: &str,
) -> Option<PathBuf> {
    let relative_path = dependency_relative_path(name);

    if let Some(requested_by) = requested_by {
        let nested = requested_by.join("node_modules").join(&relative_path);
        if nested.exists() {
            return Some(nested);
        }
    }

    let hoisted = root_node_modules.join(relative_path);
    hoisted.exists().then_some(hoisted)
}

fn dependency_relative_path(name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in name.split('/') {
        if !part.is_empty() {
            path.push(part);
        }
    }
    path
}

fn read_dependency_package_json(package_dir: &Path) -> Result<JsonValue> {
    let package_json_path = package_dir.join("package.json");
    let raw = fs::read_to_string(&package_json_path)
        .with_context(|| format!("Could not read {}", package_json_path.display()))?;
    serde_json::from_str::<JsonValue>(&raw)
        .with_context(|| format!("Could not parse {}", package_json_path.display()))
}

fn string_map(value: Option<&JsonValue>) -> BTreeMap<String, String> {
    value
        .and_then(JsonValue::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
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
    let current = if platform == "darwin" {
        bundle_dir.join("Contents/MacOS/Electron")
    } else if platform == "win32" {
        bundle_dir.join("electron.exe")
    } else {
        bundle_dir.join("electron")
    };
    let target = if platform == "darwin" {
        bundle_dir.join("Contents/MacOS").join(executable_name)
    } else {
        bundle_dir.join(executable_name)
    };

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

impl PackagerConfig {
    fn merge(&mut self, other: PackagerConfig) {
        self.name = other.name.or_else(|| self.name.take());
        self.executable_name = other
            .executable_name
            .or_else(|| self.executable_name.take());
        self.app_bundle_id = other.app_bundle_id.or_else(|| self.app_bundle_id.take());
        self.app_category_type = other
            .app_category_type
            .or_else(|| self.app_category_type.take());
        self.app_version = other.app_version.or_else(|| self.app_version.take());
        self.build_version = other.build_version.or_else(|| self.build_version.take());
        self.app_copyright = other.app_copyright.or_else(|| self.app_copyright.take());
        if !other.icon.is_empty() {
            self.icon = other.icon;
        }
        if !other.extra_resource.is_empty() {
            self.extra_resource = other.extra_resource;
        }
        self.darwin_dark_mode_support =
            other.darwin_dark_mode_support || self.darwin_dark_mode_support;
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
    fn packages_runtime_dependency_closure_from_node_modules() {
        let root = unique_temp_dir("runtime-deps");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","dependencies":{"dep-a":"1.0.0"},"devDependencies":{"electron":"30.0.0","dev-only":"1.0.0"}}"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);
        write_dependency_package(
            &root,
            "dep-a",
            r#"{"name":"dep-a","version":"1.0.0","dependencies":{"dep-b":"1.0.0"}}"#,
        );
        write_dependency_package(&root, "dep-b", r#"{"name":"dep-b","version":"1.0.0"}"#);
        write_dependency_package(
            &root,
            "dev-only",
            r#"{"name":"dev-only","version":"1.0.0"}"#,
        );

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

        assert!(report.warnings.is_empty());
        execute_package(&report, false).expect("package should succeed");

        let app_node_modules = Path::new(report.app_resources_dir.as_str())
            .join("app")
            .join("node_modules");
        assert!(app_node_modules.join("dep-a/package.json").exists());
        assert!(app_node_modules.join("dep-b/package.json").exists());
        assert!(!app_node_modules.join("dev-only").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plans_packager_metadata_from_package_json() {
        let root = unique_temp_dir("metadata-plan");
        write_metadata_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);
        write_icon_and_resource_files(&root);

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

        assert_eq!(report.app_name, "Starter Pro");
        assert_eq!(
            report.executable_name,
            executable_name("StarterExec", &report.platform)
        );
        assert_eq!(report.metadata.bundle_identifier, "com.example.starter");
        assert_eq!(report.metadata.app_version.as_deref(), Some("2.3.4"));
        assert_eq!(report.metadata.build_version.as_deref(), Some("234"));
        assert_eq!(
            report.metadata.app_category_type.as_deref(),
            Some("public.app-category.developer-tools")
        );
        assert_eq!(
            report.metadata.app_copyright.as_deref(),
            Some("Copyright 2026 Example")
        );
        assert_eq!(report.metadata.extra_resources.len(), 1);
        assert!(report
            .copy_steps
            .iter()
            .any(|step| step.to.as_str().ends_with("config.json")));

        if current_platform() == "darwin" {
            assert!(report.metadata.icon.is_some());
            assert!(report.warnings.is_empty());
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn packages_macos_info_plist_metadata() {
        if current_platform() != "darwin" {
            return;
        }

        let root = unique_temp_dir("metadata-execute");
        write_metadata_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);
        write_icon_and_resource_files(&root);

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

        execute_package(&report, false).expect("package should succeed");

        let bundle_dir = Path::new(report.bundle_dir.as_str());
        assert!(bundle_dir
            .join("Contents/MacOS")
            .join(&report.executable_name)
            .exists());
        assert!(bundle_dir
            .join("Contents/Resources/starter-pro.icns")
            .exists());
        assert!(bundle_dir.join("Contents/Resources/config.json").exists());

        let plist = PlistValue::from_file(bundle_dir.join("Contents/Info.plist"))
            .expect("Info.plist should parse");
        let dictionary = plist
            .as_dictionary()
            .expect("Info.plist should be a dictionary");

        assert_eq!(
            plist_string(dictionary, "CFBundleDisplayName"),
            Some("Starter Pro")
        );
        assert_eq!(
            plist_string(dictionary, "CFBundleExecutable"),
            Some(report.executable_name.as_str())
        );
        assert_eq!(
            plist_string(dictionary, "CFBundleIdentifier"),
            Some("com.example.starter")
        );
        assert_eq!(
            plist_string(dictionary, "CFBundleShortVersionString"),
            Some("2.3.4")
        );
        assert_eq!(plist_string(dictionary, "CFBundleVersion"), Some("234"));
        assert_eq!(
            plist_string(dictionary, "LSApplicationCategoryType"),
            Some("public.app-category.developer-tools")
        );
        assert_eq!(
            plist_string(dictionary, "CFBundleIconFile"),
            Some("starter-pro.icns")
        );
        assert_eq!(
            dictionary
                .get("NSRequiresAquaSystemAppearance")
                .and_then(PlistValue::as_boolean),
            Some(false)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_required_runtime_dependency_fails() {
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

        assert!(report.warnings.contains(
            &"Runtime dependency is not installed and packaging will fail: left-pad.".to_string()
        ));
        assert!(execute_package(&report, false).is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_optional_runtime_dependency_is_skipped() {
        let root = unique_temp_dir("optional-runtime-deps");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","optionalDependencies":{"optional-native":"1.0.0"},"devDependencies":{"electron":"30.0.0"}}"#,
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

        assert!(report.warnings.contains(
            &"Optional runtime dependency is not installed and will be skipped: optional-native."
                .to_string()
        ));
        execute_package(&report, false).expect("optional dependency should be skipped");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cleans_scoped_package_names_for_bundle_paths() {
        assert_eq!(clean_app_name("@scope/app"), "scope-app");
        assert_eq!(sanitize_artifact_name("Starter App"), "starter-app");
        assert_eq!(
            dependency_relative_path("@scope/app"),
            PathBuf::from("@scope/app")
        );
    }

    fn write_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
    }

    fn write_metadata_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{
                "name": "starter-app",
                "productName": "Starter Pro",
                "version": "2.3.4",
                "main": "src/main.js",
                "devDependencies": {
                    "electron": "30.0.0"
                },
                "electronCli": {
                    "packagerConfig": {
                        "executableName": "StarterExec",
                        "appBundleId": "com.example.starter",
                        "appCategoryType": "public.app-category.developer-tools",
                        "buildVersion": "234",
                        "appCopyright": "Copyright 2026 Example",
                        "icon": "assets/starter",
                        "extraResource": "assets/config.json",
                        "darwinDarkModeSupport": true
                    }
                }
            }"#,
        )
        .expect("package.json should be written");
    }

    fn write_app_file(root: &Path) {
        fs::create_dir_all(root.join("src")).expect("src should be created");
        fs::write(root.join("src/main.js"), "console.log('hello');")
            .expect("main file should be written");
    }

    fn write_dependency_package(root: &Path, name: &str, package_json: &str) {
        let package_dir = root
            .join("node_modules")
            .join(dependency_relative_path(name));
        fs::create_dir_all(&package_dir).expect("dependency package dir should be created");
        fs::write(package_dir.join("package.json"), package_json)
            .expect("dependency package.json should be written");
        fs::write(package_dir.join("index.js"), "module.exports = true;")
            .expect("dependency index should be written");
    }

    fn write_icon_and_resource_files(root: &Path) {
        fs::create_dir_all(root.join("assets")).expect("assets should be created");
        fs::write(root.join("assets/starter.icns"), b"icns").expect("icon should be written");
        fs::write(root.join("assets/config.json"), "{}").expect("resource should be written");
    }

    fn plist_string<'a>(dictionary: &'a PlistDictionary, key: &str) -> Option<&'a str> {
        dictionary.get(key).and_then(PlistValue::as_string)
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
