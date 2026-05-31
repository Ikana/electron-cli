use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    fs::File,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use app_store_connect::UnifiedApiKey;
use apple_codesign::{
    cryptography::{parse_pfx_data, PrivateKey},
    stapling::Stapler,
    BundleSigner, CodeSignatureFlags, NotarizationUpload, Notarizer, SettingsScope,
    SigningSettings,
};
use camino::Utf8PathBuf;
use plist::{Dictionary as PlistDictionary, Value as PlistValue};
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::{cli::PackageArgs, output, project::ProjectSnapshot};

const APPLE_TIMESTAMP_URL: &str = "http://timestamp.apple.com/ts01";
const MACOS_NOTARIZATION_WAIT_TIMEOUT_SECONDS: u64 = 600;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PackageReport {
    project: ProjectSnapshot,
    app_name: String,
    executable_name: String,
    metadata: PackageMetadata,
    asar: AsarPlan,
    signing: PackageSigningPlan,
    platform: String,
    arch: String,
    electron_dist: Utf8PathBuf,
    output_dir: Utf8PathBuf,
    bundle_dir: Utf8PathBuf,
    app_resources_dir: Utf8PathBuf,
    ignore_patterns: Vec<String>,
    dry_run: bool,
    status: PackageStatus,
    create_dirs: Vec<Utf8PathBuf>,
    copy_steps: Vec<CopyStep>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CopyStep {
    from: Utf8PathBuf,
    to: Utf8PathBuf,
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
struct IconResource {
    from: Utf8PathBuf,
    to: Utf8PathBuf,
}

#[derive(Clone, Debug, Serialize)]
struct AsarPlan {
    configured: bool,
    enabled: bool,
    archive: Option<Utf8PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
struct PackageSigningPlan {
    macos: MacosSigningPlan,
}

#[derive(Clone, Debug, Serialize)]
struct MacosSigningPlan {
    sign: MacosSignPlan,
    notarize: MacosNotarizePlan,
}

#[derive(Clone, Debug, Serialize)]
struct MacosSignPlan {
    configured: bool,
    enabled: bool,
    will_execute: bool,
    method: Option<String>,
    identity: Option<String>,
    p12_file: Option<Utf8PathBuf>,
    p12_password_source: Option<String>,
    p12_password_env: Option<String>,
    p12_password_file: Option<Utf8PathBuf>,
    #[serde(skip)]
    p12_password: RedactedSecret,
    timestamp_url: Option<String>,
    for_notarization: bool,
    entitlements: Vec<Utf8PathBuf>,
    entitlements_inherit: Option<Utf8PathBuf>,
    hardened_runtime: Option<bool>,
    gatekeeper_assess: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
struct MacosNotarizePlan {
    configured: bool,
    enabled: bool,
    will_execute: bool,
    auth_method: Option<String>,
    apple_api_key: Option<Utf8PathBuf>,
    #[serde(skip)]
    apple_api_key_id: RedactedSecret,
    #[serde(skip)]
    apple_api_issuer: RedactedSecret,
    keychain_profile: Option<String>,
    keychain: Option<String>,
    wait: bool,
    wait_timeout_seconds: u64,
    staple: bool,
}

#[derive(Clone, Default)]
struct RedactedSecret(Option<String>);

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_some() {
            formatter.write_str("<redacted>")
        } else {
            formatter.write_str("<unset>")
        }
    }
}

impl RedactedSecret {
    fn new(value: Option<String>) -> Self {
        Self(value)
    }

    fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
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
    warnings: Vec<String>,
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
    ignore: Vec<String>,
    asar: AsarConfig,
    darwin_dark_mode_support: bool,
    osx_sign: MacosSignConfig,
    osx_notarize: MacosNotarizeConfig,
}

#[derive(Clone, Debug, Default)]
struct AsarConfig {
    configured: bool,
    enabled: bool,
    invalid_type: bool,
    unsupported_options: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct MacosSignConfig {
    configured: bool,
    enabled: bool,
    invalid_type: bool,
    identity: Option<String>,
    p12_file: Option<String>,
    p12_password: Option<String>,
    p12_password_env: Option<String>,
    p12_password_file: Option<String>,
    timestamp: Option<MacosTimestampConfig>,
    entitlements: Vec<String>,
    entitlements_inherit: Option<String>,
    hardened_runtime: Option<bool>,
    gatekeeper_assess: Option<bool>,
}

#[derive(Clone, Debug)]
enum MacosTimestampConfig {
    Default,
    Disabled,
    Url(String),
}

#[derive(Clone, Debug, Default)]
struct MacosNotarizeConfig {
    configured: bool,
    enabled: bool,
    invalid_type: bool,
    apple_id_set: bool,
    apple_id_password_set: bool,
    team_id_set: bool,
    apple_api_key: Option<String>,
    apple_api_key_id: Option<String>,
    apple_api_issuer: Option<String>,
    keychain_profile: Option<String>,
    keychain: Option<String>,
    wait: Option<bool>,
    wait_timeout_seconds: Option<u64>,
    staple: Option<bool>,
}

struct IgnoreRule(Regex);

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
    let (asar, asar_warnings) = package_asar(&app_resources_dir, &package_config)?;
    let (signing, signing_warnings) = package_signing(root, &package_config, &platform)?;

    let mut warnings = package_config.warnings.clone();
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
    warnings.extend(asar_warnings);
    warnings.extend(signing_warnings);
    let _ = compile_ignore_rules(&package_config.packager.ignore, Some(&mut warnings));

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
        asar,
        signing,
        platform,
        arch,
        electron_dist: utf8_path(electron_dist)?,
        output_dir: utf8_path(output_dir)?,
        bundle_dir: utf8_path(bundle_dir)?,
        app_resources_dir: utf8_path(app_resources_dir)?,
        ignore_patterns: package_config.packager.ignore,
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
    let ignore_rules = compile_ignore_rules(&report.ignore_patterns, None);

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
        Path::new(report.project.root.as_str()),
        &ignore_rules,
    )?;
    copy_runtime_dependencies(
        Path::new(report.project.root.as_str()),
        &app_dir,
        &report.project,
        &ignore_rules,
    )?;
    execute_asar_packaging(report)?;
    execute_macos_signing(report)?;
    execute_macos_notarization(report)?;

    Ok(())
}

fn execute_macos_signing(report: &PackageReport) -> Result<()> {
    if report.platform != "darwin" || !report.signing.macos.sign.will_execute {
        return Ok(());
    }

    let bundle_dir = Path::new(report.bundle_dir.as_str());
    let bundle_parent = bundle_dir
        .parent()
        .context("macOS bundle output has no parent directory")?;
    let bundle_name = bundle_dir
        .file_name()
        .context("macOS bundle output has no bundle directory name")?;
    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let signing_parent = bundle_parent.join(format!(
        ".electron-cli-signing-{}-{unique_suffix}",
        std::process::id()
    ));
    let signed_bundle_dir = signing_parent.join(bundle_name);

    if signing_parent.exists() {
        fs::remove_dir_all(&signing_parent)
            .with_context(|| format!("Could not remove {}", signing_parent.display()))?;
    }

    let signing_result = (|| -> Result<()> {
        let mut signer = BundleSigner::new_from_path(bundle_dir).with_context(|| {
            format!(
                "Could not prepare macOS bundle signing for {}",
                bundle_dir.display()
            )
        })?;
        signer
            .collect_nested_bundles()
            .context("Could not discover nested macOS bundles for signing")?;

        let mut settings = macos_signing_settings(report)?;
        if let Some(p12_file) = &report.signing.macos.sign.p12_file {
            let p12_path = Path::new(p12_file.as_str());
            let p12_data = fs::read(p12_path)
                .with_context(|| format!("Could not read {}", p12_path.display()))?;
            let password = macos_p12_password(&report.signing.macos.sign)?;
            let (certificate, signing_key) = parse_pfx_data(&p12_data, &password)
                .with_context(|| format!("Could not parse {}", p12_path.display()))?;

            settings.set_signing_key(signing_key.as_key_info_signer(), certificate);
            settings.chain_apple_certificates();
            settings.set_team_id_from_signing_certificate();
            settings
                .ensure_for_notarization_settings()
                .context("macOS signing settings are not compatible with notarization")?;
            signer
                .write_signed_bundle(&signed_bundle_dir, &settings)
                .with_context(|| {
                    format!(
                        "Could not write signed macOS bundle to {}",
                        signed_bundle_dir.display()
                    )
                })?;
        } else {
            signer
                .write_signed_bundle(&signed_bundle_dir, &settings)
                .with_context(|| {
                    format!(
                        "Could not write signed macOS bundle to {}",
                        signed_bundle_dir.display()
                    )
                })?;
        }

        Ok(())
    })();

    if let Err(error) = signing_result {
        let _ = fs::remove_dir_all(&signing_parent);
        return Err(error);
    }

    fs::remove_dir_all(bundle_dir)
        .with_context(|| format!("Could not remove {}", bundle_dir.display()))?;
    fs::rename(&signed_bundle_dir, bundle_dir).with_context(|| {
        format!(
            "Could not move signed macOS bundle from {} to {}",
            signed_bundle_dir.display(),
            bundle_dir.display()
        )
    })?;
    let _ = fs::remove_dir_all(&signing_parent);

    Ok(())
}

fn execute_macos_notarization(report: &PackageReport) -> Result<()> {
    if report.platform != "darwin" || !report.signing.macos.notarize.will_execute {
        return Ok(());
    }

    let notarize = &report.signing.macos.notarize;
    let bundle_dir = Path::new(report.bundle_dir.as_str());
    let wait_limit = notarize.wait.then_some(std::time::Duration::from_secs(
        notarize.wait_timeout_seconds,
    ));
    let notarizer = macos_notarizer(notarize)?;
    let upload = notarizer
        .notarize_path(bundle_dir, wait_limit)
        .with_context(|| format!("Could not notarize macOS bundle {}", bundle_dir.display()))?;

    if notarize.staple {
        match upload {
            NotarizationUpload::NotaryResponse(_) => {
                let stapler =
                    Stapler::new().context("Could not prepare macOS notarization stapler")?;
                stapler.staple_path(bundle_dir).with_context(|| {
                    format!(
                        "Could not staple notarization ticket to {}",
                        bundle_dir.display()
                    )
                })?;
            }
            NotarizationUpload::UploadId(upload_id) => {
                bail!(
                    "macOS notarization upload {upload_id} was submitted without waiting; stapling requires a completed notarization result."
                );
            }
        }
    }

    Ok(())
}

fn macos_notarizer(notarize: &MacosNotarizePlan) -> Result<Notarizer> {
    let api_key_path = notarize
        .apple_api_key
        .as_ref()
        .context("macOS notarization requires appleApiKey")?;
    let api_key_path = Path::new(api_key_path.as_str());
    let key_id = notarize
        .apple_api_key_id
        .as_deref()
        .context("macOS notarization requires appleApiKeyId")?;
    let issuer = notarize
        .apple_api_issuer
        .as_deref()
        .context("macOS notarization requires appleApiIssuer")?;

    if path_extension(api_key_path) == Some("json") {
        return Notarizer::from_api_key(api_key_path)
            .with_context(|| format!("Could not load Apple API key {}", api_key_path.display()));
    }

    let temp_api_key = temporary_unified_api_key(issuer, key_id, api_key_path)?;
    Notarizer::from_api_key(&temp_api_key.path)
        .with_context(|| format!("Could not load Apple API key {}", api_key_path.display()))
}

struct TemporaryFile {
    path: PathBuf,
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn temporary_unified_api_key(
    issuer: &str,
    key_id: &str,
    private_key_path: &Path,
) -> Result<TemporaryFile> {
    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "electron-cli-notary-key-{}-{unique_suffix}.json",
        std::process::id()
    ));
    let unified = UnifiedApiKey::from_ecdsa_pem_path(issuer, key_id, private_key_path)
        .with_context(|| {
            format!(
                "Could not read Apple API private key {}",
                private_key_path.display()
            )
        })?;
    unified
        .write_json_file(&path)
        .with_context(|| format!("Could not write temporary Apple API key {}", path.display()))?;

    Ok(TemporaryFile { path })
}

fn macos_signing_settings<'key>(report: &PackageReport) -> Result<SigningSettings<'key>> {
    let sign = &report.signing.macos.sign;
    let mut settings = SigningSettings::default();
    settings.set_binary_identifier(SettingsScope::Main, &report.metadata.bundle_identifier);
    settings.set_for_notarization(sign.for_notarization);

    if let Some(timestamp_url) = &sign.timestamp_url {
        settings
            .set_time_stamp_url(timestamp_url)
            .with_context(|| format!("Invalid macOS signing timestamp URL: {timestamp_url}"))?;
    }

    if sign.hardened_runtime.unwrap_or(false) {
        settings.add_code_signature_flags(SettingsScope::Main, CodeSignatureFlags::RUNTIME);
    }

    if let Some(entitlements) = sign.entitlements.first() {
        let entitlements_path = Path::new(entitlements.as_str());
        let entitlements_xml = fs::read_to_string(entitlements_path).with_context(|| {
            format!(
                "Could not read macOS entitlements file {}",
                entitlements_path.display()
            )
        })?;
        settings
            .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
            .with_context(|| {
                format!(
                    "Could not parse macOS entitlements file {}",
                    entitlements_path.display()
                )
            })?;
    }

    Ok(settings)
}

fn macos_p12_password(sign: &MacosSignPlan) -> Result<String> {
    if let Some(password) = sign.p12_password.as_deref() {
        return Ok(password.to_string());
    }

    if let Some(env_name) = &sign.p12_password_env {
        return std::env::var(env_name)
            .with_context(|| format!("Could not read macOS signing p12 password env {env_name}"));
    }

    if let Some(path) = &sign.p12_password_file {
        let password_path = Path::new(path.as_str());
        return fs::read_to_string(password_path)
            .with_context(|| {
                format!(
                    "Could not read macOS signing p12 password file {}",
                    password_path.display()
                )
            })
            .and_then(|contents| {
                contents
                    .lines()
                    .next()
                    .map(str::to_string)
                    .context("macOS signing p12 password file is empty")
            });
    }

    Ok(String::new())
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

    if report.signing.macos.sign.configured || report.signing.macos.notarize.configured {
        println!();
        println!("Signing");
        println!(
            "  macOS signing: {}",
            if report.signing.macos.sign.enabled {
                "configured"
            } else {
                "disabled"
            }
        );
        if let Some(identity) = &report.signing.macos.sign.identity {
            println!("  identity: {identity}");
        }
        if let Some(path) = &report.signing.macos.sign.p12_file {
            println!("  p12 file: {path}");
        }
        if let Some(source) = &report.signing.macos.sign.p12_password_source {
            println!("  p12 password: {source}");
        }
        if let Some(timestamp_url) = &report.signing.macos.sign.timestamp_url {
            println!("  timestamp server: {timestamp_url}");
        }
        if report.signing.macos.sign.for_notarization {
            println!("  signing mode: notarization-compatible");
        }
        if let Some(method) = &report.signing.macos.sign.method {
            println!("  signing method: {method}");
        }
        println!(
            "  signing execution: {}",
            if report.signing.macos.sign.will_execute {
                "enabled"
            } else {
                "not available"
            }
        );
        println!(
            "  macOS notarization: {}",
            if report.signing.macos.notarize.enabled {
                "configured"
            } else {
                "disabled"
            }
        );
        if let Some(method) = &report.signing.macos.notarize.auth_method {
            println!("  notarization auth: {method}");
        }
        if let Some(path) = &report.signing.macos.notarize.apple_api_key {
            println!("  Apple API key: {path}");
        }
        println!(
            "  notarization execution: {}",
            if report.signing.macos.notarize.will_execute {
                "enabled"
            } else {
                "not available"
            }
        );
        if report.signing.macos.notarize.will_execute {
            println!(
                "  notarization wait: {}",
                if report.signing.macos.notarize.wait {
                    format!("{}s", report.signing.macos.notarize.wait_timeout_seconds)
                } else {
                    "disabled".to_string()
                }
            );
            println!(
                "  notarization stapling: {}",
                if report.signing.macos.notarize.staple {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
    }

    if report.asar.configured || report.asar.enabled {
        println!();
        println!("ASAR");
        println!(
            "  enabled: {}",
            if report.asar.enabled { "yes" } else { "no" }
        );
        if let Some(archive) = &report.asar.archive {
            println!("  archive: {archive}");
        }
    }

    println!();
    println!("Output");
    println!("  {}", report.bundle_dir);

    println!();
    println!("Copy");
    for step in &report.copy_steps {
        println!("  {} -> {}", step.from, step.to);
    }
    if !report.ignore_patterns.is_empty() {
        println!();
        println!("Ignore");
        for pattern in &report.ignore_patterns {
            println!("  {pattern}");
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

fn read_package_json_config(snapshot: &ProjectSnapshot) -> Result<PackageJsonConfig> {
    let project_config = crate::forge_config::read(snapshot)?;

    let mut packager = PackagerConfig::default();
    if let Some(config) = project_config
        .forge()
        .and_then(|forge| forge.get("packagerConfig"))
    {
        packager.merge(parse_packager_config(config));
    }
    if let Some(config) = project_config
        .package()
        .and_then(|package| package.get("electronPackagerConfig"))
    {
        packager.merge(parse_packager_config(config));
    }
    if let Some(config) = project_config
        .electron_cli()
        .and_then(|config| config.get("packagerConfig"))
    {
        packager.merge(parse_packager_config(config));
    }

    Ok(PackageJsonConfig {
        product_name: project_config
            .package()
            .and_then(|package| package.get("productName"))
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        app_version: project_config
            .package()
            .and_then(|package| package.get("version"))
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        warnings: project_config.warnings().to_vec(),
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
        ignore: string_list(value.get("ignore")),
        asar: parse_asar_config(value.get("asar")),
        darwin_dark_mode_support: value
            .get("darwinDarkModeSupport")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
        osx_sign: parse_macos_sign_config(value.get("osxSign")),
        osx_notarize: parse_macos_notarize_config(value.get("osxNotarize")),
    }
}

fn parse_asar_config(value: Option<&JsonValue>) -> AsarConfig {
    match value {
        None => AsarConfig::default(),
        Some(JsonValue::Bool(false)) => AsarConfig {
            configured: true,
            enabled: false,
            ..AsarConfig::default()
        },
        Some(JsonValue::Bool(true)) => AsarConfig {
            configured: true,
            enabled: true,
            ..AsarConfig::default()
        },
        Some(JsonValue::Object(object)) => AsarConfig {
            configured: true,
            enabled: true,
            invalid_type: false,
            unsupported_options: object.keys().cloned().collect(),
        },
        Some(_) => AsarConfig {
            configured: true,
            invalid_type: true,
            ..AsarConfig::default()
        },
    }
}

fn compile_ignore_rules(
    patterns: &[String],
    mut warnings: Option<&mut Vec<String>>,
) -> Vec<IgnoreRule> {
    let mut rules = Vec::new();

    for pattern in patterns {
        match compile_ignore_pattern(pattern) {
            Ok(regex) => rules.push(IgnoreRule(regex)),
            Err(error) => {
                if let Some(warnings) = warnings.as_deref_mut() {
                    warnings.push(format!(
                        "Configured packager ignore pattern is not a valid regex and will be skipped: {pattern}: {error}."
                    ));
                }
            }
        }
    }

    rules
}

fn compile_ignore_pattern(pattern: &str) -> Result<Regex> {
    if let Some((body, flags)) = parse_js_regex_literal(pattern) {
        let mut builder = RegexBuilder::new(body);
        for flag in flags.chars() {
            match flag {
                'i' => {
                    builder.case_insensitive(true);
                }
                'm' => {
                    builder.multi_line(true);
                }
                's' => {
                    builder.dot_matches_new_line(true);
                }
                'u' | 'g' | 'y' | 'd' => {}
                _ => bail!("unsupported JavaScript regex flag '{flag}'"),
            }
        }
        return builder
            .build()
            .context("could not compile JavaScript-style regex literal");
    }

    Regex::new(pattern).context("could not compile regex")
}

fn parse_js_regex_literal(pattern: &str) -> Option<(&str, &str)> {
    if !pattern.starts_with('/') {
        return None;
    }

    let mut escaped = false;
    let mut last_slash = None;
    for (index, char) in pattern.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if char == '\\' {
            escaped = true;
            continue;
        }
        if char == '/' {
            last_slash = Some(index);
        }
    }

    let slash = last_slash?;
    let flags = &pattern[slash + 1..];
    if !flags
        .chars()
        .all(|flag| matches!(flag, 'd' | 'g' | 'i' | 'm' | 's' | 'u' | 'y'))
    {
        return None;
    }

    Some((&pattern[1..slash], flags))
}

fn parse_macos_sign_config(value: Option<&JsonValue>) -> MacosSignConfig {
    match value {
        None => MacosSignConfig::default(),
        Some(JsonValue::Bool(false)) => MacosSignConfig {
            configured: true,
            enabled: false,
            ..MacosSignConfig::default()
        },
        Some(JsonValue::Bool(true)) => MacosSignConfig {
            configured: true,
            enabled: true,
            ..MacosSignConfig::default()
        },
        Some(JsonValue::Object(object)) => {
            let entitlements = [
                "entitlements",
                "entitlementsInherit",
                "entitlementsLoginHelper",
            ]
            .iter()
            .filter_map(|key| {
                object
                    .get(*key)
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect();

            MacosSignConfig {
                configured: true,
                enabled: true,
                invalid_type: false,
                identity: object
                    .get("identity")
                    .or_else(|| object.get("identityName"))
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned),
                p12_file: object
                    .get("p12File")
                    .or_else(|| object.get("pfxFile"))
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned),
                p12_password: object
                    .get("p12Password")
                    .or_else(|| object.get("pfxPassword"))
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned),
                p12_password_env: object
                    .get("p12PasswordEnv")
                    .or_else(|| object.get("pfxPasswordEnv"))
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned),
                p12_password_file: object
                    .get("p12PasswordFile")
                    .or_else(|| object.get("pfxPasswordFile"))
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned),
                timestamp: parse_macos_timestamp_config(
                    object
                        .get("timestamp")
                        .or_else(|| object.get("timestampUrl"))
                        .or_else(|| object.get("timestampURL")),
                ),
                entitlements,
                entitlements_inherit: object
                    .get("entitlementsInherit")
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned),
                hardened_runtime: object.get("hardenedRuntime").and_then(JsonValue::as_bool),
                gatekeeper_assess: object.get("gatekeeperAssess").and_then(JsonValue::as_bool),
            }
        }
        Some(_) => MacosSignConfig {
            configured: true,
            invalid_type: true,
            ..MacosSignConfig::default()
        },
    }
}

fn parse_macos_timestamp_config(value: Option<&JsonValue>) -> Option<MacosTimestampConfig> {
    match value {
        Some(JsonValue::String(value)) => {
            let value = value.trim();
            if value.is_empty() || value.eq_ignore_ascii_case("none") {
                Some(MacosTimestampConfig::Disabled)
            } else {
                Some(MacosTimestampConfig::Url(value.to_string()))
            }
        }
        Some(JsonValue::Bool(true)) => Some(MacosTimestampConfig::Default),
        Some(JsonValue::Bool(false)) => Some(MacosTimestampConfig::Disabled),
        _ => None,
    }
}

fn parse_macos_notarize_config(value: Option<&JsonValue>) -> MacosNotarizeConfig {
    match value {
        None => MacosNotarizeConfig::default(),
        Some(JsonValue::Bool(false)) => MacosNotarizeConfig {
            configured: true,
            enabled: false,
            ..MacosNotarizeConfig::default()
        },
        Some(JsonValue::Bool(true)) => MacosNotarizeConfig {
            configured: true,
            enabled: true,
            ..MacosNotarizeConfig::default()
        },
        Some(JsonValue::Object(object)) => MacosNotarizeConfig {
            configured: true,
            enabled: true,
            invalid_type: false,
            apple_id_set: object.get("appleId").and_then(JsonValue::as_str).is_some(),
            apple_id_password_set: object
                .get("appleIdPassword")
                .and_then(JsonValue::as_str)
                .is_some(),
            team_id_set: object.get("teamId").and_then(JsonValue::as_str).is_some(),
            apple_api_key: object
                .get("appleApiKey")
                .and_then(JsonValue::as_str)
                .map(ToOwned::to_owned),
            apple_api_key_id: object
                .get("appleApiKeyId")
                .and_then(JsonValue::as_str)
                .map(ToOwned::to_owned),
            apple_api_issuer: object
                .get("appleApiIssuer")
                .and_then(JsonValue::as_str)
                .map(ToOwned::to_owned),
            keychain_profile: object
                .get("keychainProfile")
                .and_then(JsonValue::as_str)
                .map(ToOwned::to_owned),
            keychain: object
                .get("keychain")
                .and_then(JsonValue::as_str)
                .map(ToOwned::to_owned),
            wait: object.get("wait").and_then(JsonValue::as_bool),
            wait_timeout_seconds: object
                .get("maxWaitSeconds")
                .or_else(|| object.get("waitTimeoutSeconds"))
                .and_then(JsonValue::as_u64),
            staple: object.get("staple").and_then(JsonValue::as_bool),
        },
        Some(_) => MacosNotarizeConfig {
            configured: true,
            invalid_type: true,
            ..MacosNotarizeConfig::default()
        },
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

fn package_asar(
    app_resources_dir: &Path,
    config: &PackageJsonConfig,
) -> Result<(AsarPlan, Vec<String>)> {
    let mut warnings = Vec::new();
    let config = &config.packager.asar;

    if config.invalid_type {
        warnings.push("packagerConfig.asar must be false, true, or an object.".to_string());
    }

    if config.enabled && !config.unsupported_options.is_empty() {
        warnings.push(format!(
            "packagerConfig.asar options are recognized but not implemented yet and will be ignored: {}.",
            config.unsupported_options.join(", ")
        ));
    }

    Ok((
        AsarPlan {
            configured: config.configured,
            enabled: config.enabled,
            archive: config
                .enabled
                .then(|| utf8_path(app_resources_dir.join("app.asar")))
                .transpose()?,
        },
        warnings,
    ))
}

fn package_signing(
    root: &Path,
    config: &PackageJsonConfig,
    platform: &str,
) -> Result<(PackageSigningPlan, Vec<String>)> {
    let mut warnings = Vec::new();
    let sign = macos_sign_plan(
        root,
        &config.packager.osx_sign,
        &config.packager.osx_notarize,
        platform,
        &mut warnings,
    )?;
    let notarize = macos_notarize_plan(root, config, platform, &sign, &mut warnings)?;

    Ok((
        PackageSigningPlan {
            macos: MacosSigningPlan { sign, notarize },
        },
        warnings,
    ))
}

fn macos_sign_plan(
    root: &Path,
    config: &MacosSignConfig,
    notarize_config: &MacosNotarizeConfig,
    platform: &str,
    warnings: &mut Vec<String>,
) -> Result<MacosSignPlan> {
    if config.invalid_type {
        warnings.push("packagerConfig.osxSign must be false, true, or an object.".to_string());
    }

    let entitlements = config
        .entitlements
        .iter()
        .filter(|path| !path.trim().is_empty())
        .map(|path| {
            let resolved = resolve_project_path(root, path);
            if !resolved.exists() {
                warnings.push(format!(
                    "Configured macOS entitlements file does not exist: {}.",
                    resolved.display()
                ));
            }
            utf8_path(resolved)
        })
        .collect::<Result<Vec<_>>>()?;
    let entitlements_inherit = config
        .entitlements_inherit
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(|path| utf8_path(resolve_project_path(root, path)))
        .transpose()?;
    if let Some(path) = &entitlements_inherit {
        if !Path::new(path.as_str()).exists() {
            warnings.push(format!(
                "Configured macOS inherited entitlements file does not exist: {}.",
                path
            ));
        }
    }

    let p12_file = config
        .p12_file
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(|path| utf8_path(resolve_project_path(root, path)))
        .transpose()?;
    if let Some(path) = &p12_file {
        if !Path::new(path.as_str()).exists() {
            warnings.push(format!(
                "Configured macOS signing p12 file does not exist: {}.",
                path
            ));
        }
    }
    let p12_password_file = config
        .p12_password_file
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(|path| utf8_path(resolve_project_path(root, path)))
        .transpose()?;
    if let Some(path) = &p12_password_file {
        if !Path::new(path.as_str()).exists() {
            warnings.push(format!(
                "Configured macOS signing p12 password file does not exist: {}.",
                path
            ));
        }
    }
    let p12_password_source = if p12_file.is_some() {
        if config.p12_password.is_some() {
            Some("config".to_string())
        } else if let Some(env_name) = config
            .p12_password_env
            .as_deref()
            .filter(|name| !name.trim().is_empty())
        {
            Some(format!("env:{env_name}"))
        } else if let Some(path) = &p12_password_file {
            Some(format!("file:{path}"))
        } else {
            Some("empty".to_string())
        }
    } else {
        None
    };

    let identity = config.identity.as_deref().map(str::trim);
    let ad_hoc_identity = matches!(identity, None | Some("-"));
    let p12_identity = p12_file.is_some();
    let will_execute = config.enabled && platform == "darwin" && (ad_hoc_identity || p12_identity);
    let timestamp_url = macos_timestamp_url(config, p12_identity, notarize_config.enabled);
    let for_notarization =
        will_execute && p12_identity && notarize_config.enabled && timestamp_url.is_some();
    let method = if config.enabled && platform == "darwin" {
        if p12_identity {
            Some("certificate-p12".to_string())
        } else if ad_hoc_identity {
            Some("ad-hoc".to_string())
        } else {
            Some("certificate-identity".to_string())
        }
    } else {
        None
    };

    if config.configured && platform != "darwin" {
        warnings.push(format!(
            "macOS signing is configured but ignored for target platform {platform}."
        ));
    } else if config.enabled && !will_execute {
        warnings.push(
            "macOS signing identity is configured, but Rust-native keychain identity signing is not implemented yet; package output will be unsigned. Use p12File for certificate signing, or identity '-' / omit identity for experimental ad-hoc signing.".to_string(),
        );
    } else if will_execute {
        if p12_identity && identity.is_some() {
            warnings.push(
                "packagerConfig.osxSign.p12File supplies the signing certificate; identity is reported but not used for keychain lookup.".to_string(),
            );
        }
        if config.entitlements.len() > 1 {
            warnings.push(
                "Rust-native macOS signing applies the first macOS entitlements file only; inherited/login-helper entitlement scoping is not implemented yet.".to_string(),
            );
        }
        if config.entitlements_inherit.is_some() {
            warnings.push(
                "packagerConfig.osxSign.entitlementsInherit is recognized but not applied to nested bundles by Rust-native signing yet.".to_string(),
            );
        }
        if config.gatekeeper_assess.is_some() {
            warnings.push(
                "packagerConfig.osxSign.gatekeeperAssess is recognized but Gatekeeper assessment is not implemented yet.".to_string(),
            );
        }
        if config.timestamp.is_some() && !p12_identity {
            warnings.push(
                "packagerConfig.osxSign.timestamp is recognized but ignored without p12File certificate signing.".to_string(),
            );
        }
        if notarize_config.enabled && p12_identity && timestamp_url.is_none() {
            warnings.push(
                "macOS notarization requires a secure timestamp; packagerConfig.osxSign.timestamp disabled timestamping.".to_string(),
            );
        }
    }

    Ok(MacosSignPlan {
        configured: config.configured,
        enabled: config.enabled,
        will_execute,
        method,
        identity: config.identity.clone(),
        p12_file,
        p12_password_source,
        p12_password_env: config.p12_password_env.clone(),
        p12_password_file,
        p12_password: RedactedSecret::new(config.p12_password.clone()),
        timestamp_url,
        for_notarization,
        entitlements,
        entitlements_inherit,
        hardened_runtime: config.hardened_runtime,
        gatekeeper_assess: config.gatekeeper_assess,
    })
}

fn macos_timestamp_url(
    config: &MacosSignConfig,
    p12_identity: bool,
    notarize_enabled: bool,
) -> Option<String> {
    if !p12_identity {
        return None;
    }

    match &config.timestamp {
        Some(MacosTimestampConfig::Default) => Some(APPLE_TIMESTAMP_URL.to_string()),
        Some(MacosTimestampConfig::Disabled) => None,
        Some(MacosTimestampConfig::Url(url)) => Some(url.clone()),
        None if notarize_enabled => Some(APPLE_TIMESTAMP_URL.to_string()),
        None => None,
    }
}

fn macos_notarize_plan(
    root: &Path,
    package_config: &PackageJsonConfig,
    platform: &str,
    sign: &MacosSignPlan,
    warnings: &mut Vec<String>,
) -> Result<MacosNotarizePlan> {
    let config = &package_config.packager.osx_notarize;
    if config.invalid_type {
        warnings.push("packagerConfig.osxNotarize must be false, true, or an object.".to_string());
    }

    let auth_method = macos_notarize_auth_method(config);
    let apple_api_key = config
        .apple_api_key
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .map(|path| utf8_path(resolve_project_path(root, path)))
        .transpose()?;
    let api_key_auth = auth_method.as_deref() == Some("app-store-connect-api-key");
    let staple = config.staple.unwrap_or(true);
    let wait = staple || config.wait.unwrap_or(true);
    let wait_timeout_seconds = config
        .wait_timeout_seconds
        .unwrap_or(MACOS_NOTARIZATION_WAIT_TIMEOUT_SECONDS);
    let will_execute =
        config.enabled && platform == "darwin" && sign.for_notarization && api_key_auth;

    if config.configured && platform != "darwin" {
        warnings.push(format!(
            "macOS notarization is configured but ignored for target platform {platform}."
        ));
    }

    if config.enabled && !package_config.packager.osx_sign.enabled {
        warnings.push(
            "macOS notarization requires packagerConfig.osxSign to be enabled first.".to_string(),
        );
    }
    if config.enabled
        && platform == "darwin"
        && package_config.packager.osx_sign.enabled
        && package_config.packager.osx_sign.p12_file.is_none()
        && matches!(
            package_config
                .packager
                .osx_sign
                .identity
                .as_deref()
                .map(str::trim),
            None | Some("-")
        )
    {
        warnings.push(
            "macOS notarization requires a Developer ID signature; Rust-native ad-hoc signing is not notarizable.".to_string(),
        );
    }
    if config.enabled
        && platform == "darwin"
        && package_config.packager.osx_sign.enabled
        && !sign.for_notarization
    {
        warnings.push(
            "macOS notarization execution requires Rust-native p12File Developer ID signing with a secure timestamp.".to_string(),
        );
    }
    if config.enabled && auth_method.is_none() {
        warnings.push(
            "macOS notarization config is missing a complete notarytool authentication set: appleId/appleIdPassword/teamId, appleApiKey/appleApiKeyId/appleApiIssuer, or keychainProfile.".to_string(),
        );
    }
    if config.enabled
        && platform == "darwin"
        && matches!(
            auth_method.as_deref(),
            Some("keychain-profile") | Some("apple-id")
        )
    {
        warnings.push(
            "Rust-native macOS notarization execution currently requires appleApiKey, appleApiKeyId, and appleApiIssuer; keychain profile and Apple ID auth are recognized for planning only.".to_string(),
        );
    }
    if let Some(path) = &apple_api_key {
        if !Path::new(path.as_str()).exists() {
            warnings.push(format!(
                "Configured Apple API key file does not exist: {}.",
                path
            ));
        }
    }
    Ok(MacosNotarizePlan {
        configured: config.configured,
        enabled: config.enabled,
        will_execute,
        auth_method,
        apple_api_key,
        apple_api_key_id: RedactedSecret::new(config.apple_api_key_id.clone()),
        apple_api_issuer: RedactedSecret::new(config.apple_api_issuer.clone()),
        keychain_profile: config.keychain_profile.clone(),
        keychain: config.keychain.clone(),
        wait,
        wait_timeout_seconds,
        staple,
    })
}

fn macos_notarize_auth_method(config: &MacosNotarizeConfig) -> Option<String> {
    if config
        .keychain_profile
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        Some("keychain-profile".to_string())
    } else if config.apple_api_key.is_some()
        && config
            .apple_api_key_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        && config
            .apple_api_issuer
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    {
        Some("app-store-connect-api-key".to_string())
    } else if config.apple_id_set && config.apple_id_password_set && config.team_id_set {
        Some("apple-id".to_string())
    } else {
        None
    }
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

fn copy_project_files(
    source: &Path,
    destination: &Path,
    output_dir: &Path,
    project_root: &Path,
    ignore_rules: &[IgnoreRule],
) -> Result<()> {
    for entry in
        fs::read_dir(source).with_context(|| format!("Could not read {}", source.display()))?
    {
        let entry = entry?;
        let source_path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if should_skip_project_entry(&source_path, &file_name, output_dir)
            || should_ignore_path(&source_path, project_root, ignore_rules)
        {
            continue;
        }

        let destination_path = destination.join(file_name.as_ref());
        if source_path.is_dir() {
            copy_project_files(
                &source_path,
                &destination_path,
                output_dir,
                project_root,
                ignore_rules,
            )?;
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
    ignore_rules: &[IgnoreRule],
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
        if should_ignore_path(&canonical_package_dir, root, ignore_rules) {
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
        copy_recursively_with_ignore(&canonical_package_dir, &destination, root, ignore_rules)
            .with_context(|| {
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

#[derive(Serialize)]
#[serde(untagged)]
enum AsarHeaderNode {
    File(AsarFileHeader),
    Directory {
        files: BTreeMap<String, AsarHeaderNode>,
    },
    Link {
        link: String,
    },
}

#[derive(Serialize)]
struct AsarFileHeader {
    size: u64,
    offset: String,
    #[serde(skip_serializing_if = "is_false")]
    executable: bool,
}

enum AsarEntryKind {
    Directory,
    File { size: u64, executable: bool },
    Link { target: String },
}

struct AsarEntry {
    source: PathBuf,
    relative: PathBuf,
    kind: AsarEntryKind,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn execute_asar_packaging(report: &PackageReport) -> Result<()> {
    if !report.asar.enabled {
        return Ok(());
    }

    let app_dir = Path::new(report.app_resources_dir.as_str()).join("app");
    let archive = report
        .asar
        .archive
        .as_ref()
        .context("ASAR packaging is enabled without an archive path")?;
    let archive = Path::new(archive.as_str());

    if !app_dir.exists() {
        bail!(
            "ASAR packaging expected app staging directory: {}",
            app_dir.display()
        );
    }

    let entries = collect_asar_entries(&app_dir, &app_dir)
        .with_context(|| format!("Could not collect ASAR entries from {}", app_dir.display()))?;
    write_asar_archive(&entries, archive)
        .with_context(|| format!("Could not write ASAR archive {}", archive.display()))?;

    fs::remove_dir_all(&app_dir).with_context(|| {
        format!(
            "Could not remove ASAR staging directory {}",
            app_dir.display()
        )
    })
}

fn collect_asar_entries(source: &Path, base: &Path) -> Result<Vec<AsarEntry>> {
    let mut entries = Vec::new();
    collect_asar_entries_into(source, base, &mut entries)?;
    Ok(entries)
}

fn collect_asar_entries_into(
    source: &Path,
    base: &Path,
    entries: &mut Vec<AsarEntry>,
) -> Result<()> {
    let mut children = fs::read_dir(source)
        .with_context(|| format!("Could not read {}", source.display()))?
        .collect::<Result<Vec<_>, io::Error>>()?;
    children.sort_by_key(|entry| entry.path());

    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("Could not stat {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .with_context(|| format!("Could not read symlink {}", path.display()))?;
            entries.push(AsarEntry {
                source: path.clone(),
                relative: asar_relative_path(&path, base)?,
                kind: AsarEntryKind::Link {
                    target: path_to_forward_slashes(&target),
                },
            });
        } else if metadata.is_dir() {
            entries.push(AsarEntry {
                source: path.clone(),
                relative: asar_relative_path(&path, base)?,
                kind: AsarEntryKind::Directory,
            });
            collect_asar_entries_into(&path, base, entries)?;
        } else if metadata.is_file() {
            entries.push(AsarEntry {
                source: path.clone(),
                relative: asar_relative_path(&path, base)?,
                kind: AsarEntryKind::File {
                    size: metadata.len(),
                    executable: is_executable(&metadata),
                },
            });
        }
    }

    Ok(())
}

fn write_asar_archive(entries: &[AsarEntry], archive: &Path) -> Result<()> {
    let mut header = AsarHeaderNode::Directory {
        files: BTreeMap::new(),
    };
    let mut offset = 0_u64;

    for entry in entries {
        match &entry.kind {
            AsarEntryKind::Directory => {
                insert_asar_header_entry(
                    &mut header,
                    &entry.relative,
                    AsarHeaderNode::Directory {
                        files: BTreeMap::new(),
                    },
                )?;
            }
            AsarEntryKind::File { size, executable } => {
                insert_asar_header_entry(
                    &mut header,
                    &entry.relative,
                    AsarHeaderNode::File(AsarFileHeader {
                        size: *size,
                        offset: offset.to_string(),
                        executable: *executable,
                    }),
                )?;
                offset = offset.saturating_add(*size);
            }
            AsarEntryKind::Link { target } => {
                insert_asar_header_entry(
                    &mut header,
                    &entry.relative,
                    AsarHeaderNode::Link {
                        link: target.clone(),
                    },
                )?;
            }
        }
    }

    let mut json = serde_json::to_vec(&header).context("Could not serialize ASAR header")?;
    let json_size = u32::try_from(json.len()).context("ASAR header is too large")?;
    let aligned_json_size = json_size + (4 - (json_size % 4)) % 4;
    json.resize(aligned_json_size as usize, 0);

    let file = File::create(archive)
        .with_context(|| format!("Could not create ASAR archive {}", archive.display()))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&4_u32.to_le_bytes())?;
    writer.write_all(&(aligned_json_size + 8).to_le_bytes())?;
    writer.write_all(&(aligned_json_size + 4).to_le_bytes())?;
    writer.write_all(&json_size.to_le_bytes())?;
    writer.write_all(&json)?;

    for entry in entries {
        if matches!(entry.kind, AsarEntryKind::File { .. }) {
            let mut input = File::open(&entry.source)
                .with_context(|| format!("Could not open {}", entry.source.display()))?;
            io::copy(&mut input, &mut writer)
                .with_context(|| format!("Could not write {} to ASAR", entry.source.display()))?;
        }
    }

    writer.flush().context("Could not flush ASAR archive")
}

fn insert_asar_header_entry(
    header: &mut AsarHeaderNode,
    relative: &Path,
    leaf: AsarHeaderNode,
) -> Result<()> {
    let components = asar_path_components(relative)?;
    insert_asar_header_components(header, &components, leaf)
}

fn insert_asar_header_components(
    header: &mut AsarHeaderNode,
    components: &[String],
    leaf: AsarHeaderNode,
) -> Result<()> {
    let AsarHeaderNode::Directory { files } = header else {
        bail!("ASAR header path conflicts with an existing file");
    };
    let Some((name, rest)) = components.split_first() else {
        bail!("ASAR entry path is empty");
    };

    if rest.is_empty() {
        files.insert(name.clone(), leaf);
    } else {
        let child = files
            .entry(name.clone())
            .or_insert_with(|| AsarHeaderNode::Directory {
                files: BTreeMap::new(),
            });
        insert_asar_header_components(child, rest, leaf)?;
    }

    Ok(())
}

fn asar_path_components(path: &Path) -> Result<Vec<String>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) => {
                components.push(value.to_string_lossy().to_string());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::Prefix(_)
            | std::path::Component::RootDir => {
                bail!("ASAR entry path must be relative: {}", path.display());
            }
        }
    }
    if components.is_empty() {
        bail!("ASAR entry path is empty");
    }
    Ok(components)
}

fn asar_relative_path(path: &Path, base: &Path) -> Result<PathBuf> {
    path.strip_prefix(base)
        .with_context(|| {
            format!(
                "Could not make {} relative to {} for ASAR",
                path.display(),
                base.display()
            )
        })
        .map(Path::to_path_buf)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
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
    set_plist_string(&mut dictionary, "CFBundlePackageType", "APPL");

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

fn copy_recursively_with_ignore(
    source: &Path,
    destination: &Path,
    project_root: &Path,
    ignore_rules: &[IgnoreRule],
) -> Result<()> {
    if should_ignore_path(source, project_root, ignore_rules) {
        return Ok(());
    }

    if source.is_dir() {
        fs::create_dir_all(destination)
            .with_context(|| format!("Could not create {}", destination.display()))?;

        for entry in
            fs::read_dir(source).with_context(|| format!("Could not read {}", source.display()))?
        {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            copy_recursively_with_ignore(
                &source_path,
                &destination_path,
                project_root,
                ignore_rules,
            )?;
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

fn should_ignore_path(path: &Path, project_root: &Path, ignore_rules: &[IgnoreRule]) -> bool {
    if ignore_rules.is_empty() {
        return false;
    }

    let candidates = ignore_match_candidates(path, project_root);
    ignore_rules.iter().any(|rule| {
        candidates
            .iter()
            .any(|candidate| rule.0.is_match(candidate))
    })
}

fn ignore_match_candidates(path: &Path, project_root: &Path) -> Vec<String> {
    let mut candidates = Vec::new();
    let is_dir = path.is_dir();

    if let Ok(relative) = path.strip_prefix(project_root) {
        let relative = path_to_forward_slashes(relative);
        if !relative.is_empty() {
            candidates.push(relative.clone());
            candidates.push(format!("/{relative}"));
            if is_dir {
                candidates.push(format!("{relative}/"));
                candidates.push(format!("/{relative}/"));
            }
        }
    }

    let absolute = path_to_forward_slashes(path);
    candidates.push(absolute.clone());
    if is_dir {
        candidates.push(format!("{absolute}/"));
    }

    candidates
}

fn path_to_forward_slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
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
        if !other.ignore.is_empty() {
            self.ignore = other.ignore;
        }
        if other.asar.configured {
            self.asar = other.asar;
        }
        self.darwin_dark_mode_support =
            other.darwin_dark_mode_support || self.darwin_dark_mode_support;
        if other.osx_sign.configured {
            self.osx_sign = other.osx_sign;
        }
        if other.osx_notarize.configured {
            self.osx_notarize = other.osx_notarize;
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

    pub(crate) fn executable_name(&self) -> &str {
        &self.executable_name
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
    fn packages_respect_packager_ignore_patterns() {
        let root = unique_temp_dir("ignore-patterns");
        fs::write(
            root.join("package.json"),
            r#"{
                "name":"starter-app",
                "version":"0.1.0",
                "main":"src/main.js",
                "devDependencies":{"electron":"30.0.0"},
                "electronCli":{
                    "packagerConfig":{
                        "ignore":[
                            "^/src/ignored\\.js$",
                            "^/build(?:/|$)",
                            "/^\\/coverage(?:\\/|$)/"
                        ]
                    }
                }
            }"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        fs::write(root.join("src/ignored.js"), "console.log('ignore');")
            .expect("ignored source should be written");
        fs::create_dir_all(root.join("build")).expect("build dir should be created");
        fs::write(root.join("build/generated.js"), "console.log('ignore');")
            .expect("ignored build file should be written");
        fs::create_dir_all(root.join("coverage")).expect("coverage dir should be created");
        fs::write(root.join("coverage/report.txt"), "ignore")
            .expect("ignored coverage file should be written");
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

        assert_eq!(report.ignore_patterns.len(), 3);
        assert!(report.warnings.is_empty());
        execute_package(&report, false).expect("package should succeed");

        let app_dir = Path::new(report.app_resources_dir.as_str()).join("app");
        assert!(app_dir.join("src/main.js").exists());
        assert!(!app_dir.join("src/ignored.js").exists());
        assert!(!app_dir.join("build").exists());
        assert!(!app_dir.join("coverage").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn packages_respect_packager_ignore_patterns_inside_runtime_dependencies() {
        let root = unique_temp_dir("ignore-runtime-deps");
        fs::write(
            root.join("package.json"),
            r#"{
                "name":"starter-app",
                "version":"0.1.0",
                "main":"src/main.js",
                "dependencies":{"dep-a":"1.0.0"},
                "devDependencies":{"electron":"30.0.0"},
                "electronCli":{
                    "packagerConfig":{
                        "ignore":["^/node_modules/dep-a/test(?:/|$)"]
                    }
                }
            }"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);
        write_dependency_package(&root, "dep-a", r#"{"name":"dep-a","version":"1.0.0"}"#);
        let dep_test_dir = root.join("node_modules/dep-a/test");
        fs::create_dir_all(&dep_test_dir).expect("dependency test dir should be created");
        fs::write(dep_test_dir.join("fixture.js"), "module.exports = true;")
            .expect("dependency test fixture should be written");

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
        assert!(app_node_modules.join("dep-a/index.js").exists());
        assert!(!app_node_modules.join("dep-a/test").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_packager_ignore_pattern_is_reported_and_skipped() {
        let root = unique_temp_dir("invalid-ignore-pattern");
        fs::write(
            root.join("package.json"),
            r#"{
                "name":"starter-app",
                "version":"0.1.0",
                "main":"src/main.js",
                "devDependencies":{"electron":"30.0.0"},
                "electronCli":{"packagerConfig":{"ignore":["["]}}
            }"#,
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
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report
            .warnings
            .iter()
            .any(|warning| warning
                .contains("Configured packager ignore pattern is not a valid regex")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn packages_app_into_asar_archive() {
        let root = unique_temp_dir("asar-package");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","dependencies":{"dep-a":"1.0.0"},"devDependencies":{"electron":"30.0.0"},"electronCli":{"packagerConfig":{"asar":true}}}"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);
        write_dependency_package(&root, "dep-a", r#"{"name":"dep-a","version":"1.0.0"}"#);
        fs::create_dir_all(root.join("node_modules/dep-a/empty-cache"))
            .expect("empty dependency directory should be written");

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

        assert!(report.asar.configured);
        assert!(report.asar.enabled);
        assert!(report.asar.archive.is_some());
        assert!(report.warnings.is_empty());

        execute_package(&report, false).expect("package should succeed");

        let app_dir = Path::new(report.app_resources_dir.as_str()).join("app");
        let app_asar = Path::new(report.app_resources_dir.as_str()).join("app.asar");
        assert!(!app_dir.exists());
        assert!(app_asar.exists());

        let archive = fs::read(&app_asar).expect("ASAR archive should read");
        let reader = asar::AsarReader::new(&archive, None).expect("ASAR archive should parse");
        assert!(reader.read(Path::new("package.json")).is_some());
        assert!(reader.read(Path::new("src/main.js")).is_some());
        assert!(reader
            .read(Path::new("node_modules/dep-a/package.json"))
            .is_some());
        assert!(reader
            .read(Path::new("node_modules/dep-a/index.js"))
            .is_some());
        let dep_contents = reader
            .read_dir(Path::new("node_modules/dep-a"))
            .expect("dep-a directory should be readable");
        assert!(dep_contents
            .iter()
            .any(|path| path.as_path() == Path::new("node_modules/dep-a/empty-cache")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn warns_for_unsupported_asar_options_but_plans_archive() {
        let root = unique_temp_dir("asar-options");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"},"electronCli":{"packagerConfig":{"asar":{"unpack":"**/*.node","ordering":"ordering.txt"}}}}"#,
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
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.asar.configured);
        assert!(report.asar.enabled);
        assert!(report.asar.archive.is_some());
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("packagerConfig.asar options")
                && warning.contains("unpack")
                && warning.contains("ordering")
        }));

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
    fn plans_packager_metadata_from_forge_config_js() {
        let root = unique_temp_dir("forge-config-metadata");
        write_package_json(&root);
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                name: 'Forge Config App',
                executableName: 'ForgeExec',
                appBundleId: 'com.example.forge-config',
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
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

        assert_eq!(report.app_name, "Forge Config App");
        assert_eq!(
            report.executable_name,
            executable_name("ForgeExec", &report.platform)
        );
        assert_eq!(
            report.metadata.bundle_identifier,
            "com.example.forge-config"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plans_macos_signing_and_notarization_without_serializing_secrets() {
        let root = unique_temp_dir("macos-signing-plan");
        write_package_json(&root);
        fs::write(root.join("entitlements.plist"), "<plist></plist>")
            .expect("entitlements should be written");
        fs::write(root.join("AuthKey_TEST.p8"), "secret api key")
            .expect("api key should be written");
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                osxSign: {
                  identity: 'Developer ID Application: Example, Inc. (TEAMID1234)',
                  entitlements: 'entitlements.plist',
                  entitlementsInherit: 'entitlements.plist',
                  hardenedRuntime: true,
                  gatekeeperAssess: false,
                },
                osxNotarize: {
                  appleApiKey: 'AuthKey_TEST.p8',
                  appleApiKeyId: 'SECRET_KEY_ID',
                  appleApiIssuer: 'SECRET_ISSUER_ID',
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.configured);
        assert!(report.signing.macos.sign.enabled);
        assert!(!report.signing.macos.sign.will_execute);
        assert_eq!(
            report.signing.macos.sign.method.as_deref(),
            Some("certificate-identity")
        );
        assert_eq!(
            report.signing.macos.sign.identity.as_deref(),
            Some("Developer ID Application: Example, Inc. (TEAMID1234)")
        );
        assert_eq!(report.signing.macos.sign.hardened_runtime, Some(true));
        assert_eq!(report.signing.macos.sign.gatekeeper_assess, Some(false));
        assert_eq!(report.signing.macos.sign.entitlements.len(), 2);
        assert!(report.signing.macos.notarize.configured);
        assert!(!report.signing.macos.notarize.will_execute);
        assert_eq!(
            report.signing.macos.notarize.auth_method.as_deref(),
            Some("app-store-connect-api-key")
        );
        assert!(report.signing.macos.notarize.apple_api_key.is_some());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("Rust-native keychain identity signing")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("p12File Developer ID signing")));

        let json = serde_json::to_string(&report).expect("report should serialize");
        assert!(!json.contains("SECRET_KEY_ID"));
        assert!(!json.contains("SECRET_ISSUER_ID"));
        assert!(!json.contains("secret api key"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plans_macos_ad_hoc_signing_execution() {
        let root = unique_temp_dir("macos-ad-hoc-signing-plan");
        write_package_json(&root);
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                osxSign: {
                  identity: '-',
                  hardenedRuntime: true,
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.configured);
        assert!(report.signing.macos.sign.enabled);
        assert!(report.signing.macos.sign.will_execute);
        assert_eq!(report.signing.macos.sign.method.as_deref(), Some("ad-hoc"));
        assert_eq!(report.signing.macos.sign.identity.as_deref(), Some("-"));
        assert_eq!(report.signing.macos.sign.hardened_runtime, Some(true));
        assert!(!report.warnings.iter().any(|warning| {
            warning.contains("Rust-native keychain identity signing")
                || warning.contains("Rust-native signing is not implemented")
        }));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plans_macos_p12_signing_without_serializing_password() {
        let root = unique_temp_dir("macos-p12-signing-plan");
        write_package_json(&root);
        fs::write(root.join("developer-id.p12"), "not a real p12")
            .expect("p12 placeholder should be written");
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                osxSign: {
                  identity: 'Developer ID Application: Example, Inc. (TEAMID1234)',
                  p12File: 'developer-id.p12',
                  p12Password: 'p12-secret',
                  timestamp: 'http://timestamp.example.test/tsa',
                  hardenedRuntime: true,
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.configured);
        assert!(report.signing.macos.sign.enabled);
        assert!(report.signing.macos.sign.will_execute);
        assert_eq!(
            report.signing.macos.sign.method.as_deref(),
            Some("certificate-p12")
        );
        assert_eq!(
            report.signing.macos.sign.p12_password_source.as_deref(),
            Some("config")
        );
        assert_eq!(
            report.signing.macos.sign.timestamp_url.as_deref(),
            Some("http://timestamp.example.test/tsa")
        );
        assert!(!report.signing.macos.sign.for_notarization);
        assert!(report.signing.macos.sign.p12_file.is_some());
        assert!(report
            .warnings
            .iter()
            .any(|warning| { warning.contains("p12File supplies the signing certificate") }));

        let json = serde_json::to_string(&report).expect("report should serialize");
        assert!(!json.contains("p12-secret"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plans_macos_p12_signing_for_notarization_with_default_timestamp() {
        let root = unique_temp_dir("macos-p12-notarization-signing-plan");
        write_package_json(&root);
        fs::write(root.join("developer-id.p12"), "not a real p12")
            .expect("p12 placeholder should be written");
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                appBundleId: 'com.example.notarized',
                osxSign: {
                  p12File: 'developer-id.p12',
                  p12PasswordEnv: 'P12_PASSWORD',
                },
                osxNotarize: {
                  keychainProfile: 'notary-profile',
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.will_execute);
        assert_eq!(
            report.signing.macos.sign.timestamp_url.as_deref(),
            Some(APPLE_TIMESTAMP_URL)
        );
        assert!(report.signing.macos.sign.for_notarization);
        assert_eq!(
            report.signing.macos.notarize.auth_method.as_deref(),
            Some("keychain-profile")
        );
        assert!(!report.signing.macos.notarize.will_execute);
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("ad-hoc signing is not notarizable")));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("requires appleApiKey")));

        let settings = macos_signing_settings(&report).expect("signing settings should build");
        assert!(settings.for_notarization());
        assert_eq!(
            settings.time_stamp_url().map(|url| url.as_str()),
            Some(APPLE_TIMESTAMP_URL)
        );

        let json = serde_json::to_string(&report).expect("report should serialize");
        assert!(!json.contains("P12_PASSWORD="));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plans_macos_native_notarization_execution_with_api_key_auth() {
        let root = unique_temp_dir("macos-native-notarization-plan");
        write_package_json(&root);
        fs::write(root.join("developer-id.p12"), "not a real p12")
            .expect("p12 placeholder should be written");
        fs::write(root.join("AuthKey_TEST.p8"), "not a real api key")
            .expect("api key placeholder should be written");
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                appBundleId: 'com.example.native-notarized',
                osxSign: {
                  p12File: 'developer-id.p12',
                  p12Password: 'p12-secret',
                  hardenedRuntime: true,
                },
                osxNotarize: {
                  appleApiKey: 'AuthKey_TEST.p8',
                  appleApiKeyId: 'SECRET_KEY_ID',
                  appleApiIssuer: 'SECRET_ISSUER_ID',
                  maxWaitSeconds: 120,
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.for_notarization);
        assert!(report.signing.macos.notarize.will_execute);
        assert_eq!(
            report.signing.macos.notarize.auth_method.as_deref(),
            Some("app-store-connect-api-key")
        );
        assert!(report.signing.macos.notarize.wait);
        assert_eq!(report.signing.macos.notarize.wait_timeout_seconds, 120);
        assert!(report.signing.macos.notarize.staple);
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("Rust-native notarization is not implemented")));

        let json = serde_json::to_string(&report).expect("report should serialize");
        assert!(!json.contains("SECRET_KEY_ID"));
        assert!(!json.contains("SECRET_ISSUER_ID"));
        assert!(!json.contains("p12-secret"));
        assert!(!json.contains("not a real api key"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn warns_when_macos_notarization_timestamp_is_disabled() {
        let root = unique_temp_dir("macos-p12-notarization-no-timestamp");
        write_package_json(&root);
        fs::write(root.join("developer-id.p12"), "not a real p12")
            .expect("p12 placeholder should be written");
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                osxSign: {
                  p12File: 'developer-id.p12',
                  timestamp: 'none',
                },
                osxNotarize: {
                  keychainProfile: 'notary-profile',
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.will_execute);
        assert!(report.signing.macos.sign.timestamp_url.is_none());
        assert!(!report.signing.macos.sign.for_notarization);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("requires a secure timestamp")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn warns_when_macos_notarization_is_configured_without_signing() {
        let root = unique_temp_dir("notarize-without-sign");
        write_package_json(&root);
        fs::write(
            root.join("forge.config.js"),
            r#"
            module.exports = {
              packagerConfig: {
                osxSign: false,
                osxNotarize: {
                  keychainProfile: 'notary-profile',
                },
              },
            };
            "#,
        )
        .expect("forge config should be written");
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = PackageArgs {
            cwd: root.clone(),
            out_dir: PathBuf::from("out"),
            name: None,
            platform: Some("darwin".to_string()),
            arch: Some("arm64".to_string()),
            force: false,
            dry_run: true,
            json: true,
        };
        let snapshot = crate::project::inspect(&root).expect("project should inspect");
        let report = build_report(snapshot, &args).expect("report should build");

        assert!(report.signing.macos.sign.configured);
        assert!(!report.signing.macos.sign.enabled);
        assert_eq!(
            report.signing.macos.notarize.auth_method.as_deref(),
            Some("keychain-profile")
        );
        assert!(report.warnings.iter().any(|warning| {
            warning.contains("macOS notarization requires packagerConfig.osxSign")
        }));

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
            plist_string(dictionary, "CFBundlePackageType"),
            Some("APPL")
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
    fn packages_macos_bundle_with_ad_hoc_signature() {
        if current_platform() != "darwin" {
            return;
        }

        let root = unique_temp_dir("macos-ad-hoc-signing-execute");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"},"electronCli":{"packagerConfig":{"appBundleId":"com.example.signed","osxSign":true}}}"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        write_macho_electron_dist(&root);

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

        assert!(report.signing.macos.sign.will_execute);
        assert_eq!(report.signing.macos.sign.method.as_deref(), Some("ad-hoc"));
        assert!(report.warnings.is_empty());

        execute_package(&report, false).expect("package should succeed");

        let bundle_dir = Path::new(report.bundle_dir.as_str());
        assert!(bundle_dir
            .join("Contents/_CodeSignature/CodeResources")
            .exists());

        let executable = bundle_dir
            .join("Contents/MacOS")
            .join(&report.executable_name);
        let executable_data = fs::read(executable).expect("signed executable should read");
        let macho = apple_codesign::MachFile::parse(&executable_data)
            .expect("signed executable should parse as Mach-O");
        assert!(macho.iter_macho().all(|binary| binary
            .code_signature()
            .expect("code signature should parse")
            .is_some()));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn packages_macos_bundle_with_p12_certificate_signature() {
        if current_platform() != "darwin" {
            return;
        }

        let Some(p12_fixture) = apple_codesign_test_fixture("apple-codesign-testuser.p12") else {
            return;
        };

        let root = unique_temp_dir("macos-p12-signing-execute");
        fs::copy(&p12_fixture, root.join("developer-id.p12"))
            .expect("p12 fixture should be copied");
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"},"electronCli":{"packagerConfig":{"appBundleId":"com.example.p12-signed","osxSign":{"p12File":"developer-id.p12","p12Password":"password123","hardenedRuntime":true}}}}"#,
        )
        .expect("package.json should be written");
        write_app_file(&root);
        write_macho_electron_dist(&root);

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

        assert!(report.signing.macos.sign.will_execute);
        assert_eq!(
            report.signing.macos.sign.method.as_deref(),
            Some("certificate-p12")
        );
        assert!(report.warnings.is_empty());

        execute_package(&report, false).expect("package should succeed");

        let executable = Path::new(report.bundle_dir.as_str())
            .join("Contents/MacOS")
            .join(&report.executable_name);
        let executable_data = fs::read(executable).expect("signed executable should read");
        let macho = apple_codesign::MachFile::parse(&executable_data)
            .expect("signed executable should parse as Mach-O");
        assert!(macho.iter_macho().all(|binary| {
            let signature = binary
                .code_signature()
                .expect("code signature should parse")
                .expect("code signature should exist");
            signature
                .signature_data()
                .expect("CMS signature should parse")
                .is_some_and(|data| !data.is_empty())
        }));

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

    fn write_macho_electron_dist(root: &Path) {
        let app = root.join("node_modules/electron/dist/Electron.app/Contents/MacOS");
        fs::create_dir_all(&app).expect("macOS Electron app should be created");
        fs::copy(
            std::env::current_exe().expect("current test executable should resolve"),
            app.join("Electron"),
        )
        .expect("Mach-O test executable should be copied");
    }

    fn apple_codesign_test_fixture(file_name: &str) -> Option<PathBuf> {
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))?;
        let registry_src = cargo_home.join("registry/src");
        for index_dir in fs::read_dir(registry_src).ok()? {
            let index_dir = index_dir.ok()?;
            for crate_dir in fs::read_dir(index_dir.path()).ok()? {
                let crate_dir = crate_dir.ok()?;
                let file_name_matches = crate_dir
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("apple-codesign-"));
                if file_name_matches {
                    let candidate = crate_dir.path().join("src").join(file_name);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                }
            }
        }

        None
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
