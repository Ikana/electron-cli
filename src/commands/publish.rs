use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{
    cli::{MakeArgs, PublishArgs, PublishTarget},
    commands::make::{self, MakeReport},
    output,
    project::ProjectSnapshot,
};

#[derive(Debug, Serialize)]
struct PublishReport {
    make: MakeReport,
    publisher: String,
    #[serde(skip)]
    publisher_kind: PublishTarget,
    channel: String,
    local: Option<LocalPublishPlan>,
    github: Option<GithubPublishPlan>,
    #[serde(skip)]
    force_publish: bool,
    #[serde(skip)]
    github_auth_token: Option<String>,
    skip_make: bool,
    dry_run: bool,
    status: PublishStatus,
    published_at_unix_seconds: Option<u64>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LocalPublishPlan {
    destination_dir: Utf8PathBuf,
    destination_artifact: Utf8PathBuf,
    manifest: Utf8PathBuf,
}

#[derive(Debug, Serialize)]
struct GithubPublishPlan {
    repo: String,
    tag: String,
    release_name: String,
    draft: bool,
    prerelease: bool,
    api_url: String,
    artifact_name: String,
    release_url: Option<String>,
    asset_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublishStatus {
    Planned,
    Published,
}

#[derive(Debug, Serialize)]
struct PublishRunReport<'a> {
    publishes: &'a [PublishReport],
    dry_run: bool,
    status: PublishStatus,
    warnings: Vec<String>,
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

#[derive(Debug)]
struct ResolvedPublishers {
    publishers: Vec<ResolvedPublisher>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct ResolvedPublisher {
    target: PublishTarget,
    to: PathBuf,
    channel: String,
    github_repo: Option<String>,
    github_tag: Option<String>,
    github_tag_prefix: Option<String>,
    github_release_name: Option<String>,
    github_draft: bool,
    github_prerelease: bool,
    github_api_url: String,
    github_auth_token: Option<String>,
    force_publish: bool,
}

#[derive(Debug)]
struct ConfiguredPublisher {
    label: String,
    target: Option<PublishTarget>,
    platforms: Vec<String>,
    to: Option<PathBuf>,
    channel: Option<String>,
    github_repo: Option<String>,
    github_tag: Option<String>,
    github_tag_prefix: Option<String>,
    github_release_name: Option<String>,
    github_draft: Option<bool>,
    github_prerelease: Option<bool>,
    github_api_url: Option<String>,
    github_auth_token: Option<String>,
    force_publish: Option<bool>,
}

pub fn run(args: PublishArgs) -> Result<()> {
    let mut make_reports = make::build_reports(&make_args(&args))?;
    let mut reports = build_reports_from_make_reports(&args, &make_reports)?;

    if args.dry_run {
        return print_reports(&reports, args.json, PublishStatus::Planned);
    }

    execute_publish_reports(&mut reports, &mut make_reports, &args)?;

    print_reports(&reports, args.json, PublishStatus::Published)
}

#[cfg(test)]
fn build_report(args: &PublishArgs) -> Result<PublishReport> {
    let reports = build_reports(args)?;
    if reports.len() != 1 {
        bail!(
            "Expected one publish target, but resolved {}. Pass --target and --publisher to select one target.",
            reports.len()
        );
    }
    Ok(reports
        .into_iter()
        .next()
        .expect("length was checked above"))
}

#[cfg(test)]
fn build_reports(args: &PublishArgs) -> Result<Vec<PublishReport>> {
    let make_reports = make::build_reports(&make_args(args))?;
    build_reports_from_make_reports(args, &make_reports)
}

fn build_reports_from_make_reports(
    args: &PublishArgs,
    make_reports: &[MakeReport],
) -> Result<Vec<PublishReport>> {
    let first_make = make_reports
        .first()
        .context("No make targets were resolved for publish.")?;
    let project = first_make.package().project();
    let platform = first_make.package().platform();
    let resolved = resolve_publishers(project, args, platform)?;
    let mut reports = Vec::new();

    for publisher in &resolved.publishers {
        for make in make_reports {
            reports.push(build_report_for_publisher(
                args,
                make.clone(),
                publisher,
                &resolved.warnings,
            )?);
        }
    }

    Ok(reports)
}

fn build_report_for_publisher(
    args: &PublishArgs,
    make: MakeReport,
    publisher: &ResolvedPublisher,
    config_warnings: &[String],
) -> Result<PublishReport> {
    let root = Path::new(make.package().project().root.as_str());
    let artifact_name = make
        .artifact()
        .file_name()
        .context("Make artifact path has no UTF-8 file name")?
        .to_string();

    let mut warnings = make.warnings().to_vec();
    warnings.extend(config_warnings.iter().cloned());
    if args.skip_make && !Path::new(make.artifact().as_str()).exists() {
        warnings.push(format!(
            "Make artifact does not exist: {}.",
            make.artifact()
        ));
    }
    let (local, github) = match publisher.target {
        PublishTarget::Local => {
            let local = build_local_plan(root, publisher, &make, &artifact_name)?;
            if Path::new(local.destination_artifact.as_str()).exists() && !publisher.force_publish {
                warnings.push(format!(
                    "Publish artifact already exists: {}. Use --force to overwrite it.",
                    local.destination_artifact
                ));
            }
            if Path::new(local.manifest.as_str()).exists() && !publisher.force_publish {
                warnings.push(format!(
                    "Publish manifest already exists: {}. Use --force to overwrite it.",
                    local.manifest
                ));
            }
            (Some(local), None)
        }
        PublishTarget::Github => {
            let github = build_github_plan(publisher, &make, &artifact_name, &mut warnings)?;
            (None, Some(github))
        }
    };

    Ok(PublishReport {
        make,
        publisher: publisher.target.as_str().to_string(),
        publisher_kind: publisher.target,
        channel: publisher.channel.clone(),
        local,
        github,
        force_publish: publisher.force_publish,
        github_auth_token: publisher.github_auth_token.clone(),
        skip_make: args.skip_make,
        dry_run: args.dry_run,
        status: PublishStatus::Planned,
        published_at_unix_seconds: None,
        warnings,
    })
}

fn build_local_plan(
    root: &Path,
    publisher: &ResolvedPublisher,
    make: &MakeReport,
    artifact_name: &str,
) -> Result<LocalPublishPlan> {
    let publish_root = resolve_destination(root, &publisher.to);
    let destination_dir = publish_root
        .join(&publisher.channel)
        .join(make.package().platform())
        .join(make.package().arch());
    let destination_artifact = destination_dir.join(artifact_name);
    let manifest = destination_dir.join("manifest.json");

    Ok(LocalPublishPlan {
        destination_dir: utf8_path(destination_dir)?,
        destination_artifact: utf8_path(destination_artifact)?,
        manifest: utf8_path(manifest)?,
    })
}

fn build_github_plan(
    publisher: &ResolvedPublisher,
    make: &MakeReport,
    artifact_name: &str,
    warnings: &mut Vec<String>,
) -> Result<GithubPublishPlan> {
    let repo = publisher
        .github_repo
        .clone()
        .or_else(|| {
            make.package()
                .project()
                .repository
                .as_deref()
                .and_then(github_repo_from_repository)
        })
        .unwrap_or_default();
    if repo.is_empty() {
        warnings.push(
            "GitHub repository is not configured. Pass --github-repo OWNER/REPO or set package.json repository.".to_string(),
        );
    } else if !valid_github_repo(&repo) {
        warnings.push(format!(
            "GitHub repository should use OWNER/REPO form: {repo}."
        ));
    }

    let tag = publisher.github_tag.clone().unwrap_or_else(|| {
        default_github_tag(
            make,
            &publisher.channel,
            publisher.github_tag_prefix.as_deref(),
        )
    });
    let release_name = publisher
        .github_release_name
        .clone()
        .unwrap_or_else(|| tag.clone());
    let prerelease = publisher.github_prerelease || tag.contains('-');

    Ok(GithubPublishPlan {
        repo,
        tag,
        release_name,
        draft: publisher.github_draft,
        prerelease,
        api_url: publisher.github_api_url.trim_end_matches('/').to_string(),
        artifact_name: artifact_name.to_string(),
        release_url: None,
        asset_url: None,
    })
}

fn make_args(args: &PublishArgs) -> MakeArgs {
    MakeArgs {
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
    }
}

fn resolve_publishers(
    project: &ProjectSnapshot,
    args: &PublishArgs,
    platform: &str,
) -> Result<ResolvedPublishers> {
    if let Some(target) = args.publisher {
        return Ok(ResolvedPublishers {
            publishers: vec![resolved_publisher_from_args(args, target, None)],
            warnings: Vec::new(),
        });
    }

    let configured = configured_publishers(project)?;
    let mut warnings = Vec::new();
    let mut publishers = Vec::new();

    for publisher in &configured {
        let Some(target) = publisher.target else {
            warnings.push(format!(
                "Configured publisher is not implemented yet and will be skipped: {}.",
                publisher.label
            ));
            continue;
        };
        if !publisher_applies_to_platform(publisher, platform) {
            continue;
        }
        publishers.push(resolved_publisher_from_args(args, target, Some(publisher)));
    }

    if publishers.is_empty() {
        if !configured.is_empty() {
            warnings.push(format!(
                "No supported configured publishers apply to {platform}; defaulting to local. Pass --publisher to override."
            ));
        }
        publishers.push(resolved_publisher_from_args(
            args,
            PublishTarget::Local,
            None,
        ));
    }

    Ok(ResolvedPublishers {
        publishers,
        warnings,
    })
}

fn resolved_publisher_from_args(
    args: &PublishArgs,
    target: PublishTarget,
    configured: Option<&ConfiguredPublisher>,
) -> ResolvedPublisher {
    let default_to = PathBuf::from("out/publish/local");
    let default_channel = "default".to_string();
    let default_github_api_url = "https://api.github.com".to_string();

    ResolvedPublisher {
        target,
        to: args
            .to
            .clone()
            .or_else(|| configured.and_then(|publisher| publisher.to.clone()))
            .unwrap_or(default_to),
        channel: args
            .channel
            .clone()
            .or_else(|| configured.and_then(|publisher| publisher.channel.clone()))
            .unwrap_or(default_channel),
        github_repo: args
            .github_repo
            .clone()
            .or_else(|| configured.and_then(|publisher| publisher.github_repo.clone())),
        github_tag: args
            .github_tag
            .clone()
            .or_else(|| configured.and_then(|publisher| publisher.github_tag.clone())),
        github_tag_prefix: configured.and_then(|publisher| publisher.github_tag_prefix.clone()),
        github_release_name: args
            .github_release_name
            .clone()
            .or_else(|| configured.and_then(|publisher| publisher.github_release_name.clone())),
        github_draft: args.github_draft
            || configured
                .and_then(|publisher| publisher.github_draft)
                .unwrap_or(false),
        github_prerelease: args.github_prerelease
            || configured
                .and_then(|publisher| publisher.github_prerelease)
                .unwrap_or(false),
        github_api_url: args
            .github_api_url
            .clone()
            .or_else(|| configured.and_then(|publisher| publisher.github_api_url.clone()))
            .unwrap_or(default_github_api_url),
        github_auth_token: configured.and_then(|publisher| publisher.github_auth_token.clone()),
        force_publish: args.force
            || configured
                .and_then(|publisher| publisher.force_publish)
                .unwrap_or(false),
    }
}

fn configured_publishers(project: &ProjectSnapshot) -> Result<Vec<ConfiguredPublisher>> {
    let Some(package_json_path) = &project.package_json else {
        return Ok(Vec::new());
    };
    let package_json_path = Path::new(package_json_path.as_str());
    let raw = fs::read_to_string(package_json_path)
        .with_context(|| format!("Could not read {}", package_json_path.display()))?;
    let package = serde_json::from_str::<JsonValue>(&raw)
        .with_context(|| format!("Could not parse {}", package_json_path.display()))?;

    let mut publishers = Vec::new();
    for value in [
        package
            .get("config")
            .and_then(|config| config.get("forge"))
            .and_then(|forge| forge.get("publishers")),
        package
            .get("electronCli")
            .or_else(|| package.get("electron-cli"))
            .and_then(|config| config.get("publishers")),
    ]
    .into_iter()
    .flatten()
    {
        publishers.extend(parse_publisher_list(value));
    }

    Ok(publishers)
}

fn parse_publisher_list(value: &JsonValue) -> Vec<ConfiguredPublisher> {
    match value {
        JsonValue::Array(values) => values.iter().filter_map(parse_publisher).collect(),
        _ => Vec::new(),
    }
}

fn parse_publisher(value: &JsonValue) -> Option<ConfiguredPublisher> {
    match value {
        JsonValue::String(label) => Some(ConfiguredPublisher {
            label: label.clone(),
            target: publisher_target(label),
            platforms: Vec::new(),
            to: None,
            channel: None,
            github_repo: None,
            github_tag: None,
            github_tag_prefix: None,
            github_release_name: None,
            github_draft: None,
            github_prerelease: None,
            github_api_url: None,
            github_auth_token: None,
            force_publish: None,
        }),
        JsonValue::Object(object) => {
            let label = object
                .get("name")
                .or_else(|| object.get("publisher"))
                .or_else(|| object.get("target"))
                .and_then(JsonValue::as_str)?
                .to_string();
            Some(ConfiguredPublisher {
                target: publisher_target(&label),
                platforms: string_values(object.get("platforms")),
                to: publisher_config_string(object, &["to", "path", "dir", "directory"])
                    .map(PathBuf::from),
                channel: publisher_config_string(object, &["channel"]),
                github_repo: publisher_config_github_repo(object),
                github_tag: publisher_config_string(object, &["tag", "tagName", "tag_name"]),
                github_tag_prefix: publisher_config_string(object, &["tagPrefix", "tag_prefix"]),
                github_release_name: publisher_config_string(
                    object,
                    &["releaseName", "release_name"],
                ),
                github_draft: publisher_config_bool(object, &["draft"]),
                github_prerelease: publisher_config_bool(object, &["prerelease", "preRelease"]),
                github_api_url: publisher_config_api_url(object),
                github_auth_token: publisher_config_string(object, &["authToken", "auth_token"]),
                force_publish: publisher_config_bool(object, &["force"]),
                label,
            })
        }
        _ => None,
    }
}

fn publisher_target(label: &str) -> Option<PublishTarget> {
    let label = label.trim().to_ascii_lowercase();
    let compact = label
        .trim_start_matches("@electron-forge/")
        .trim_start_matches("electron-forge-")
        .trim_start_matches("publisher-");

    if compact == "github"
        || label.ends_with("/publisher-github")
        || label.ends_with("publisher-github")
    {
        Some(PublishTarget::Github)
    } else if compact == "local"
        || label.ends_with("/publisher-local")
        || label.ends_with("publisher-local")
    {
        Some(PublishTarget::Local)
    } else {
        None
    }
}

fn publisher_applies_to_platform(publisher: &ConfiguredPublisher, platform: &str) -> bool {
    publisher.platforms.is_empty()
        || publisher
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

fn publisher_config_string(object: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        publisher_config_value(object, key)
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn publisher_config_bool(object: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| publisher_config_value(object, key).and_then(JsonValue::as_bool))
}

fn publisher_config_value<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &str,
) -> Option<&'a JsonValue> {
    object
        .get("config")
        .and_then(JsonValue::as_object)
        .and_then(|config| config.get(key))
        .or_else(|| object.get(key))
}

fn publisher_config_github_repo(object: &JsonMap<String, JsonValue>) -> Option<String> {
    ["repository", "repo", "githubRepo", "github_repo"]
        .iter()
        .find_map(|key| publisher_config_value(object, key).and_then(github_repo_from_config_value))
}

fn github_repo_from_config_value(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        }
        JsonValue::Object(object) => {
            let owner = object
                .get("owner")
                .or_else(|| object.get("user"))
                .and_then(JsonValue::as_str)?
                .trim();
            let name = object
                .get("name")
                .or_else(|| object.get("repo"))
                .and_then(JsonValue::as_str)?
                .trim();
            if owner.is_empty() || name.is_empty() {
                None
            } else {
                Some(format!("{owner}/{name}"))
            }
        }
        _ => None,
    }
}

fn publisher_config_api_url(object: &JsonMap<String, JsonValue>) -> Option<String> {
    publisher_config_string(object, &["apiUrl", "api_url", "baseUrl", "base_url"]).or_else(|| {
        publisher_config_value(object, "octokitOptions")
            .and_then(JsonValue::as_object)
            .and_then(|octokit| {
                octokit
                    .get("baseUrl")
                    .or_else(|| octokit.get("base_url"))
                    .and_then(JsonValue::as_str)
            })
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

#[cfg(test)]
fn execute_publish(report: &mut PublishReport, args: &PublishArgs) -> Result<()> {
    if !args.skip_make {
        make::execute_make(&mut report.make, &make_args(args))?;
        report.make.mark_made()?;
    } else if !Path::new(report.make.artifact().as_str()).exists() {
        bail!(
            "Make artifact does not exist: {}. Run without --skip-make or run electron-cli make first.",
            report.make.artifact()
        );
    }

    let published_at_unix_seconds = now_unix_seconds()?;
    report.published_at_unix_seconds = Some(published_at_unix_seconds);
    execute_publish_destination(report, published_at_unix_seconds)?;
    report.status = PublishStatus::Published;

    Ok(())
}

fn execute_publish_reports(
    reports: &mut [PublishReport],
    make_reports: &mut [MakeReport],
    args: &PublishArgs,
) -> Result<()> {
    if !args.skip_make {
        make::execute_make_reports(make_reports, &make_args(args))?;
        sync_make_reports(reports, make_reports);
    } else {
        ensure_make_artifacts_exist(make_reports)?;
    }

    let published_at_unix_seconds = now_unix_seconds()?;
    for report in reports {
        report.published_at_unix_seconds = Some(published_at_unix_seconds);
        execute_publish_destination(report, published_at_unix_seconds)?;
        report.status = PublishStatus::Published;
    }

    Ok(())
}

fn sync_make_reports(reports: &mut [PublishReport], make_reports: &[MakeReport]) {
    for report in reports {
        if let Some(make) = make_reports
            .iter()
            .find(|make| make.artifact().as_str() == report.make.artifact().as_str())
        {
            report.make = make.clone();
        }
    }
}

fn ensure_make_artifacts_exist(make_reports: &[MakeReport]) -> Result<()> {
    for make in make_reports {
        if !Path::new(make.artifact().as_str()).exists() {
            bail!(
                "Make artifact does not exist: {}. Run without --skip-make or run electron-cli make first.",
                make.artifact()
            );
        }
    }
    Ok(())
}

fn execute_publish_destination(
    report: &mut PublishReport,
    published_at_unix_seconds: u64,
) -> Result<()> {
    match report.publisher_kind {
        PublishTarget::Local => execute_local_publish(report, published_at_unix_seconds),
        PublishTarget::Github => execute_github_publish(report),
    }
}

fn execute_local_publish(report: &PublishReport, published_at_unix_seconds: u64) -> Result<()> {
    let local = report
        .local
        .as_ref()
        .context("Local publish plan was not built")?;
    let destination_artifact = Path::new(local.destination_artifact.as_str());
    let manifest = Path::new(local.manifest.as_str());

    for path in [destination_artifact, manifest] {
        if path.exists() {
            if report.force_publish {
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

    fs::create_dir_all(local.destination_dir.as_str())
        .with_context(|| format!("Could not create {}", local.destination_dir))?;
    fs::copy(report.make.artifact().as_str(), destination_artifact).with_context(|| {
        format!(
            "Could not publish {} to {}",
            report.make.artifact(),
            destination_artifact.display()
        )
    })?;

    let manifest_json =
        serde_json::to_string_pretty(&build_manifest(report, published_at_unix_seconds)?)?;
    fs::write(manifest, format!("{manifest_json}\n"))
        .with_context(|| format!("Could not write {}", manifest.display()))?;

    Ok(())
}

fn execute_github_publish(report: &mut PublishReport) -> Result<()> {
    let token = github_token(report.github_auth_token.as_deref())?;
    let agent = github_agent();
    publish_to_github(report, &token, &agent)
}

#[derive(Debug, Serialize)]
struct CreateGithubRelease<'a> {
    tag_name: &'a str,
    name: &'a str,
    body: &'a str,
    draft: bool,
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    html_url: String,
    upload_url: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    id: u64,
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubErrorBody {
    message: Option<String>,
}

fn publish_to_github(report: &mut PublishReport, token: &str, agent: &ureq::Agent) -> Result<()> {
    let artifact_path = Path::new(report.make.artifact().as_str());
    let github = report
        .github
        .as_mut()
        .context("GitHub publish plan was not built")?;
    if github.repo.is_empty() || !valid_github_repo(&github.repo) {
        bail!("GitHub repository must be configured as OWNER/REPO.");
    }

    let release = get_or_create_github_release(agent, token, github)?;
    if let Some(asset) = release
        .assets
        .iter()
        .find(|asset| asset.name == github.artifact_name)
    {
        if report.force_publish {
            delete_github_asset(agent, token, github, asset.id)?;
        } else {
            bail!(
                "GitHub release asset already exists: {}. Use --force to replace it.",
                github.artifact_name
            );
        }
    }

    let asset = upload_github_asset(agent, token, github, &release.upload_url, artifact_path)?;
    github.release_url = Some(release.html_url);
    github.asset_url = Some(asset.browser_download_url);

    Ok(())
}

fn get_or_create_github_release(
    agent: &ureq::Agent,
    token: &str,
    github: &GithubPublishPlan,
) -> Result<GithubRelease> {
    let get_url = format!(
        "{}/repos/{}/releases/tags/{}",
        github.api_url,
        github.repo,
        encode_url_component(&github.tag)
    );
    let response = github_request(agent.get(&get_url), token)
        .call()
        .with_context(|| format!("Could not query GitHub release {}", github.tag))?;
    match response.status().as_u16() {
        200 => parse_github_response(response, "Could not parse GitHub release"),
        404 => create_github_release(agent, token, github),
        status => github_status_error(response, status, "Could not query GitHub release"),
    }
}

fn create_github_release(
    agent: &ureq::Agent,
    token: &str,
    github: &GithubPublishPlan,
) -> Result<GithubRelease> {
    let url = format!("{}/repos/{}/releases", github.api_url, github.repo);
    let body = format!(
        "{} {} {} artifact published by electron-cli.",
        github.artifact_name, github.tag, github.repo
    );
    let request = CreateGithubRelease {
        tag_name: &github.tag,
        name: &github.release_name,
        body: &body,
        draft: github.draft,
        prerelease: github.prerelease,
    };
    let response = github_request(agent.post(&url), token)
        .content_type("application/json")
        .send_json(&request)
        .with_context(|| format!("Could not create GitHub release {}", github.tag))?;
    let status = response.status().as_u16();
    if status == 201 {
        parse_github_response(response, "Could not parse created GitHub release")
    } else {
        github_status_error(response, status, "Could not create GitHub release")
    }
}

fn delete_github_asset(
    agent: &ureq::Agent,
    token: &str,
    github: &GithubPublishPlan,
    asset_id: u64,
) -> Result<()> {
    let url = format!(
        "{}/repos/{}/releases/assets/{}",
        github.api_url, github.repo, asset_id
    );
    let response = github_request(agent.delete(&url), token)
        .call()
        .with_context(|| format!("Could not delete GitHub release asset {asset_id}"))?;
    let status = response.status().as_u16();
    if status == 204 {
        Ok(())
    } else {
        github_status_error(response, status, "Could not delete GitHub release asset")
    }
}

fn upload_github_asset(
    agent: &ureq::Agent,
    token: &str,
    github: &GithubPublishPlan,
    upload_url: &str,
    artifact_path: &Path,
) -> Result<GithubAsset> {
    let url = github_asset_upload_url(upload_url, &github.artifact_name);
    let file = File::open(artifact_path)
        .with_context(|| format!("Could not open {}", artifact_path.display()))?;
    let response = github_request(agent.post(&url), token)
        .content_type("application/octet-stream")
        .send(file)
        .with_context(|| format!("Could not upload {}", artifact_path.display()))?;
    let status = response.status().as_u16();
    if status == 201 {
        parse_github_response(response, "Could not parse uploaded GitHub asset")
    } else {
        github_status_error(response, status, "Could not upload GitHub release asset")
    }
}

fn github_request<T>(request: ureq::RequestBuilder<T>, token: &str) -> ureq::RequestBuilder<T> {
    request
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {token}"))
        .header(
            "User-Agent",
            format!("electron-cli/{}", env!("CARGO_PKG_VERSION")),
        )
}

fn parse_github_response<T: DeserializeOwned>(
    mut response: ureq::http::Response<ureq::Body>,
    context: &str,
) -> Result<T> {
    response
        .body_mut()
        .read_json::<T>()
        .with_context(|| context.to_string())
}

fn github_status_error<T>(
    mut response: ureq::http::Response<ureq::Body>,
    status: u16,
    context: &str,
) -> Result<T> {
    let body = response.body_mut().read_to_string().unwrap_or_default();
    let message = serde_json::from_str::<GithubErrorBody>(&body)
        .ok()
        .and_then(|body| body.message)
        .filter(|message| !message.trim().is_empty())
        .unwrap_or(body);
    bail!("{context}: HTTP {status}: {message}")
}

fn github_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(300)))
        .build()
        .into()
}

fn github_token(configured_token: Option<&str>) -> Result<String> {
    configured_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .or_else(|| std::env::var("GH_TOKEN").ok())
        .context("GitHub publisher requires GITHUB_TOKEN or GH_TOKEN")
}

fn build_manifest(
    report: &PublishReport,
    published_at_unix_seconds: u64,
) -> Result<PublishManifest> {
    let local = report
        .local
        .as_ref()
        .context("Local publish manifest requires a local publish plan")?;
    let destination_artifact = Path::new(local.destination_artifact.as_str());
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
            path: local.destination_artifact.clone(),
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
    if let Some(local) = &report.local {
        println!("  artifact: {}", local.destination_artifact);
        println!("  manifest: {}", local.manifest);
    }
    if let Some(github) = &report.github {
        println!("  repository: {}", github.repo);
        println!("  tag: {}", github.tag);
        println!("  release: {}", github.release_name);
        println!("  artifact: {}", github.artifact_name);
        if let Some(url) = &github.release_url {
            println!("  release url: {url}");
        }
        if let Some(url) = &github.asset_url {
            println!("  asset url: {url}");
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

fn print_reports(reports: &[PublishReport], json: bool, status: PublishStatus) -> Result<()> {
    if reports.len() == 1 {
        return print_report(&reports[0], json);
    }

    let warnings = combined_warnings(reports);
    if json {
        return output::json(&PublishRunReport {
            publishes: reports,
            dry_run: reports.iter().any(|report| report.dry_run),
            status,
            warnings,
        });
    }

    println!("electron-cli publish");
    println!();
    if let Some(first) = reports.first() {
        println!("Project");
        println!("  root: {}", first.make.package().project().root);
        match first.make.package().project().package_label() {
            Some(label) => println!("  package: {label}"),
            None => println!("  package: not found"),
        }
        println!("  app name: {}", first.make.package().app_name());
        println!(
            "  target platform: {} {}",
            first.make.package().platform(),
            first.make.package().arch()
        );
        println!("  status: {}", status.as_str());
    }

    println!();
    println!("Publishes");
    for report in reports {
        println!(
            "  {} {}: {}",
            report.publisher,
            report.make.target(),
            report.make.artifact()
        );
        if let Some(local) = &report.local {
            println!("    artifact: {}", local.destination_artifact);
            println!("    manifest: {}", local.manifest);
        }
        if let Some(github) = &report.github {
            println!("    repository: {}", github.repo);
            println!("    tag: {}", github.tag);
            if let Some(url) = &github.release_url {
                println!("    release url: {url}");
            }
            if let Some(url) = &github.asset_url {
                println!("    asset url: {url}");
            }
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

fn combined_warnings(reports: &[PublishReport]) -> Vec<String> {
    let mut warnings = Vec::new();
    for warning in reports.iter().flat_map(|report| report.warnings.iter()) {
        if !warnings.contains(warning) {
            warnings.push(warning.clone());
        }
    }
    warnings
}

fn resolve_destination(root: &Path, destination: &Path) -> PathBuf {
    if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        root.join(destination)
    }
}

fn default_github_tag(make: &MakeReport, channel: &str, tag_prefix: Option<&str>) -> String {
    make.package()
        .project()
        .version
        .as_deref()
        .map(|version| {
            let prefix = tag_prefix.unwrap_or("v");
            if prefix.is_empty() || version.starts_with(prefix) {
                version.to_string()
            } else {
                format!("{prefix}{version}")
            }
        })
        .unwrap_or_else(|| channel.to_string())
}

fn valid_github_repo(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let Some(owner) = parts.next() else {
        return false;
    };
    let Some(name) = parts.next() else {
        return false;
    };
    parts.next().is_none() && valid_github_path_part(owner) && valid_github_path_part(name)
}

fn valid_github_path_part(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_' | '.'))
}

fn github_repo_from_repository(repository: &str) -> Option<String> {
    let mut value = repository.trim().trim_start_matches("git+").to_string();
    if let Some(fragment) = value.find('#') {
        value.truncate(fragment);
    }
    let value = value.trim_end_matches(".git");
    let path = value
        .split_once("github.com:")
        .map(|(_, path)| path)
        .or_else(|| value.split_once("github.com/").map(|(_, path)| path))?;
    let mut parts = path.trim_matches('/').split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        None
    } else {
        Some(format!("{owner}/{repo}"))
    }
}

fn github_asset_upload_url(upload_url: &str, artifact_name: &str) -> String {
    let base = upload_url.split('{').next().unwrap_or(upload_url);
    let separator = if base.contains('?') { '&' } else { '?' };
    format!(
        "{base}{separator}name={}",
        encode_url_component(artifact_name)
    )
}

fn encode_url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread,
    };

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
        let local = report.local.as_ref().expect("local plan should exist");
        assert!(Path::new(local.destination_artifact.as_str()).ends_with(
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

        let local = report.local.as_ref().expect("local plan should exist");
        assert!(Path::new(local.destination_artifact.as_str()).exists());
        assert!(Path::new(local.manifest.as_str()).exists());
        let manifest = fs::read_to_string(local.manifest.as_str()).expect("manifest should read");
        assert!(manifest.contains("\"publisher\": \"local\""));
        assert!(manifest.contains("\"app_name\": \"starter-app\""));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_github_publish_report_from_package_repository() {
        let root = unique_temp_dir("github-plan");
        write_github_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let args = github_publish_args(root.clone(), true, "http://127.0.0.1:9");
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.publisher, "github");
        assert!(report.local.is_none());
        let github = report.github.as_ref().expect("github plan should exist");
        assert_eq!(github.repo, "Ikana/electron-cli");
        assert_eq!(github.tag, "v0.1.0");
        assert_eq!(github.release_name, "v0.1.0");
        assert!(!github.draft);
        assert!(!github.prerelease);
        assert_eq!(
            github.artifact_name,
            format!(
                "starter-app-{}-{}.zip",
                report.make.package().platform(),
                report.make.package().arch()
            )
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_github_publish_report_from_configured_forge_publisher() {
        let root = unique_temp_dir("configured-github-plan");
        write_package_json_with_publishers(
            &root,
            r#"[
                {
                    "name":"@electron-forge/publisher-github",
                    "platforms":["*"],
                    "config":{
                        "repository":{"owner":"Ikana","name":"electron-cli"},
                        "draft":true,
                        "prerelease":true,
                        "tagPrefix":"release-",
                        "releaseName":"Configured Release",
                        "baseUrl":"http://127.0.0.1:9"
                    }
                }
            ]"#,
        );
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let mut args = publish_args(root.clone(), true);
        args.target = None;
        args.publisher = None;
        args.github_api_url = None;
        args.channel = None;
        let report = build_report(&args).expect("report should build");

        assert_eq!(report.publisher, "github");
        assert!(report.local.is_none());
        assert_eq!(report.channel, "default");
        let github = report.github.as_ref().expect("github plan should exist");
        assert_eq!(github.repo, "Ikana/electron-cli");
        assert_eq!(github.tag, "release-0.1.0");
        assert_eq!(github.release_name, "Configured Release");
        assert!(github.draft);
        assert!(github.prerelease);
        assert_eq!(github.api_url, "http://127.0.0.1:9");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn builds_publish_reports_from_configured_makers_and_publishers() {
        let root = unique_temp_dir("configured-publishers");
        write_package_json_with_makers_and_publishers(
            &root,
            r#"[
                {"name":"@electron-forge/maker-zip"},
                {"name":"@electron-forge/maker-deb","platforms":["linux"]}
            ]"#,
            r#"[
                {"name":"@electron-forge/publisher-github","config":{"repository":"Ikana/electron-cli"}},
                {"name":"local","config":{"to":"dist/publish","channel":"beta"}},
                {"name":"@electron-forge/publisher-s3"}
            ]"#,
        );
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let mut args = publish_args(root.clone(), true);
        args.platform = Some("linux".to_string());
        args.arch = Some("x64".to_string());
        args.target = None;
        args.publisher = None;
        args.to = None;
        args.channel = None;
        args.github_api_url = None;
        let reports = build_reports(&args).expect("reports should build");

        assert_eq!(reports.len(), 4);
        assert_eq!(reports[0].publisher, "github");
        assert_eq!(reports[0].make.target(), "zip");
        assert_eq!(reports[1].publisher, "github");
        assert_eq!(reports[1].make.target(), "deb");
        assert_eq!(reports[2].publisher, "local");
        assert_eq!(reports[2].make.target(), "zip");
        assert_eq!(reports[3].publisher, "local");
        assert_eq!(reports[3].make.target(), "deb");
        let local = reports[2].local.as_ref().expect("local plan should exist");
        let local_parent = Path::new(local.destination_artifact.as_str())
            .parent()
            .expect("local artifact should have parent");
        assert!(local_parent.ends_with(
            PathBuf::from("dist")
                .join("publish")
                .join("beta")
                .join("linux")
                .join("x64")
        ));
        assert!(reports[0]
            .warnings
            .iter()
            .any(|warning| warning.contains("@electron-forge/publisher-s3")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn publishes_make_artifact_to_github_release() {
        let server = MockGithubServer::new(3);
        let root = unique_temp_dir("github-execute");
        write_github_package_json(&root);
        write_app_file(&root);
        write_fake_electron_dist(&root);

        let mut args = github_publish_args(root.clone(), false, &server.api_url);
        args.skip_make = true;
        let mut report = build_report(&args).expect("report should build");
        let artifact = Path::new(report.make.artifact().as_str());
        fs::create_dir_all(artifact.parent().expect("artifact parent should exist"))
            .expect("artifact parent should be created");
        fs::write(artifact, b"artifact bytes").expect("artifact should be written");

        let agent = github_agent();
        publish_to_github(&mut report, "test-token", &agent)
            .expect("github publish should succeed");

        let github = report.github.as_ref().expect("github plan should exist");
        let artifact_name = github.artifact_name.clone();
        assert_eq!(
            github.release_url.as_deref(),
            Some("https://github.com/Ikana/electron-cli/releases/tag/v0.1.0")
        );
        assert_eq!(
            github.asset_url.as_deref(),
            Some("https://github.com/Ikana/electron-cli/releases/download/v0.1.0/starter-app.zip")
        );

        let requests = server.finish();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(
            requests[0].path,
            "/repos/Ikana/electron-cli/releases/tags/v0.1.0"
        );
        assert_eq!(
            requests[0].header("authorization").as_deref(),
            Some("Bearer test-token")
        );
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].path, "/repos/Ikana/electron-cli/releases");
        let release_body =
            String::from_utf8(requests[1].body.clone()).expect("release body should be utf-8");
        assert!(release_body.contains("\"tag_name\": \"v0.1.0\""));
        assert_eq!(requests[2].method, "POST");
        assert_eq!(
            requests[2].path,
            format!("/uploads/1?name={}", encode_url_component(&artifact_name))
        );
        assert_eq!(requests[2].body, b"artifact bytes");

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

    #[test]
    fn parses_github_repository_urls() {
        assert_eq!(
            github_repo_from_repository("git+https://github.com/Ikana/electron-cli.git"),
            Some("Ikana/electron-cli".to_string())
        );
        assert_eq!(
            github_repo_from_repository("git@github.com:Ikana/electron-cli.git"),
            Some("Ikana/electron-cli".to_string())
        );
        assert_eq!(
            github_repo_from_repository("https://example.com/Ikana/electron-cli.git"),
            None
        );
    }

    fn publish_args(root: PathBuf, dry_run: bool) -> PublishArgs {
        PublishArgs {
            cwd: root,
            out_dir: PathBuf::from("out"),
            name: None,
            platform: None,
            arch: None,
            target: Some(crate::cli::MakeTarget::Zip),
            publisher: Some(crate::cli::PublishTarget::Local),
            to: Some(PathBuf::from("out/publish/local")),
            github_repo: None,
            github_tag: None,
            github_release_name: None,
            github_draft: false,
            github_prerelease: false,
            github_api_url: Some("https://api.github.com".to_string()),
            channel: Some("default".to_string()),
            skip_make: false,
            force: false,
            dry_run,
            json: true,
        }
    }

    fn github_publish_args(root: PathBuf, dry_run: bool, api_url: &str) -> PublishArgs {
        let mut args = publish_args(root, dry_run);
        args.publisher = Some(crate::cli::PublishTarget::Github);
        args.github_api_url = Some(api_url.to_string());
        args
    }

    fn write_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","main":"src/main.js","devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
    }

    fn write_github_package_json(root: &Path) {
        fs::write(
            root.join("package.json"),
            r#"{"name":"starter-app","version":"0.1.0","repository":{"type":"git","url":"git+https://github.com/Ikana/electron-cli.git"},"main":"src/main.js","devDependencies":{"electron":"30.0.0"}}"#,
        )
        .expect("package.json should be written");
    }

    fn write_package_json_with_publishers(root: &Path, publishers: &str) {
        fs::write(
            root.join("package.json"),
            format!(
                r#"{{
                    "name":"starter-app",
                    "version":"0.1.0",
                    "main":"src/main.js",
                    "devDependencies":{{"electron":"30.0.0"}},
                    "config":{{"forge":{{"publishers":{publishers}}}}}
                }}"#
            ),
        )
        .expect("package.json with publishers should be written");
    }

    fn write_package_json_with_makers_and_publishers(root: &Path, makers: &str, publishers: &str) {
        fs::write(
            root.join("package.json"),
            format!(
                r#"{{
                    "name":"starter-app",
                    "version":"0.1.0",
                    "main":"src/main.js",
                    "devDependencies":{{"electron":"30.0.0"}},
                    "config":{{"forge":{{"makers":{makers},"publishers":{publishers}}}}}
                }}"#
            ),
        )
        .expect("package.json with makers and publishers should be written");
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

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl RecordedRequest {
        fn header(&self, name: &str) -> Option<String> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        }
    }

    struct MockGithubServer {
        api_url: String,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockGithubServer {
        fn new(request_count: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("server should bind");
            let address = listener.local_addr().expect("server address should read");
            let api_url = format!("http://{address}");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let thread_requests = Arc::clone(&requests);
            let thread_api_url = api_url.clone();
            let handle = thread::spawn(move || {
                for index in 0..request_count {
                    let (mut stream, _) = listener.accept().expect("request should connect");
                    let request = read_http_request(&mut stream);
                    thread_requests
                        .lock()
                        .expect("requests should lock")
                        .push(request);

                    match index {
                        0 => write_http_response(&mut stream, 404, r#"{"message":"Not Found"}"#),
                        1 => write_http_response(
                            &mut stream,
                            201,
                            &format!(
                                r#"{{
                                    "html_url":"https://github.com/Ikana/electron-cli/releases/tag/v0.1.0",
                                    "upload_url":"{}/uploads/1{{?name,label}}",
                                    "assets":[]
                                }}"#,
                                thread_api_url
                            ),
                        ),
                        _ => write_http_response(
                            &mut stream,
                            201,
                            r#"{
                                "id":42,
                                "name":"starter-app",
                                "browser_download_url":"https://github.com/Ikana/electron-cli/releases/download/v0.1.0/starter-app.zip"
                            }"#,
                        ),
                    }
                }
            });

            Self {
                api_url,
                requests,
                handle: Some(handle),
            }
        }

        fn finish(mut self) -> Vec<RecordedRequest> {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("server thread should finish");
            }
            self.requests.lock().expect("requests should lock").clone()
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> RecordedRequest {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut buffer = [0; 1024];
            let read = stream.read(&mut buffer).expect("request should read");
            assert!(read > 0, "connection closed before request headers");
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };

        let headers_text =
            String::from_utf8(bytes[..header_end].to_vec()).expect("headers should be utf-8");
        let mut lines = headers_text.split("\r\n");
        let request_line = lines.next().expect("request line should exist");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .expect("request method should exist")
            .to_string();
        let path = request_parts
            .next()
            .expect("request path should exist")
            .to_string();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
            .collect::<Vec<_>>();
        let content_length = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let mut buffer = [0; 1024];
            let read = stream.read(&mut buffer).expect("request body should read");
            assert!(read > 0, "connection closed before request body");
            bytes.extend_from_slice(&buffer[..read]);
        }
        let body = bytes[header_end..header_end + content_length].to_vec();

        RecordedRequest {
            method,
            path,
            headers,
            body,
        }
    }

    fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) {
        let reason = match status {
            201 => "Created",
            404 => "Not Found",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("response should write");
    }
}
