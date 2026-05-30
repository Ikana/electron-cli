use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct ProjectSnapshot {
    pub root: Utf8PathBuf,
    pub package_json: Option<Utf8PathBuf>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub main: Option<String>,
    pub package_manager: Option<String>,
    pub scripts: BTreeMap<String, String>,
    pub dependencies: BTreeMap<String, String>,
    pub dev_dependencies: BTreeMap<String, String>,
    pub optional_dependencies: BTreeMap<String, String>,
    pub peer_dependencies: BTreeMap<String, String>,
    pub electron_dependency: Option<String>,
    pub forge_dependencies: BTreeMap<String, String>,
    pub signals: Vec<String>,
}

impl ProjectSnapshot {
    pub fn package_label(&self) -> Option<String> {
        match (&self.name, &self.version) {
            (Some(name), Some(version)) => Some(format!("{name}@{version}")),
            (Some(name), None) => Some(name.clone()),
            (None, Some(version)) => Some(format!("version {version}")),
            (None, None) => None,
        }
    }

    pub fn has_javascript_dependencies(&self) -> bool {
        !self.dependencies.is_empty()
            || !self.dev_dependencies.is_empty()
            || !self.optional_dependencies.is_empty()
            || !self.peer_dependencies.is_empty()
    }
}

pub fn inspect(cwd: &Path) -> Result<ProjectSnapshot> {
    let cwd = cwd
        .canonicalize()
        .with_context(|| format!("Could not resolve {}", cwd.display()))?;

    let package_json_path = find_upwards(&cwd, "package.json");
    let root = package_json_path
        .as_ref()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or(cwd);

    let package_json = match &package_json_path {
        Some(path) => {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("Could not read {}", path.display()))?;
            Some(
                serde_json::from_str::<Value>(&raw)
                    .with_context(|| format!("Could not parse {}", path.display()))?,
            )
        }
        None => None,
    };

    let scripts = package_json
        .as_ref()
        .map(|package| string_map(package.get("scripts")))
        .unwrap_or_default();

    let dependencies = package_json
        .as_ref()
        .map(|package| string_map(package.get("dependencies")))
        .unwrap_or_default();

    let dev_dependencies = package_json
        .as_ref()
        .map(|package| string_map(package.get("devDependencies")))
        .unwrap_or_default();

    let optional_dependencies = package_json
        .as_ref()
        .map(|package| string_map(package.get("optionalDependencies")))
        .unwrap_or_default();

    let peer_dependencies = package_json
        .as_ref()
        .map(|package| string_map(package.get("peerDependencies")))
        .unwrap_or_default();

    let all_dependencies = merge_dependencies([
        &dependencies,
        &dev_dependencies,
        &optional_dependencies,
        &peer_dependencies,
    ]);

    let electron_dependency = all_dependencies.get("electron").cloned();
    let forge_dependencies = all_dependencies
        .iter()
        .filter(|(name, _)| name.starts_with("@electron-forge/"))
        .map(|(name, version)| (name.clone(), version.clone()))
        .collect::<BTreeMap<_, _>>();

    let package_manager = detect_package_manager(&root);
    let signals = build_signals(
        &scripts,
        &all_dependencies,
        electron_dependency.as_ref(),
        &forge_dependencies,
    );

    Ok(ProjectSnapshot {
        root: utf8_path(root)?,
        package_json: package_json_path.map(utf8_path).transpose()?,
        name: package_json
            .as_ref()
            .and_then(|package| package.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        version: package_json
            .as_ref()
            .and_then(|package| package.get("version"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        main: package_json
            .as_ref()
            .and_then(|package| package.get("main"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        package_manager,
        scripts,
        dependencies,
        dev_dependencies,
        optional_dependencies,
        peer_dependencies,
        electron_dependency,
        forge_dependencies,
        signals,
    })
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
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

fn merge_dependencies<'a>(
    groups: impl IntoIterator<Item = &'a BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();

    for group in groups {
        for (name, version) in group {
            merged.insert(name.clone(), version.clone());
        }
    }

    merged
}

fn detect_package_manager(root: &Path) -> Option<String> {
    [
        ("package-lock.json", "npm"),
        ("npm-shrinkwrap.json", "npm"),
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
    ]
    .iter()
    .find_map(|(file, manager)| root.join(file).exists().then(|| manager.to_string()))
}

fn build_signals(
    scripts: &BTreeMap<String, String>,
    dependencies: &BTreeMap<String, String>,
    electron_dependency: Option<&String>,
    forge_dependencies: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut signals = Vec::new();

    if electron_dependency.is_some() {
        signals.push("electron dependency declared".to_string());
    }

    if !forge_dependencies.is_empty() {
        signals.push("electron forge dependency declared".to_string());
    }

    if dependencies.contains_key("vite") || dependencies.contains_key("@vitejs/plugin-react") {
        signals.push("vite tooling detected".to_string());
    }

    if dependencies.contains_key("typescript") {
        signals.push("typescript tooling detected".to_string());
    }

    if scripts
        .values()
        .any(|script| script.contains("electron") || script.contains("electron-forge"))
    {
        signals.push("electron command found in package scripts".to_string());
    }

    signals
}

fn find_upwards(start: &Path, file_name: &str) -> Option<PathBuf> {
    let mut current = Some(start);

    while let Some(path) = current {
        let candidate = path.join(file_name);
        if candidate.exists() {
            return Some(candidate);
        }

        current = path.parent();
    }

    None
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

    #[test]
    fn maps_string_values_only() {
        let value = serde_json::json!({
            "electron": "^30.0.0",
            "bad": false
        });

        let map = string_map(Some(&value));

        assert_eq!(map.get("electron"), Some(&"^30.0.0".to_string()));
        assert!(!map.contains_key("bad"));
    }

    #[test]
    fn builds_electron_signals() {
        let mut scripts = BTreeMap::new();
        scripts.insert("start".to_string(), "electron-forge start".to_string());

        let mut dependencies = BTreeMap::new();
        dependencies.insert("electron".to_string(), "^30.0.0".to_string());
        dependencies.insert("@electron-forge/cli".to_string(), "^7.0.0".to_string());
        dependencies.insert("typescript".to_string(), "^5.0.0".to_string());

        let forge = dependencies
            .iter()
            .filter(|(name, _)| name.starts_with("@electron-forge/"))
            .map(|(name, version)| (name.clone(), version.clone()))
            .collect::<BTreeMap<_, _>>();

        let signals = build_signals(
            &scripts,
            &dependencies,
            dependencies.get("electron"),
            &forge,
        );

        assert!(signals.contains(&"electron dependency declared".to_string()));
        assert!(signals.contains(&"electron forge dependency declared".to_string()));
        assert!(signals.contains(&"typescript tooling detected".to_string()));
        assert!(signals.contains(&"electron command found in package scripts".to_string()));
    }

    #[test]
    fn inspects_electron_forge_fixture_from_nested_directory() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/electron-forge");
        let nested = fixture.join("src");

        let snapshot = inspect(&nested).expect("fixture should inspect");

        assert_eq!(snapshot.name.as_deref(), Some("fixture-electron-forge-app"));
        assert_eq!(snapshot.version.as_deref(), Some("0.1.0"));
        assert_eq!(snapshot.main.as_deref(), Some("src/main.ts"));
        assert_eq!(snapshot.package_manager.as_deref(), Some("npm"));
        assert_eq!(snapshot.electron_dependency.as_deref(), Some("^31.0.0"));
        assert_eq!(
            snapshot
                .forge_dependencies
                .get("@electron-forge/cli")
                .map(String::as_str),
            Some("^7.0.0")
        );
        assert!(snapshot.has_javascript_dependencies());
        assert!(snapshot
            .signals
            .contains(&"electron forge dependency declared".to_string()));
        assert!(snapshot
            .signals
            .contains(&"electron command found in package scripts".to_string()));
    }
}
