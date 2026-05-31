use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde_json::Value as JsonValue;

use crate::project::ProjectSnapshot;

#[derive(Clone, Debug, Default)]
pub(crate) struct ProjectConfig {
    package: Option<JsonValue>,
    forge: Option<JsonValue>,
    electron_cli: Option<JsonValue>,
    warnings: Vec<String>,
}

pub(crate) fn read(snapshot: &ProjectSnapshot) -> Result<ProjectConfig> {
    let package = read_package_json(snapshot)?;
    let root = Path::new(snapshot.root.as_str());
    let mut warnings = Vec::new();
    let forge = resolve_forge_config(root, package.as_ref(), &mut warnings);
    let electron_cli = package
        .as_ref()
        .and_then(|package| {
            package
                .get("electronCli")
                .or_else(|| package.get("electron-cli"))
        })
        .cloned();

    Ok(ProjectConfig {
        package,
        forge,
        electron_cli,
        warnings,
    })
}

fn read_package_json(snapshot: &ProjectSnapshot) -> Result<Option<JsonValue>> {
    let Some(package_json_path) = &snapshot.package_json else {
        return Ok(None);
    };
    let package_json_path = Path::new(package_json_path.as_str());
    let raw = fs::read_to_string(package_json_path)
        .with_context(|| format!("Could not read {}", package_json_path.display()))?;
    serde_json::from_str::<JsonValue>(&raw)
        .with_context(|| format!("Could not parse {}", package_json_path.display()))
        .map(Some)
}

fn resolve_forge_config(
    root: &Path,
    package: Option<&JsonValue>,
    warnings: &mut Vec<String>,
) -> Option<JsonValue> {
    match package
        .and_then(|package| package.get("config"))
        .and_then(|config| config.get("forge"))
    {
        Some(JsonValue::Object(_)) => {
            return package
                .and_then(|package| package.get("config"))
                .and_then(|config| config.get("forge"))
                .cloned()
        }
        Some(JsonValue::String(path)) => {
            return read_forge_config_file(root, Path::new(path), warnings);
        }
        Some(_) => {
            warnings.push(
                "package.json config.forge must be an object or relative config file path."
                    .to_string(),
            );
            return None;
        }
        None => {}
    }

    for candidate in [
        "forge.config.js",
        "forge.config.cjs",
        "forge.config.mjs",
        "forge.config.ts",
    ] {
        let path = root.join(candidate);
        if path.exists() {
            return read_forge_config_file(root, &PathBuf::from(candidate), warnings);
        }
    }

    None
}

fn read_forge_config_file(
    root: &Path,
    configured_path: &Path,
    warnings: &mut Vec<String>,
) -> Option<JsonValue> {
    let path = if configured_path.is_absolute() {
        configured_path.to_path_buf()
    } else {
        root.join(configured_path)
    };
    let display = path.display();

    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            warnings.push(format!(
                "Could not read Forge config file {display}: {error}."
            ));
            return None;
        }
    };

    match parse_forge_config_file(&raw, &path) {
        Ok(config) => Some(config),
        Err(error) => {
            warnings.push(format!(
                "Could not parse Forge config file {display} without JavaScript execution: {error}."
            ));
            None
        }
    }
}

fn parse_forge_config_file(raw: &str, path: &Path) -> Result<JsonValue> {
    if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
        return serde_json::from_str(raw).with_context(|| "Forge JSON config is not valid JSON");
    }

    let object_literal = extract_static_config_object(raw)
        .ok_or_else(|| anyhow!("expected a static object export"))?;
    json5::from_str::<JsonValue>(&object_literal)
        .with_context(|| "static Forge config object is not valid JSON5")
}

fn extract_static_config_object(source: &str) -> Option<String> {
    for marker in ["module.exports", "exports.default"] {
        if let Some(object) = extract_assignment_object(source, marker) {
            return Some(object);
        }
    }

    if let Some(object) = extract_export_default_object(source) {
        return Some(object);
    }

    if let Some(identifier) = export_default_identifier(source)
        .or_else(|| assignment_identifier(source, "module.exports"))
        .or_else(|| assignment_identifier(source, "exports.default"))
    {
        return extract_variable_object(source, &identifier);
    }

    None
}

fn extract_assignment_object(source: &str, marker: &str) -> Option<String> {
    let marker_index = source.find(marker)?;
    let after_marker = &source[marker_index + marker.len()..];
    let equals = after_marker.find('=')?;
    let after_equals_start = marker_index + marker.len() + equals + 1;
    let object_start = find_next_object_start(source, after_equals_start)?;
    extract_balanced_object(source, object_start)
}

fn extract_export_default_object(source: &str) -> Option<String> {
    let marker = "export default";
    let marker_index = source.find(marker)?;
    let after_marker = marker_index + marker.len();
    let object_start = find_next_object_start(source, after_marker)?;
    let identifier = read_identifier(source, skip_whitespace(source, after_marker)).0;
    if identifier.is_some() {
        return None;
    }
    extract_balanced_object(source, object_start)
}

fn export_default_identifier(source: &str) -> Option<String> {
    let marker = "export default";
    let marker_index = source.find(marker)?;
    let start = skip_whitespace(source, marker_index + marker.len());
    read_identifier(source, start).0
}

fn assignment_identifier(source: &str, marker: &str) -> Option<String> {
    let marker_index = source.find(marker)?;
    let after_marker = &source[marker_index + marker.len()..];
    let equals = after_marker.find('=')?;
    let start = skip_whitespace(source, marker_index + marker.len() + equals + 1);
    read_identifier(source, start).0
}

fn extract_variable_object(source: &str, identifier: &str) -> Option<String> {
    for keyword in ["const", "let", "var"] {
        for (keyword_index, _) in source.match_indices(keyword) {
            if !is_word_boundary(source, keyword_index, keyword.len()) {
                continue;
            }
            let start = skip_whitespace(source, keyword_index + keyword.len());
            let (name, after_name) = read_identifier(source, start);
            if name.as_deref() != Some(identifier) {
                continue;
            }
            let rest = &source[after_name..];
            let equals = rest.find('=')?;
            let object_start = find_next_object_start(source, after_name + equals + 1)?;
            return extract_balanced_object(source, object_start);
        }
    }

    None
}

fn find_next_object_start(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => return Some(index),
            b';' | b'\n' if !source[start..index].trim().is_empty() => return None,
            _ => index += 1,
        }
    }
    None
}

fn extract_balanced_object(source: &str, object_start: usize) -> Option<String> {
    let bytes = source.as_bytes();
    let mut index = object_start;
    let mut depth = 0usize;
    let mut state = ScanState::Normal;

    while index < bytes.len() {
        match state {
            ScanState::Normal => match bytes[index] {
                b'{' => {
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    depth = depth.checked_sub(1)?;
                    index += 1;
                    if depth == 0 {
                        return Some(source[object_start..index].to_string());
                    }
                }
                b'\'' | b'"' | b'`' => {
                    state = ScanState::String(bytes[index]);
                    index += 1;
                }
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    state = ScanState::LineComment;
                    index += 2;
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    state = ScanState::BlockComment;
                    index += 2;
                }
                _ => index += 1,
            },
            ScanState::String(quote) => {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == quote {
                    state = ScanState::Normal;
                    index += 1;
                } else {
                    index += 1;
                }
            }
            ScanState::LineComment => {
                if bytes[index] == b'\n' {
                    state = ScanState::Normal;
                }
                index += 1;
            }
            ScanState::BlockComment => {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    state = ScanState::Normal;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        }
    }

    None
}

fn skip_whitespace(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut index = start;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn read_identifier(source: &str, start: usize) -> (Option<String>, usize) {
    let bytes = source.as_bytes();
    if bytes.get(start).is_none_or(|byte| !identifier_start(*byte)) {
        return (None, start);
    }

    let mut index = start + 1;
    while index < bytes.len() && identifier_continue(bytes[index]) {
        index += 1;
    }

    (Some(source[start..index].to_string()), index)
}

fn is_word_boundary(source: &str, start: usize, len: usize) -> bool {
    let bytes = source.as_bytes();
    let before = start
        .checked_sub(1)
        .and_then(|index| bytes.get(index))
        .copied();
    let after = bytes.get(start + len).copied();
    before.is_none_or(|byte| !identifier_continue(byte))
        && after.is_none_or(|byte| !identifier_continue(byte))
}

fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

#[derive(Clone, Copy, Debug)]
enum ScanState {
    Normal,
    String(u8),
    LineComment,
    BlockComment,
}

impl ProjectConfig {
    pub(crate) fn package(&self) -> Option<&JsonValue> {
        self.package.as_ref()
    }

    pub(crate) fn forge(&self) -> Option<&JsonValue> {
        self.forge.as_ref()
    }

    pub(crate) fn electron_cli(&self) -> Option<&JsonValue> {
        self.electron_cli.as_ref()
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    #[test]
    fn parses_commonjs_static_forge_config() {
        let config = parse_forge_config_file(
            r#"
            module.exports = {
              packagerConfig: {
                name: 'Desk Tool',
              },
              makers: [
                { name: '@electron-forge/maker-zip' },
              ],
            };
            "#,
            Path::new("forge.config.js"),
        )
        .expect("config should parse");

        assert_eq!(
            config
                .get("packagerConfig")
                .and_then(|config| config.get("name"))
                .and_then(JsonValue::as_str),
            Some("Desk Tool")
        );
    }

    #[test]
    fn parses_typescript_exported_config_identifier() {
        let config = parse_forge_config_file(
            r#"
            import type { ForgeConfig } from '@electron-forge/shared-types';

            const config: ForgeConfig = {
              publishers: [
                {
                  name: '@electron-forge/publisher-github',
                  platforms: ['darwin'],
                  config: { repository: { owner: 'Ikana', name: 'electron-cli' } },
                },
              ],
            };

            export default config;
            "#,
            Path::new("forge.config.ts"),
        )
        .expect("config should parse");

        assert_eq!(
            config
                .get("publishers")
                .and_then(JsonValue::as_array)
                .and_then(|publishers| publishers.first())
                .and_then(|publisher| publisher.get("platforms"))
                .and_then(JsonValue::as_array)
                .and_then(|platforms| platforms.first())
                .and_then(JsonValue::as_str),
            Some("darwin")
        );
    }

    #[test]
    fn reads_config_path_from_package_json() {
        let root = unique_temp_dir("config-path");
        fs::write(
            root.join("package.json"),
            r#"{"name":"app","config":{"forge":"./build/forge.config.js"}}"#,
        )
        .expect("package.json should be written");
        fs::create_dir_all(root.join("build")).expect("build dir should be created");
        fs::write(
            root.join("build/forge.config.js"),
            "module.exports = { makers: [{ name: '@electron-forge/maker-deb' }] };",
        )
        .expect("forge config should be written");

        let snapshot = snapshot(&root);
        let config = read(&snapshot).expect("config should read");

        assert_eq!(
            config
                .forge()
                .and_then(|forge| forge.get("makers"))
                .and_then(JsonValue::as_array)
                .and_then(|makers| makers.first())
                .and_then(|maker| maker.get("name"))
                .and_then(JsonValue::as_str),
            Some("@electron-forge/maker-deb")
        );
        assert!(config.warnings().is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovers_default_forge_config_js() {
        let root = unique_temp_dir("default-config");
        fs::write(root.join("package.json"), r#"{"name":"app"}"#)
            .expect("package.json should be written");
        fs::write(
            root.join("forge.config.js"),
            "module.exports = { packagerConfig: { executableName: 'desk-tool' } };",
        )
        .expect("forge config should be written");

        let snapshot = snapshot(&root);
        let config = read(&snapshot).expect("config should read");

        assert_eq!(
            config
                .forge()
                .and_then(|forge| forge.get("packagerConfig"))
                .and_then(|packager| packager.get("executableName"))
                .and_then(JsonValue::as_str),
            Some("desk-tool")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn warns_when_config_requires_javascript_execution() {
        let root = unique_temp_dir("dynamic-config");
        fs::write(root.join("package.json"), r#"{"name":"app"}"#)
            .expect("package.json should be written");
        fs::write(
            root.join("forge.config.js"),
            "module.exports = buildConfig(process.env.NODE_ENV);",
        )
        .expect("forge config should be written");

        let snapshot = snapshot(&root);
        let config = read(&snapshot).expect("config should read");

        assert!(config.forge().is_none());
        assert!(config
            .warnings()
            .iter()
            .any(|warning| warning.contains("without JavaScript execution")));

        let _ = fs::remove_dir_all(root);
    }

    fn snapshot(root: &Path) -> ProjectSnapshot {
        ProjectSnapshot {
            root: Utf8PathBuf::from_path_buf(root.to_path_buf()).expect("root should be utf-8"),
            package_json: Some(
                Utf8PathBuf::from_path_buf(root.join("package.json"))
                    .expect("package path should be utf-8"),
            ),
            name: Some("app".to_string()),
            version: None,
            repository: None,
            license: None,
            main: Some("src/main.js".to_string()),
            package_manager: None,
            scripts: Default::default(),
            dependencies: Default::default(),
            dev_dependencies: Default::default(),
            optional_dependencies: Default::default(),
            peer_dependencies: Default::default(),
            electron_dependency: Some("30.0.0".to_string()),
            forge_dependencies: Default::default(),
            signals: Vec::new(),
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "electron-cli-forge-config-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }
}
