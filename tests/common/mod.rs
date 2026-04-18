use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

pub struct EphemeralTestConfig {
    pub temp_dir: tempfile::TempDir,
    pub config_path: PathBuf,
}

fn set_string_value(root: &mut toml::Value, section: &str, key: &str, value: String) -> Result<()> {
    let table = root
        .get_mut(section)
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("Missing [{}] section in config", section))?;
    table.insert(key.to_string(), toml::Value::String(value));
    Ok(())
}

pub fn create_ephemeral_test_config() -> Result<EphemeralTestConfig> {
    let base_config = std::fs::read_to_string("config.toml")
        .context("Failed to read config.toml from repository root")?;
    let mut config_value: toml::Value =
        toml::from_str(&base_config).context("Failed to parse config.toml into TOML value")?;

    let temp_dir = tempfile::Builder::new()
        .prefix("pki-chain-tests-")
        .tempdir()
        .context("Failed to create temporary test directory")?;
    let temp_root = temp_dir.path();

    let certificate_path = temp_root.join("data/certificates");
    let private_key_path = temp_root.join("data/private_keys");
    let crl_path = temp_root.join("data/crl");
    let app_key_path = temp_root.join("key/app.key");
    let app_cert_path = temp_root.join("certificate/app.crt");

    for path in [
        &certificate_path,
        &private_key_path,
        &crl_path,
        &app_key_path,
        &app_cert_path,
    ] {
        ensure_parent_dir(path)?;
    }

    set_string_value(
        &mut config_value,
        "blockchains",
        "certificate_path",
        certificate_path.to_string_lossy().into_owned(),
    )?;
    set_string_value(
        &mut config_value,
        "blockchains",
        "private_key_path",
        private_key_path.to_string_lossy().into_owned(),
    )?;
    set_string_value(
        &mut config_value,
        "blockchains",
        "crl_path",
        crl_path.to_string_lossy().into_owned(),
    )?;
    set_string_value(
        &mut config_value,
        "key_exports",
        "app_key_path",
        app_key_path.to_string_lossy().into_owned(),
    )?;
    set_string_value(
        &mut config_value,
        "key_exports",
        "app_cert_path",
        app_cert_path.to_string_lossy().into_owned(),
    )?;

    let generated = toml::to_string_pretty(&config_value)
        .context("Failed to serialize generated test configuration")?;
    let config_path = temp_root.join("tests_config.toml");
    std::fs::write(&config_path, generated)
        .context("Failed to write generated tests_config.toml")?;

    Ok(EphemeralTestConfig {
        temp_dir,
        config_path,
    })
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    Ok(())
}
