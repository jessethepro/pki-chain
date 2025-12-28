use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub blockchains: Blockchains,
    pub key_exports: KeyExports,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Blockchains {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeyExports {
    pub key_export_directory_path: PathBuf,
    pub app_key_path: PathBuf,
    pub root_key_name: String,
}

impl AppConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self> {
        let config_str =
            fs::read_to_string(path).context(format!("Failed to read config file: {}", path))?;

        let config: AppConfig =
            toml::from_str(&config_str).context("Failed to parse config file")?;

        Ok(config)
    }

    /// Load configuration with default path (config.toml)
    pub fn load() -> Result<Self> {
        Self::from_file("config.toml")
    }
}
