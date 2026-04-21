use anyhow::Result;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub blockchains: Blockchains,
    pub key_exports: KeyExports,
    pub server: ServerConfig,
    pub root_ca_defaults: RootCADefaults,
    pub admin_ca_defaults: AdminCADefaults,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Blockchains {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub crl_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeyExports {
    pub app_key_path: PathBuf,
    pub app_cert_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub comm_sock: PathBuf,
    pub setup_sock: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RootCADefaults {
    pub root_ca_common_name: String,
    pub root_ca_organization: String,
    pub root_ca_organizational_unit: String,
    pub root_ca_locality: String,
    pub root_ca_state: String,
    pub root_ca_country: String,
    pub root_ca_validity_days: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminCADefaults {
    pub admin_ca_common_name: String,
    pub admin_ca_organization: String,
    pub admin_ca_organizational_unit: String,
    pub admin_ca_locality: String,
    pub admin_ca_state: String,
    pub admin_ca_country: String,
    pub admin_ca_validity_days: u32,
}

impl AppConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &str) -> Result<Self> {
        let config_str = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "from_file -> Failed to read config file: {}: {}",
                    path,
                    e
                ));
            }
        };

        let config: AppConfig = match toml::from_str(&config_str) {
            Ok(config) => config,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "from_file -> Failed to parse config file: {}: {}",
                    path,
                    e
                ));
            }
        };
        Ok(config)
    }

    /// Load configuration with default path (config.toml)
    pub fn load() -> Result<Self> {
        Self::from_file("config.toml")
    }
}
