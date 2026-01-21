use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub blockchains: Blockchains,
    pub key_exports: KeyExports,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub root_ca_defaults: RootCADefaults,
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
    pub root_key_name: String,
    #[serde(default = "default_key_export_dir")]
    pub key_export_directory_path: PathBuf,
}

fn default_key_export_dir() -> PathBuf {
    PathBuf::from("exports/keystore")
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_server_host")]
    pub host: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
    #[serde(default = "default_web_root")]
    pub web_root: PathBuf,
    #[serde(default = "default_tls_cert_path")]
    pub tls_cert_path: PathBuf,
    #[serde(default = "default_tls_key_path")]
    pub tls_key_path: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_server_host(),
            port: default_server_port(),
            web_root: default_web_root(),
            tls_cert_path: default_tls_cert_path(),
            tls_key_path: default_tls_key_path(),
        }
    }
}

fn default_server_host() -> String {
    "127.0.0.1".to_string()
}

fn default_server_port() -> u16 {
    3000
}

fn default_web_root() -> PathBuf {
    PathBuf::from("web_root")
}

fn default_tls_cert_path() -> PathBuf {
    PathBuf::from("web_certs/server/chain.pem")
}

fn default_tls_key_path() -> PathBuf {
    PathBuf::from("web_certs/server/server.key")
}

#[derive(Debug, Deserialize, Clone)]
pub struct RootCADefaults {
    #[serde(default = "default_root_ca_cn")]
    pub root_ca_common_name: String,
    #[serde(default = "default_root_ca_org")]
    pub root_ca_organization: String,
    #[serde(default = "default_root_ca_ou")]
    pub root_ca_organizational_unit: String,
    #[serde(default = "default_root_ca_locality")]
    pub root_ca_locality: String,
    #[serde(default = "default_root_ca_state")]
    pub root_ca_state: String,
    #[serde(default = "default_root_ca_country")]
    pub root_ca_country: String,
    #[serde(default = "default_root_ca_validity")]
    pub root_ca_validity_days: u32,
}

impl Default for RootCADefaults {
    fn default() -> Self {
        Self {
            root_ca_common_name: default_root_ca_cn(),
            root_ca_organization: default_root_ca_org(),
            root_ca_organizational_unit: default_root_ca_ou(),
            root_ca_locality: default_root_ca_locality(),
            root_ca_state: default_root_ca_state(),
            root_ca_country: default_root_ca_country(),
            root_ca_validity_days: default_root_ca_validity(),
        }
    }
}

fn default_root_ca_cn() -> String {
    "MenaceLabs Root CA".to_string()
}

fn default_root_ca_org() -> String {
    "MenaceLabs".to_string()
}

fn default_root_ca_ou() -> String {
    "CY".to_string()
}

fn default_root_ca_locality() -> String {
    "Sao Jose dos Campos".to_string()
}

fn default_root_ca_state() -> String {
    "SP".to_string()
}

fn default_root_ca_country() -> String {
    "BR".to_string()
}

fn default_root_ca_validity() -> u32 {
    3650 // 10 years
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
