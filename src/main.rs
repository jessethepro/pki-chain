//! PKI Chain - Blockchain-backed Certificate Authority
//!
//! A production-ready Public Key Infrastructure system that stores certificates in blockchain
//! storage and private keys in encrypted PKCS#8 format. Provides a complete three-tier
//! CA hierarchy: Root CA → Intermediate CA → User Certificates.
//!
//! # Features
//!
//! - **Terminal User Interface**: Cursive-based TUI for certificate management
//! - **Configuration System**: TOML-based configuration for paths and keyring settings
//! - **Hybrid Storage Architecture**:
//!   - Certificates stored as DER in blockchain
//!   - Private keys stored as encrypted PKCS#8 PEM files
//!   - Key chain stores SHA-256 hashes and certificate signatures
//! - **Keyring Integration**: Linux kernel keyring for secure key management
//! - **Interactive Certificate Creation**: Form-based Intermediate CA and User certificate creation with validation
//! - **Three-Tier PKI**: Root CA, Intermediate CAs, and User certificates
//! - **4096-bit RSA**: Strong cryptographic keys with SHA-256 signatures
//! - **Transactional Safety**: Automatic rollback on storage failures
//! - **Thread-Safe Operations**: Concurrent access support via Protocol layer
//!
//! # Quick Start
//!
//! ```bash
//! # Generate application key (first run only)
//! ./generate_app_keypair.sh
//!
//! # Build and run
//! cargo build --release
//! ./target/release/pki-chain
//! ```
//!
//! # Architecture
//!
//! The system consists of several key modules:
//!
//! - [`ui`]: Terminal user interface built with cursive for certificate management
//! - [`storage`]: Blockchain storage abstraction for certificates and keys
//! - [`protocol`]: Protocol layer that handles certificate operations and validation
//! - [`pki_generator`]: Certificate generation functions for all certificate types
//! - [`private_key_storage`]: Encrypted key store for PKCS#8 private keys
//! - [`configs`]: Configuration management for TOML settings
//!
//! # Example Usage
//!
//! The application provides a terminal user interface with the following features:
//!
//! 1. **Create Intermediate Certificate**: Interactive form for generating Intermediate CA certificates
//!    - All Distinguished Name fields (CN, O, OU, L, ST, C)
//!    - Configurable validity period
//!    - Real-time validation
//! 2. **Create User Certificate**: Interactive form for generating User certificates
//!    - Select issuing Intermediate CA from dropdown
//!    - All Distinguished Name fields with validation
//! 3. **Validate Blockchain**: Verify integrity of certificate and key chains
//! 4. **View System Status**: Display blockchain statistics and tracked certificates
//! 5. **Exit**: Shutdown application
//!
//! # Storage Architecture
//!
//! On first run, the application automatically initializes the Root CA:
//! - Height 0: Root CA (self-signed, 10-year validity, pathlen=1)
//!
//! ## Storage Layout
//!
//! - **Certificate Blockchain** (configurable via config.toml, default: `data/certificates/`):
//!   Stores X.509 certificates in DER format
//! - **Private Key Blockchain** (configurable via config.toml, default: `data/private_keys/`):
//!   Stores SHA-512 hashes of private keys with signatures column family
//! - **Encrypted Key Store** (configurable via config.toml, default: `exports/keystore/`):
//!   - Root CA private key: PKCS#8 PEM encrypted format with password protection
//!   - Other private keys: RSA + AES-GCM-256 hybrid encryption format
//!     - Format: `[AES Key Len (u64)][Encrypted AES Key][Nonce][Tag][Data Length (usize)][Encrypted Data]`
//!     - AES session key encrypted with Root CA public key
//!     - Private key data encrypted with AES-GCM-256
//!
//! User-created certificates (Intermediate CAs and User certificates) are stored at heights 1 and above.

mod ui;

use anyhow::{Context, Result};
use pki_chain::storage::Storage;

fn main() -> Result<()> {
    let default_configs =
        pki_chain::configs::AppConfig::load().context("Failed to load default configurations")?;
    // Initialize storage
    let storage = Storage::new(default_configs.clone()).context("Failed to initialize storage")?;

    if storage.is_empty()? {
        storage
            .initialize()
            .context("Failed to initialize PKI storage")?;
    }

    // Run the TUI
    ui::run_ui();

    Ok(())
}
