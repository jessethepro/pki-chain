//! PKI Chain - Blockchain-backed Certificate Authority
//!
//! A production-ready Public Key Infrastructure system that stores certificates and private keys
//! in tamper-proof blockchain storage. Provides a complete three-tier CA hierarchy:
//! Root CA → Intermediate CA → User Certificates.
//!
//! # Features
//!
//! - **Terminal User Interface**: Cursive-based TUI for certificate management
//! - **Blockchain Storage**: Dual blockchain instances for certificates and private keys
//! - **Interactive Certificate Creation**: Form-based Intermediate CA creation with validation
//! - **Three-Tier PKI**: Root CA, Intermediate CAs, and User certificates
//! - **4096-bit RSA**: Strong cryptographic keys with SHA-256 signatures
//! - **Transactional Safety**: Automatic rollback on storage failures
//! - **Signature Verification**: Cross-validation between certificate and key chains
//! - **Thread-Safe Operations**: Arc-wrapped storage with concurrent access support
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
//! - [`protocol`]: IPC protocol definitions for socket communication
//! - [`external_interface`]: Unix socket server for external certificate requests (currently disabled)
//! - [`generate_root_ca`]: Self-signed Root CA certificate generation
//! - [`generate_intermediate_ca`]: Intermediate CA generation (signed by Root)
//! - [`generate_user_keypair`]: User certificate generation (signed by Intermediate)
//! - [`generate_webclient_tls`]: TLS server certificate with SubjectAltName extensions
//!
//! # Example Usage
//!
//! The application provides a terminal user interface with the following features:
//!
//! 1. **Create Intermediate Certificate**: Interactive form for generating Intermediate CA certificates
//!    - All Distinguished Name fields (CN, O, OU, L, ST, C)
//!    - Configurable validity period
//!    - Real-time validation
//! 2. **Validate Blockchain**: Verify integrity of certificate and key chains
//! 3. **View System Status**: Display blockchain statistics and tracked certificates
//! 4. **Exit**: Shutdown application
//!
//! # Certificate Storage
//!
//! On first run, the application automatically initializes a 3-tier TLS hierarchy:
//! - Height 0: Root CA (self-signed, 5-year validity)
//! - Height 1: Intermediate TLS CA (pathlen=0, 3-year validity)
//! - Height 2: WebClient TLS Certificate (serverAuth, 1-year validity)
//!
//! User-created certificates are stored at heights 3 and above.

mod ui;

use anyhow::{Context, Result};
use pki_chain::protocol::Protocol;
use pki_chain::storage::Storage;
use std::sync::Arc;

const APP_KEY_PATH: &str = "key/pki-chain-app.key";

fn main() -> Result<()> {
    // Initialize storage
    let storage = Storage::new(APP_KEY_PATH).context("Failed to initialize storage")?;

    if storage.is_empty()? {
        storage
            .initialize()
            .context("Failed to initialize PKI storage")?;
    }
    storage
        .populate_subject_name_index()
        .context("Failed to populate subject name index")?;

    // Create protocol that owns storage
    let protocol = Arc::new(Protocol::new(storage));

    // Socket server disabled for now
    // let protocol_clone = Arc::clone(&protocol);
    // std::thread::spawn(move || {
    //     if let Err(e) = pki_chain::external_interface::start_socket_server(protocol_clone) {
    //         eprintln!("Socket server error: {}", e);
    //     }
    // });

    // Run the TUI
    ui::run_ui(protocol);

    Ok(())
}
