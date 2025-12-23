//! PKI Chain - Blockchain-backed Certificate Authority
//!
//! A production-ready Public Key Infrastructure system that stores certificates in blockchain
//! storage and private keys in AES-256-GCM encrypted files. Provides a complete three-tier
//! CA hierarchy: Root CA → Intermediate CA → User Certificates.
//!
//! # Features
//!
//! - **Terminal User Interface**: Cursive-based TUI for certificate management
//! - **Hybrid Storage Architecture**:
//!   - Certificates stored as DER in blockchain
//!   - Private keys encrypted with AES-256-GCM in filesystem (enables offline/cold storage)
//!   - Key chain stores SHA-256 hashes and certificate signatures
//! - **Interactive Certificate Creation**: Form-based Intermediate CA and User certificate creation with validation
//! - **Three-Tier PKI**: Root CA, Intermediate CAs, and User certificates
//! - **4096-bit RSA**: Strong cryptographic keys with SHA-256 signatures
//! - **Transactional Safety**: Automatic rollback on storage failures
//! - **Integrity Verification**: Hash-based validation of private keys
//! - **Thread-Safe Operations**: Arc-wrapped Protocol with concurrent access support
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
//! # Storage Architecture
//!
//! On first run, the application automatically initializes a Root CA certificate and sets up
//! the necessary storage structure. The storage layout is as follows:
//! - Height 0: Root CA (self-signed, 5-year validity)
//!
//! ## Storage Layout
//!
//! - **Certificate Blockchain** (`data/certificates/`): Stores X.509 certificates in DER format
//! - **Private Key Blockchain** (`data/private_keys/`): Stores SHA-256 hashes of private keys
//!   - Signatures column family: Stores signatures of corresponding certificates
//! - **Encrypted Key Store** (`exports/keystore/`): AES-256-GCM encrypted private keys
//!   - Format: [nonce (12 bytes)][tag (16 bytes)][ciphertext]
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
