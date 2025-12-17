//! PKI Chain - Blockchain-backed Certificate Authority
//!
//! A production-ready Public Key Infrastructure system that stores certificates and private keys
//! in tamper-proof blockchain storage. Provides a complete three-tier CA hierarchy:
//! Root CA → Intermediate CA → User Certificates.
//!
//! # Features
//!
//! - **Blockchain Storage**: Dual blockchain instances for certificates and private keys
//! - **Unix Socket API**: External IPC interface for certificate operations
//! - **Three-Tier PKI**: Root CA, Intermediate CAs, and User certificates
//! - **4096-bit RSA**: Strong cryptographic keys with SHA-256 signatures
//! - **Transactional Safety**: Automatic rollback on storage failures
//! - **Signature Verification**: Cross-validation between certificate and key chains
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
//! - [`storage`]: Blockchain storage abstraction for certificates and keys
//! - [`external_interface`]: Unix socket server for external certificate requests
//! - [`generate_root_ca`]: Self-signed Root CA certificate generation
//! - [`generate_intermediate_ca`]: Intermediate CA generation (signed by Root)
//! - [`generate_user_keypair`]: User certificate generation (signed by Intermediate)
//!
//! # Example Usage
//!
//! The application provides an interactive menu for:
//! 1. Validating blockchain integrity
//! 2. Viewing certificate statistics
//!
//! External applications can request certificates via the Unix socket at `/tmp/pki_socket`.

use anyhow::{Context, Result};
use pki_chain::external_interface;
use pki_chain::storage::Storage;
use std::io::{self, Write};
use std::sync::Arc;

const APP_KEY_PATH: &str = "key/pki-chain-app.key";

fn main() -> Result<()> {
    println!("=== PKI Chain Application ===\n");
    // Initialize storage
    let storage = Arc::new(Storage::new(APP_KEY_PATH).context("Failed to initialize storage")?);

    if storage.is_empty()? {
        storage
            .initialize()
            .context("Failed to initialize PKI storage")?;
        println!("✓ PKI storage initialized with Root CA, Intermediate TLS certificate and Web Client TLS certificate\n");
    }
    // Start socket server in background thread
    let storage_clone = Arc::clone(&storage);
    std::thread::spawn(move || {
        if let Err(e) = external_interface::start_socket_server(storage_clone) {
            eprintln!("Socket server error: {}", e);
        }
    });
    println!("✓ Socket server started in background\n");

    // Main menu loop
    loop {
        println!("\n=== PKI Chain Menu ===");
        println!("1. Validate Blockchain");
        println!("2. Exit");
        print!("\nSelect an option: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => validate_pki_storage(&storage)?,
            "2" => {
                println!("\nExiting PKI Chain application...");
                break;
            }
            _ => println!("Invalid option. Please select 1-4."),
        }
    }

    Ok(())
}

fn validate_pki_storage(storage: &Storage) -> Result<()> {
    println!("\n=== Validate Blockchain ===");
    if storage.is_empty()? {
        println!("Blockchain is empty. No data to validate.");
        return Ok(());
    }

    if storage.validate()? {
        println!(
            "Total Certificates Stored: {}",
            storage.certificate_chain.block_count()?
        );
        println!(
            "Total Private Keys Stored: {}",
            storage.private_chain.block_count()?
        );
        println!(
            "Total Subject Names: {}",
            storage.subject_name_to_height.lock().unwrap().len()
        );
        println!("✓ Blockchain validation successful");
    } else {
        println!("✗ Blockchain validation failed");
        return Err(anyhow::anyhow!("Blockchain validation failed"));
    }
    Ok(())
}
