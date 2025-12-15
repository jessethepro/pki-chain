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

mod external_interface;
mod generate_intermediate_ca;
mod generate_root_ca;
mod generate_user_keypair;
mod storage;

use anyhow::{Context, Result};
use generate_root_ca::RsaRootCABuilder;
use std::io::{self, Write};
use std::sync::Arc;
use storage::Storage;

const APP_KEY_PATH: &str = "key/pki-chain-app.key";

fn main() -> Result<()> {
    println!("=== PKI Chain Application ===\n");
    // Initialize storage
    let storage = Arc::new(Storage::new(APP_KEY_PATH).context("Failed to initialize storage")?);

    if storage.is_empty()? {
        let (private_key, certificate) = RsaRootCABuilder::new()
            .subject_common_name("PKI Chain Root CA".to_string())
            .organization("MenaceLabs".to_string())
            .organizational_unit("CY".to_string())
            .country("BR".to_string())
            .state("SP".to_string())
            .locality("Sao Jose dos Campos".to_string())
            .validity_days(365 * 5) // 5 years
            .build()
            .context("Failed to generate Root CA")?;
        println!("✓ Root CA generated");
        // Save to blockchain
        let height = storage
            .store_key_certificate(&private_key, &certificate)
            .context("Failed to store Root CA in blockchain")?;
        println!("✓ Root CA certificate and private key stored in blockchain as the genesis block");

        // Verify storage
        if storage.verify_stored_key_certificate_pair(&private_key, &certificate, height)? {
            println!("✓ Stored Root CA key-certificate pair verified successfully");
            // Export Root CA private key to file
            std::fs::create_dir_all("exports")?;
            let key_pem = private_key.private_key_to_pem_pkcs8()?;
            std::fs::write("exports/root_ca.key", key_pem)?;
            println!("✓ Root CA private key exported to 'exports/root_ca.key'");
        } else {
            println!("✗ Verification of stored Root CA key-certificate pair failed");
            return Err(anyhow::anyhow!(
                "Stored Root CA key-certificate pair verification failed"
            ));
        }
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
        println!("✓ Blockchain validation successful");
    } else {
        println!("✗ Blockchain validation failed");
        return Err(anyhow::anyhow!("Blockchain validation failed"));
    }
    Ok(())
}
