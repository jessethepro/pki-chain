mod chain_state;
mod external_interface;
mod generate_intermediate_ca;
mod generate_root_ca;
mod generate_user_keypair;

use anyhow::{Context, Result};
use generate_root_ca::RsaRootCABuilder;
use libblockchain::blockchain::BlockChain;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

const APP_KEY_PATH: &str = "key/pki-chain-app.key";

fn main() -> Result<()> {
    println!("=== PKI Chain Application ===\n");
    // Initialize blockchain storage for certificates and private keys
    let _certificate_chain = Arc::new(Mutex::new(BlockChain::new(
        "data/certificates",
        APP_KEY_PATH,
    )?));
    println!("✓ Certificate blockchain initialized from 'data/certificates'");

    let _private_chain = Arc::new(Mutex::new(BlockChain::new(
        "data/private_keys",
        APP_KEY_PATH,
    )?));
    println!("✓ Private key blockchain initialized from 'data/private_keys'");

    if _certificate_chain.lock().unwrap().block_count()? == 0 {
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
        // Save certificate to blockchain
        _certificate_chain
            .lock()
            .unwrap()
            .put_block(certificate.to_pem()?)?;
        _private_chain
            .lock()
            .unwrap()
            .put_block(private_key.private_key_to_der()?)?;
        println!("✓ Root CA certificate and private key stored in blockchain as the genesis block");
        // Verify stored Root CA
        let stored_cert = {
            let block = _certificate_chain.lock().unwrap().get_block_by_height(0)?;
            openssl::x509::X509::from_pem(&block.block_data)
                .context("Failed to parse stored Root CA certificate")?
        };
        assert_eq!(
            stored_cert, certificate,
            "Stored Root CA certificate does not match generated certificate"
        );
        let stored_key = {
            let block = _private_chain.lock().unwrap().get_block_by_height(0)?;
            openssl::pkey::PKey::private_key_from_der(&block.block_data)
                .context("Failed to parse stored Root CA key")?
        };
        assert_eq!(
            stored_key.private_key_to_der()?,
            private_key.private_key_to_der()?,
            "Stored Root CA key does not match generated key"
        );
        println!("✓ Verified stored Root CA certificate matches generated certificate\n");
        println!("✓ Verified stored Root CA key matches generated key\n");

        // Export Root CA private key to file
        std::fs::create_dir_all("exports")?;
        let key_pem = private_key.private_key_to_pem_pkcs8()?;
        std::fs::write("exports/root_ca.key", key_pem)?;
        println!("✓ Root CA private key exported to 'exports/root_ca.key'");
    }
    // Start socket server in background thread
    let cert_chain_clone = Arc::clone(&_certificate_chain);
    let private_chain_clone = Arc::clone(&_private_chain);
    std::thread::spawn(move || {
        if let Err(e) =
            external_interface::start_socket_server(cert_chain_clone, private_chain_clone)
        {
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
            "1" => validate_blockchain(&_certificate_chain, &_private_chain)?,
            "2" => {
                println!("\nExiting PKI Chain application...");
                break;
            }
            _ => println!("Invalid option. Please select 1-4."),
        }
    }

    Ok(())
}

fn validate_blockchain(
    certificate_chain: &Arc<Mutex<BlockChain>>,
    private_chain: &Arc<Mutex<BlockChain>>,
) -> Result<()> {
    println!("\n=== Validate Blockchain ===");

    print!("Validating certificate blockchain... ");
    io::stdout().flush()?;
    certificate_chain.lock().unwrap().validate()?;
    println!("✓ Valid");

    print!("Validating private key blockchain... ");
    io::stdout().flush()?;
    private_chain.lock().unwrap().validate()?;
    println!("✓ Valid");

    println!("\n✓ Both blockchains are valid");
    println!(
        "  Certificate chain height: {}",
        certificate_chain.lock().unwrap().get_height()?
    );
    println!(
        "  Private key chain height: {}",
        private_chain.lock().unwrap().get_height()?
    );
    println!(
        "  Total blocks: {}",
        certificate_chain.lock().unwrap().block_count()?
    );

    Ok(())
}
