mod generate_intermediate_ca;
mod generate_root_ca;
mod generate_user_keypair;

use anyhow::{Context, Result};
use generate_intermediate_ca::RsaIntermediateCABuilder;
use generate_root_ca::RsaRootCABuilder;
use generate_user_keypair::RsaUserKeyPairBuilder;
use libblockchain::blockchain::BlockChain;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::io::{self, Write};

const APP_KEY_PATH: &str = "key/pki-chain-app.key";

fn main() -> Result<()> {
    println!("=== PKI Chain Application ===\n");
    // Initialize blockchain storage for certificates and private keys
    let _certificate_chain = BlockChain::new("data/certificates", APP_KEY_PATH)?;
    println!("✓ Certificate blockchain initialized from 'data/certificates'");

    let _private_chain = BlockChain::new("data/private_keys", APP_KEY_PATH)?;
    println!("✓ Private key blockchain initialized from 'data/private_keys'");

    if _certificate_chain.block_count()? == 0 {
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
        _certificate_chain.put_block(certificate.to_pem()?)?;
        _private_chain.put_block(private_key.private_key_to_der()?)?;
        println!("✓ Root CA certificate and private key stored in blockchain as the genesis block");
        // Verify stored Root CA
        let stored_cert = {
            let block = _certificate_chain.get_block_by_height(0)?;
            openssl::x509::X509::from_pem(&block.block_data)
                .context("Failed to parse stored Root CA certificate")?
        };
        assert_eq!(
            stored_cert, certificate,
            "Stored Root CA certificate does not match generated certificate"
        );
        let stored_key = {
            let block = _private_chain.get_block_by_height(0)?;
            openssl::pkey::PKey::private_key_from_der(&block.block_data)
                .context("Failed to parse stored Root CA key")?
        };
        assert_eq!(
            stored_key.private_key_to_der()?,
            private_key.private_key_to_der()?,
            "Stored Root CA key does not match generated key"
        );

        // Export Root CA private key to file
        std::fs::create_dir_all("exports")?;
        let key_pem = private_key.private_key_to_pem_pkcs8()?;
        std::fs::write("exports/root_ca.key", key_pem)?;
        println!("✓ Root CA private key exported to 'exports/root_ca.key'");
    }
    println!("✓ Verified stored Root CA certificate matches generated certificate\n");

    // Main menu loop
    loop {
        println!("\n=== PKI Chain Menu ===");
        println!("1. Create Intermediate Certificate");
        println!("2. Create User Certificate");
        println!("3. Validate Blockchain");
        println!("4. Exit");
        print!("\nSelect an option: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => create_intermediate_certificate(&_certificate_chain, &_private_chain)?,
            "2" => create_user_certificate(&_certificate_chain, &_private_chain)?,
            "3" => validate_blockchain(&_certificate_chain, &_private_chain)?,
            "4" => {
                println!("\nExiting PKI Chain application...");
                break;
            }
            _ => println!("Invalid option. Please select 1-4."),
        }
    }

    Ok(())
}

fn create_intermediate_certificate(
    certificate_chain: &BlockChain,
    private_chain: &BlockChain,
) -> Result<()> {
    println!("\n=== Create Intermediate Certificate ===");

    // Get Root CA from blockchain
    let root_cert = (|| -> Result<X509> {
        let root_block = certificate_chain.get_block_by_height(0)?;
        let root_cert = openssl::x509::X509::from_pem(&root_block.block_data)
            .context("Failed to parse stored Root CA certificate")?;
        Ok(root_cert)
    })()?;

    let root_key = (|| -> Result<PKey<Private>> {
        let root_key_block = private_chain.get_block_by_height(0)?;
        let root_key = openssl::pkey::PKey::private_key_from_der(&root_key_block.block_data)
            .context("Failed to parse stored Root CA private key")?;
        Ok(root_key)
    })()?;

    // Prompt for intermediate CA details
    print!("Common Name (CN): ");
    io::stdout().flush()?;
    let mut cn = String::new();
    io::stdin().read_line(&mut cn)?;

    print!("Organization (O): ");
    io::stdout().flush()?;
    let mut org = String::new();
    io::stdin().read_line(&mut org)?;

    print!("Organizational Unit (OU): ");
    io::stdout().flush()?;
    let mut ou = String::new();
    io::stdin().read_line(&mut ou)?;

    print!("Country (C): ");
    io::stdout().flush()?;
    let mut country = String::new();
    io::stdin().read_line(&mut country)?;

    // Generate intermediate CA
    let (inter_key, inter_cert) = RsaIntermediateCABuilder::new(root_key, root_cert)
        .subject_common_name(cn.trim().to_string())
        .organization(org.trim().to_string())
        .organizational_unit(ou.trim().to_string())
        .country(country.trim().to_string())
        .validity_days(365 * 3) // 3 years
        .build()?;

    // Store in blockchain
    certificate_chain.put_block(inter_cert.to_pem()?)?;
    private_chain.put_block(inter_key.private_key_to_der()?)?;

    println!("✓ Intermediate CA created and stored in blockchain");
    println!("✓ Blockchain height: {}", certificate_chain.get_height()?);

    Ok(())
}

fn create_user_certificate(
    certificate_chain: &BlockChain,
    private_chain: &BlockChain,
) -> Result<()> {
    println!("\n=== Create User Certificate ===");

    // Find the latest intermediate CA (last block before potential user certs)
    let chain_height = certificate_chain.get_height()?;
    if chain_height < 1 {
        println!("✗ No intermediate CA found. Create an intermediate CA first.");
        return Ok(());
    }

    // Get the most recent intermediate CA (height 1)
    let inter_cert = {
        let block = certificate_chain.get_block_by_height(1)?;
        openssl::x509::X509::from_pem(&block.block_data)
            .context("Failed to parse stored Intermediate CA certificate")?
    };

    let inter_key = (|| -> Result<PKey<Private>> {
        let block = private_chain.get_block_by_height(1)?;
        let key = openssl::pkey::PKey::private_key_from_der(&block.block_data)
            .context("Failed to parse stored Intermediate CA private key")?;
        Ok(key)
    })()?;

    // Prompt for user details
    print!("User Name (CN): ");
    io::stdout().flush()?;
    let mut cn = String::new();
    io::stdin().read_line(&mut cn)?;

    print!("Email: ");
    io::stdout().flush()?;
    let mut email = String::new();
    io::stdin().read_line(&mut email)?;

    print!("Organization (O): ");
    io::stdout().flush()?;
    let mut org = String::new();
    io::stdin().read_line(&mut org)?;

    // Generate user certificate
    let (user_key, user_cert) = RsaUserKeyPairBuilder::new(inter_key, inter_cert)
        .subject_common_name(cn.trim().to_string())
        .organization(org.trim().to_string())
        .validity_days(365) // 1 year
        .build()?;

    // Store in blockchain
    certificate_chain.put_block(user_cert.to_pem()?)?;
    private_chain.put_block(user_key.private_key_to_der()?)?;

    println!("✓ User certificate created and stored in blockchain");
    println!("✓ Blockchain height: {}", certificate_chain.get_height()?);

    Ok(())
}

fn validate_blockchain(certificate_chain: &BlockChain, private_chain: &BlockChain) -> Result<()> {
    println!("\n=== Validate Blockchain ===");

    print!("Validating certificate blockchain... ");
    io::stdout().flush()?;
    certificate_chain.validate()?;
    println!("✓ Valid");

    print!("Validating private key blockchain... ");
    io::stdout().flush()?;
    private_chain.validate()?;
    println!("✓ Valid");

    println!("\n✓ Both blockchains are valid");
    println!(
        "  Certificate chain height: {}",
        certificate_chain.get_height()?
    );
    println!(
        "  Private key chain height: {}",
        private_chain.get_height()?
    );
    println!("  Total blocks: {}", certificate_chain.block_count()?);

    Ok(())
}
