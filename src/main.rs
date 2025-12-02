mod app_key_store;

use anyhow::{Context, Result};
use app_key_store::AppKeyStore;
use libblockchain::blockchain::BlockChain;
use libcertcrypto::{
    CertificateTools, RsaIntermediateCABuilder, RsaRootCABuilder, RsaUserKeyPairBuilder,
};
use std::io::{self, Write};

const APP_CERT_PATH: &str = "certificate/pki-chain-app.crt";
const APP_KEY_PATH: &str = "key/pki-chain-app.key";

fn main() -> Result<()> {
    println!("=== PKI Chain Application ===\n");
    let _app_cert =
        CertificateTools::load_certificate_from_pem_file(APP_CERT_PATH).context(format!(
            "Failed to load application certificate from {}",
            APP_CERT_PATH
        ))?;
    println!("✓ Application certificate loaded from '{}'", APP_CERT_PATH);

    let _app_key = AppKeyStore::from_pem_file(APP_KEY_PATH, None).context(format!(
        "Failed to load application private key from {}",
        APP_KEY_PATH
    ))?;
    println!("✓ Application private key loaded from '{}'\n", APP_KEY_PATH);

    // Initialize blockchain storage for certificates and private keys
    let _certificate_chain = BlockChain::new("data/certificates")?;
    println!("✓ Certificate blockchain initialized from 'data/certificates'");

    let _private_chain = BlockChain::new("data/private_keys")?;
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
        _certificate_chain.insert_block(certificate.to_pem()?, _app_cert.clone())?;
        _private_chain.insert_block(private_key.private_key_to_der()?, _app_cert.clone())?;
        println!("✓ Root CA certificate and private key stored in blockchain as the genesis block");
        let stored_cert_data = _app_key.decrypt_block_data(
            _certificate_chain
                .get_block_by_height(0)?
                .context("Failed to retrieve stored Root CA certificate")?,
        )?;
        let stored_cert = CertificateTools::load_cert_from_pem_bytes(&stored_cert_data)
            .context("Failed to parse stored Root CA certificate")?;
        assert_eq!(
            stored_cert, certificate,
            "Stored Root CA certificate does not match generated certificate"
        );
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
            "1" => create_intermediate_certificate(
                &_certificate_chain,
                &_private_chain,
                &_app_cert,
                &_app_key,
            )?,
            "2" => create_user_certificate(
                &_certificate_chain,
                &_private_chain,
                &_app_cert,
                &_app_key,
            )?,
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
    app_cert: &openssl::x509::X509,
    app_key: &AppKeyStore,
) -> Result<()> {
    println!("\n=== Create Intermediate Certificate ===");

    // Get Root CA from blockchain
    let root_cert_block = certificate_chain
        .get_block_by_height(0)?
        .context("Root CA not found in blockchain")?;
    let root_cert_data = app_key.decrypt_block_data(root_cert_block)?;
    let root_cert = CertificateTools::load_cert_from_pem_bytes(&root_cert_data)?;

    let root_key_block = private_chain
        .get_block_by_height(0)?
        .context("Root CA private key not found")?;
    let root_key_data = app_key.decrypt_block_data(root_key_block)?;
    let root_key = openssl::pkey::PKey::private_key_from_der(&root_key_data)?;

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
    certificate_chain.insert_block(inter_cert.to_pem()?, app_cert.clone())?;
    private_chain.insert_block(inter_key.private_key_to_der()?, app_cert.clone())?;

    println!("✓ Intermediate CA created and stored in blockchain");
    println!("✓ Blockchain height: {}", certificate_chain.get_height()?);

    Ok(())
}

fn create_user_certificate(
    certificate_chain: &BlockChain,
    private_chain: &BlockChain,
    app_cert: &openssl::x509::X509,
    app_key: &AppKeyStore,
) -> Result<()> {
    println!("\n=== Create User Certificate ===");

    // Find the latest intermediate CA (last block before potential user certs)
    let chain_height = certificate_chain.get_height()?;
    if chain_height < 1 {
        println!("✗ No intermediate CA found. Create an intermediate CA first.");
        return Ok(());
    }

    // Get the most recent intermediate CA (height 1)
    let inter_cert_block = certificate_chain
        .get_block_by_height(1)?
        .context("Intermediate CA not found")?;
    let inter_cert_data = app_key.decrypt_block_data(inter_cert_block)?;
    let inter_cert = CertificateTools::load_cert_from_pem_bytes(&inter_cert_data)?;

    let inter_key_block = private_chain
        .get_block_by_height(1)?
        .context("Intermediate CA private key not found")?;
    let inter_key_data = app_key.decrypt_block_data(inter_key_block)?;
    let inter_key = openssl::pkey::PKey::private_key_from_der(&inter_key_data)?;

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
    certificate_chain.insert_block(user_cert.to_pem()?, app_cert.clone())?;
    private_chain.insert_block(user_key.private_key_to_der()?, app_cert.clone())?;

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
