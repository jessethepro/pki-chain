use anyhow::Result;
use libblockchainstor::BlockchainDb;
use crate::app_key_store::AppKeyStore;
use crate::store_root_key::store_root_ca_pfx;
use crate::store_root_cert::store_root_ca_certificate;
use libcertcrypto::CertificateTools;
use libblockchainstor::libblockchain::BlockHeaderHasher;

/// SHA-256 hasher implementation for blockchain operations
struct Sha256Hasher;

impl BlockHeaderHasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        CertificateTools::hash_sha256(data).unwrap_or_default()
    }
    
    fn hash_size(&self) -> usize {
        32
    }
}

/// Handle the --insert-root command
///
/// This command:
/// 1. Stores the Root CA PFX file as the genesis block in the PFX blockchain
/// 2. Stores the Root CA certificate as the genesis block in the certificate blockchain
///
/// # Arguments
///
/// * `pfx_path` - Path to the Root CA PFX file
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `certificate_chain` - Reference to the certificate blockchain database
/// * `app_key_store` - Application key store for encryption/decryption
///
/// # Returns
///
/// * `Result<()>` - Success or error
///
/// # Example
/// ```no_run
/// use pki_chain::commands::insert_root::handle_insert_root;
/// use libblockchainstor::BlockchainDb;
/// use std::sync::Arc;
/// use pki_chain::AppKeyStore;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
/// let app_key_store = Arc::new(AppKeyStore::load_from_pfx("key/app.pfx", "password")?);
///
/// handle_insert_root("RootCA.pfx", &pfx_chain, &cert_chain, &app_key_store)?;
/// ```
pub fn handle_insert_root(
    pfx_path: &str,
    pfx_chain: &BlockchainDb,
    certificate_chain: &BlockchainDb,
    app_key_store: &AppKeyStore,
) -> Result<()> {
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  INSERTING ROOT CA");
    println!("═══════════════════════════════════════════════════════════\n");
    
    println!("📄 PFX File: {}", pfx_path);
    println!("\n⏳ Processing...\n");
    
    // Create SHA-256 hasher
    let hasher = Sha256Hasher;
    
    // Step 1: Store Root CA PFX in PFX blockchain (genesis block)
    println!("1️⃣  Storing Root CA PFX in PFX blockchain...");
    let (pfx_uid, pfx_height) = store_root_ca_pfx(
        pfx_path,
        pfx_chain,
        &hasher,
        app_key_store,
    )?;
    
    println!("   ✓ Stored at height {} (genesis)", pfx_height);
    println!("   Block UID: {:x?}", pfx_uid);
    
    // Step 2: Store Root CA certificate in certificate blockchain (genesis block)
    println!("\n2️⃣  Storing Root CA certificate in certificate blockchain...");
    let (cert_uid, cert_height) = store_root_ca_certificate(
        pfx_chain,
        certificate_chain,
        &hasher,
        app_key_store,
    )?;
    
    println!("   ✓ Stored at height {} (genesis)", cert_height);
    println!("   Block UID: {:x?}", cert_uid);
    
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  ✓ ROOT CA SUCCESSFULLY INSERTED");
    println!("═══════════════════════════════════════════════════════════\n");
    
    Ok(())
}
