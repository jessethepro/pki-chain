use anyhow::Result;
use libblockchainstor::BlockchainDb;
use crate::app_key_store::AppKeyStore;
use crate::store_intermediate_key::store_intermediate_ca_pfx;
use crate::store_intermediate_cert::store_intermediate_ca_certificate;
use sha2::{Sha256, Digest};
use libblockchainstor::libblockchain::traits::BlockHeaderHasher;

/// SHA-256 hasher implementation for blockchain operations
struct Sha256Hasher;

impl BlockHeaderHasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn hash_size(&self) -> usize {
        32
    }
}

/// Handle the --insert-intermediate command
///
/// This command:
/// 1. Stores the Intermediate CA PFX file in the PFX blockchain
/// 2. Stores the Intermediate CA certificate in the certificate blockchain
///
/// # Arguments
///
/// * `pfx_path` - Path to the Intermediate CA PFX file
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
/// use pki_chain::commands::insert_intermediate::handle_insert_intermediate;
/// use libblockchainstor::BlockchainDb;
/// use std::sync::Arc;
/// use pki_chain::AppKeyStore;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
/// let app_key_store = Arc::new(AppKeyStore::load_from_pfx("key/app.pfx", "password")?);
///
/// handle_insert_intermediate("IntermediateCA.pfx", &pfx_chain, &cert_chain, &app_key_store)?;
/// ```
pub fn handle_insert_intermediate(
    pfx_path: &str,
    pfx_chain: &BlockchainDb,
    certificate_chain: &BlockchainDb,
    app_key_store: &AppKeyStore,
) -> Result<()> {
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  INSERTING INTERMEDIATE CA");
    println!("═══════════════════════════════════════════════════════════\n");
    
    println!("📄 PFX File: {}", pfx_path);
    println!("\n⏳ Processing...\n");
    
    // Create SHA-256 hasher
    let hasher = Sha256Hasher;
    
    // Step 1: Store Intermediate CA PFX in PFX blockchain
    println!("1️⃣  Storing Intermediate CA PFX in PFX blockchain...");
    let (pfx_uid, pfx_height) = store_intermediate_ca_pfx(
        pfx_path,
        pfx_chain,
        &hasher,
        app_key_store,
    )?;
    
    println!("   ✓ Stored at height {}", pfx_height);
    println!("   Block UID: {:x?}", pfx_uid);
    
    // Step 2: Store Intermediate CA certificate in certificate blockchain
    println!("\n2️⃣  Storing Intermediate CA certificate in certificate blockchain...");
    let (cert_uid, cert_height) = store_intermediate_ca_certificate(
        pfx_chain,
        pfx_height,
        certificate_chain,
        &hasher,
        app_key_store,
    )?;
    
    println!("   ✓ Stored at height {}", cert_height);
    println!("   Block UID: {:x?}", cert_uid);
    
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  ✓ INTERMEDIATE CA SUCCESSFULLY INSERTED");
    println!("═══════════════════════════════════════════════════════════\n");
    
    Ok(())
}
