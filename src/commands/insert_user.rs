use anyhow::Result;
use libblockchainstor::BlockchainDb;
use crate::app_key_store::AppKeyStore;
use crate::store_user_key::store_user_pfx;
use crate::store_user_cert::store_user_certificate;
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

/// Handle the --insert-user command
///
/// This command:
/// 1. Stores the User certificate PFX file in the PFX blockchain
/// 2. Stores the User certificate in the certificate blockchain
///
/// # Arguments
///
/// * `pfx_path` - Path to the User certificate PFX file
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
/// use pki_chain::commands::insert_user::handle_insert_user;
/// use libblockchainstor::BlockchainDb;
/// use std::sync::Arc;
/// use pki_chain::AppKeyStore;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
/// let app_key_store = Arc::new(AppKeyStore::load_from_pfx("key/app.pfx", "password")?);
///
/// handle_insert_user("user@example.com.pfx", &pfx_chain, &cert_chain, &app_key_store)?;
/// ```
pub fn handle_insert_user(
    pfx_path: &str,
    pfx_chain: &BlockchainDb,
    certificate_chain: &BlockchainDb,
    app_key_store: &AppKeyStore,
) -> Result<()> {
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  INSERTING USER CERTIFICATE");
    println!("═══════════════════════════════════════════════════════════\n");
    
    println!("📄 PFX File: {}", pfx_path);
    println!("\n⏳ Processing...\n");
    
    // Create SHA-256 hasher
    let hasher = Sha256Hasher;
    
    // Step 1: Store User certificate PFX in PFX blockchain
    println!("1️⃣  Storing User certificate PFX in PFX blockchain...");
    let (pfx_uid, pfx_height) = store_user_pfx(
        pfx_path,
        pfx_chain,
        &hasher,
        app_key_store,
    )?;
    
    println!("   ✓ Stored at height {}", pfx_height);
    println!("   Block UID: {:x?}", pfx_uid);
    
    // Step 2: Store User certificate in certificate blockchain
    println!("\n2️⃣  Storing User certificate in certificate blockchain...");
    let (cert_uid, cert_height) = store_user_certificate(
        pfx_chain,
        pfx_height,
        certificate_chain,
        &hasher,
        app_key_store,
    )?;
    
    println!("   ✓ Stored at height {}", cert_height);
    println!("   Block UID: {:x?}", cert_uid);
    
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  ✓ USER CERTIFICATE SUCCESSFULLY INSERTED");
    println!("═══════════════════════════════════════════════════════════\n");
    
    Ok(())
}
