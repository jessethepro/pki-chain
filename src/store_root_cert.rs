use libcertcrypto::{hybrid_encrypt, hybrid_decrypt, HybridEncryptedData};
use anyhow::{Result, anyhow, bail};
use libblockchainstor::BlockchainDb;
use libblockchainstor::libblockchain::traits::BlockHeaderHasher;
use crate::app_key_store::AppKeyStore;
use crate::store_root_key::get_root_ca_pfx;

/// Store a Root CA certificate as the genesis block in the certificate blockchain
///
/// This function:
/// 1. Retrieves the Root CA PFX from the genesis block of the PFX blockchain
/// 2. Extracts the certificate in DER format
/// 3. Encrypts the DER bytes using hybrid encryption with the app public key
/// 4. Stores the encrypted certificate as the genesis block in the certificate chain
/// 5. Validates no genesis block already exists
///
/// # Arguments
///
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `certificate_chain` - Reference to the certificate blockchain database
/// * `hasher` - Block header hasher for creating the genesis block
/// * `app_key_store` - Application key store for encryption and PFX retrieval
///
/// # Returns
///
/// * `Result<([u8; 16], u32)>` - The block UID and height (0) on success
///
/// # Errors
///
/// Returns an error if:
/// - No Root CA PFX exists in the PFX chain
/// - Certificate extraction fails
/// - A genesis block already exists in the certificate blockchain
/// - Hybrid encryption fails
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::store_root_ca_certificate;
/// use libblockchainstor::BlockchainDb;
/// use sha2::{Sha256, Digest};
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
/// let hasher = Sha256::new();
///
/// let (block_uid, height) = store_root_ca_certificate(
///     &pfx_chain,
///     &cert_chain,
///     &hasher,
///     &app_key_store
/// )?;
///
/// assert_eq!(height, 0); // Genesis block
/// ```
pub fn store_root_ca_certificate<H: BlockHeaderHasher>(
    pfx_chain: &BlockchainDb,
    certificate_chain: &BlockchainDb,
    hasher: &H,
    app_key_store: &AppKeyStore,
) -> Result<([u8; 16], u32)> {
    // Check if genesis block (height 0) already exists in certificate chain
    let mut iter = certificate_chain.iter()
        .map_err(|e| anyhow!("Failed to create blockchain iterator: {}", e))?;
    
    if iter.next().is_some() {
        bail!("Genesis block already exists in the certificate blockchain. Cannot store Root CA certificate.");
    }
    
    // Retrieve the Root CA PFX from the PFX blockchain
    let root_ca_pfx = get_root_ca_pfx(pfx_chain, app_key_store)
        .map_err(|e| anyhow!("Failed to retrieve Root CA PFX: {}", e))?;
    
    // Extract the certificate in DER format
    let cert_der = &root_ca_pfx.certificate_der;
    
    // Encrypt the DER bytes using hybrid encryption with the app public key
    let encrypted_data = hybrid_encrypt(app_key_store.get_public_key(), &cert_der)
        .map_err(|e| anyhow!("Failed to encrypt certificate DER: {}", e))?;
    
    // Serialize encrypted data to bytes for blockchain storage
    let encrypted_bytes = encrypted_data.to_bytes();
    
    // Store encrypted certificate as genesis block (will be height 0)
    let (block, height, _signature) = certificate_chain.store_block(hasher, encrypted_bytes)
        .map_err(|e| anyhow!("Failed to store genesis block: {}", e))?;
    
    // Verify it's actually the genesis block
    if height != 0 {
        bail!("Expected genesis block (height 0), but got height {}", height);
    }
    
    Ok((block.block_header.block_uid, height))
}

/// Retrieve the Root CA certificate from the genesis block of the certificate blockchain
///
/// This function:
/// 1. Retrieves the genesis block (height 0) from the certificate blockchain
/// 2. Decrypts the encrypted certificate data using the app private key
/// 3. Returns the certificate DER bytes
///
/// # Arguments
///
/// * `certificate_chain` - Reference to the certificate blockchain database
/// * `app_key_store` - Application key store (provides private key for decryption)
///
/// # Returns
///
/// * `Result<Vec<u8>>` - The Root CA certificate DER bytes on success
///
/// # Errors
///
/// Returns an error if:
/// - No genesis block exists in the certificate blockchain
/// - Decryption fails
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::get_root_ca_certificate;
/// use libblockchainstor::BlockchainDb;
///
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
///
/// let root_ca_der = get_root_ca_certificate(&cert_chain, &app_key_store)?;
/// // Use root_ca_der for certificate operations
/// ```
pub fn get_root_ca_certificate(
    certificate_chain: &BlockchainDb,
    app_key_store: &AppKeyStore,
) -> Result<Vec<u8>> {
    // Retrieve the genesis block (height 0) directly from the height tree
    let (genesis_block, _uid) = certificate_chain.get_block_by_height(0)
        .map_err(|e| anyhow!("Failed to retrieve genesis block: {}", e))?;
    
    let encrypted_bytes = genesis_block.block_data;
    
    // Deserialize encrypted data
    let encrypted_data = HybridEncryptedData::from_bytes(&encrypted_bytes)
        .map_err(|e| anyhow!("Failed to deserialize encrypted data: {}", e))?;
    
    // Decrypt using app private key
    let private_key = app_key_store.get_private_key_rsa()
        .map_err(|e| anyhow!("Failed to get private key: {}", e))?;
    
    let cert_der = hybrid_decrypt(&private_key, &encrypted_data)
        .map_err(|e| anyhow!("Failed to decrypt certificate data: {}", e))?;
    
    Ok(cert_der)
}
