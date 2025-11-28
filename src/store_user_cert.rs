use libcertcrypto::{hybrid_encrypt, hybrid_decrypt, HybridEncryptedData};
use anyhow::{Result, anyhow};
use libblockchainstor::BlockchainDb;
use libblockchainstor::libblockchain::BlockHeaderHasher;
use crate::app_key_store::AppKeyStore;
use crate::store_user_key::get_user_pfx;

/// Store a User certificate in the certificate blockchain
///
/// This function:
/// 1. Retrieves the User certificate PFX from the PFX blockchain at the specified height
/// 2. Extracts the certificate in DER format
/// 3. Encrypts the DER bytes using hybrid encryption with the app public key
/// 4. Stores the encrypted certificate as a new block in the certificate chain
///
/// # Arguments
///
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `pfx_height` - Height of the User certificate in the PFX blockchain
/// * `certificate_chain` - Reference to the certificate blockchain database
/// * `hasher` - Block header hasher for creating the block
/// * `app_key_store` - Application key store for encryption and PFX retrieval
///
/// # Returns
///
/// * `Result<([u8; 16], u32)>` - The block UID and height on success
///
/// # Errors
///
/// Returns an error if:
/// - No User certificate PFX exists at the specified height in the PFX chain
/// - Certificate extraction fails
/// - Hybrid encryption fails
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::store_user_certificate;
/// use libblockchainstor::BlockchainDb;
/// use libblockchainstor::libblockchain::BlockHeaderHasher;
/// use libcertcrypto::CertificateTools;
///
/// struct Sha256Hasher;
/// impl BlockHeaderHasher for Sha256Hasher {
///     fn hash(&self, data: &[u8]) -> Vec<u8> {
///         CertificateTools::hash_sha256(data).unwrap_or_default()
///     }
///     fn hash_size(&self) -> usize { 32 }
/// }
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
/// let hasher = Sha256Hasher;
///
/// let (block_uid, height) = store_user_certificate(
///     &pfx_chain,
///     2, // Height in PFX chain
///     &cert_chain,
///     &hasher,
///     &app_key_store
/// )?;
/// ```
pub fn store_user_certificate<H: BlockHeaderHasher>(
    pfx_chain: &BlockchainDb,
    pfx_height: u32,
    certificate_chain: &BlockchainDb,
    hasher: &H,
    app_key_store: &AppKeyStore,
) -> Result<([u8; 16], u32)> {
    // Retrieve the User certificate PFX from the PFX blockchain
    let user_pfx = get_user_pfx(pfx_chain, pfx_height, app_key_store)
        .map_err(|e| anyhow!("Failed to retrieve User certificate PFX: {}", e))?;
    
    // Extract the certificate in DER format
    let cert_der = &user_pfx.certificate_der;
    
    // Encrypt the DER bytes using hybrid encryption with the app public key
    let encrypted_data = hybrid_encrypt(app_key_store.get_public_key(), &cert_der)
        .map_err(|e| anyhow!("Failed to encrypt certificate DER: {}", e))?;
    
    // Serialize encrypted data to bytes for blockchain storage
    let encrypted_bytes = encrypted_data.to_bytes();
    
    // Store encrypted certificate as a new block
    let (block, height, _signature) = certificate_chain.store_block(hasher, encrypted_bytes)
        .map_err(|e| anyhow!("Failed to store block: {}", e))?;
    
    Ok((block.block_header.block_uid, height))
}

/// Retrieve a User certificate from the certificate blockchain by height
///
/// This function:
/// 1. Retrieves the block at the specified height from the certificate blockchain
/// 2. Decrypts the encrypted certificate data using the app private key
/// 3. Returns the certificate DER bytes
///
/// # Arguments
///
/// * `certificate_chain` - Reference to the certificate blockchain database
/// * `height` - The height of the block containing the certificate
/// * `app_key_store` - Application key store (provides private key for decryption)
///
/// # Returns
///
/// * `Result<Vec<u8>>` - The User certificate DER bytes on success
///
/// # Errors
///
/// Returns an error if:
/// - No block exists at the specified height in the certificate blockchain
/// - Decryption fails
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::get_user_certificate;
/// use libblockchainstor::BlockchainDb;
///
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
///
/// let user_cert_der = get_user_certificate(&cert_chain, 2, &app_key_store)?;
/// // Use user_cert_der for certificate operations
/// ```
pub fn get_user_certificate(
    certificate_chain: &BlockchainDb,
    height: u32,
    app_key_store: &AppKeyStore,
) -> Result<Vec<u8>> {
    // Retrieve the block at the specified height
    let (block, _uid) = certificate_chain.get_block_by_height(height)
        .map_err(|e| anyhow!("Failed to retrieve block at height {}: {}", height, e))?;
    
    let encrypted_bytes = block.block_data;
    
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
