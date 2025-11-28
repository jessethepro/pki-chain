use libcertcrypto::{PfxContainer, CertificateUsageType, hybrid_encrypt, hybrid_decrypt, HybridEncryptedData};
use std::path::Path;
use anyhow::{Result, anyhow, bail};
use libblockchainstor::BlockchainDb;
use libblockchainstor::libblockchain::BlockHeaderHasher;
use crate::app_key_store::AppKeyStore;

/// Store an Intermediate CA PFX file in the PFX blockchain
///
/// This function validates that:
/// 1. The PFX file is a valid Intermediate Certificate Authority
/// 2. Encrypts the PFX file using hybrid encryption with the app public key
/// 3. Stores the encrypted PFX as a new block in the blockchain
///
/// # Arguments
///
/// * `pfx_path` - Path to the Intermediate CA PFX file
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `hasher` - Block header hasher for creating the block
/// * `app_key_store` - Application key store (provides derived password for PFX decryption and public key for encryption)
///
/// # Returns
///
/// * `Result<([u8; 16], u32)>` - The block UID and height on success
///
/// # Errors
///
/// Returns an error if:
/// - The PFX file cannot be loaded
/// - The certificate is not an Intermediate CA
/// - Hybrid encryption fails
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::store_intermediate_ca_pfx;
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
/// let blockchain = BlockchainDb::open("../data/pfx")?;
/// let hasher = Sha256Hasher;
///
/// let (block_uid, height) = store_intermediate_ca_pfx(
///     "IntermediateCA.pfx",
///     &pfx_chain,
///     &hasher,
///     &app_key_store
/// )?;
/// ```
pub fn store_intermediate_ca_pfx<P: AsRef<Path>, H: BlockHeaderHasher>(
    pfx_path: P,
    pfx_chain: &BlockchainDb,
    hasher: &H,
    app_key_store: &AppKeyStore,
) -> Result<([u8; 16], u32)> {
    // Load and validate the PFX file using the derived password from AppKeyStore
    let pfx_container = PfxContainer::load_from_file(
        pfx_path.as_ref(),
        app_key_store.get_derived_password(),
        CertificateUsageType::IntermediateCA,
    ).map_err(|e| anyhow!("Failed to load PFX file: {}", e))?;
    
    // Validate it's an Intermediate CA
    if pfx_container.usage_type != CertificateUsageType::IntermediateCA {
        bail!("PFX file is not an Intermediate CA certificate (type: {:?})", pfx_container.usage_type);
    }
    
    if !pfx_container.is_ca() {
        bail!("PFX file is not a Certificate Authority");
    }
    
    // Read the PFX file bytes for storage
    let pfx_bytes = std::fs::read(pfx_path.as_ref())
        .map_err(|e| anyhow!("Failed to read PFX file: {}", e))?;
    
    // Encrypt the PFX bytes using hybrid encryption with the app public key
    let encrypted_data = hybrid_encrypt(app_key_store.get_public_key(), &pfx_bytes)
        .map_err(|e| anyhow!("Failed to encrypt PFX file: {}", e))?;
    
    // Serialize encrypted data to bytes for blockchain storage
    let encrypted_bytes = encrypted_data.to_bytes();
    
    // Store encrypted PFX as a new block
    let (block, height, _signature) = pfx_chain.store_block(hasher, encrypted_bytes)
        .map_err(|e| anyhow!("Failed to store block: {}", e))?;
    
    Ok((block.block_header.block_uid, height))
}

/// Retrieve an Intermediate CA PFX from the PFX blockchain by height
///
/// This function:
/// 1. Retrieves the block at the specified height from the blockchain
/// 2. Decrypts the encrypted PFX data using the app private key
/// 3. Loads the decrypted PFX bytes into a PfxContainer
/// 4. Validates it's an Intermediate CA certificate
///
/// # Arguments
///
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `height` - The height of the block containing the Intermediate CA
/// * `app_key_store` - Application key store (provides private key for decryption and derived password)
///
/// # Returns
///
/// * `Result<PfxContainer>` - The Intermediate CA PfxContainer on success
///
/// # Errors
///
/// Returns an error if:
/// - No block exists at the specified height
/// - Decryption fails
/// - The decrypted data is not a valid PFX file
/// - The PFX is not an Intermediate CA certificate
///
/// # Example
/// ```no_run
/// use pki_chain::get_intermediate_ca_pfx;
/// use libblockchainstor::BlockchainDb;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
///
/// let intermediate_ca = get_intermediate_ca_pfx(&pfx_chain, 1, &app_key_store)?;
/// assert_eq!(intermediate_ca.usage_type, CertificateUsageType::IntermediateCA);
/// ```
pub fn get_intermediate_ca_pfx(
    pfx_chain: &BlockchainDb,
    height: u32,
    app_key_store: &AppKeyStore,
) -> Result<PfxContainer> {
    // Retrieve the block at the specified height
    let (block, _uid) = pfx_chain.get_block_by_height(height)
        .map_err(|e| anyhow!("Failed to retrieve block at height {}: {}", height, e))?;
    
    let encrypted_bytes = block.block_data;
    
    // Deserialize encrypted data
    let encrypted_data = HybridEncryptedData::from_bytes(&encrypted_bytes)
        .map_err(|e| anyhow!("Failed to deserialize encrypted data: {}", e))?;
    
    // Decrypt using app private key
    let private_key = app_key_store.get_private_key_rsa()
        .map_err(|e| anyhow!("Failed to get private key: {}", e))?;
    
    let pfx_bytes = hybrid_decrypt(&private_key, &encrypted_data)
        .map_err(|e| anyhow!("Failed to decrypt PFX data: {}", e))?;
    
    // Load PFX container from decrypted bytes
    let pfx_container = PfxContainer::from_pfx(
        &pfx_bytes,
        app_key_store.get_derived_password(),
        CertificateUsageType::IntermediateCA,
    ).map_err(|e| anyhow!("Failed to load PFX from decrypted data: {}", e))?;
    
    // Validate it's an Intermediate CA
    if pfx_container.usage_type != CertificateUsageType::IntermediateCA {
        bail!("Retrieved PFX is not an Intermediate CA certificate (type: {:?})", pfx_container.usage_type);
    }
    
    if !pfx_container.is_ca() {
        bail!("Retrieved PFX is not a Certificate Authority");
    }
    
    Ok(pfx_container)
}
