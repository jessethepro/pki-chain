use libcertcrypto::{PfxContainer, CertificateUsageType, hybrid_encrypt, hybrid_decrypt, HybridEncryptedData};
use std::path::Path;
use anyhow::{Result, anyhow, bail};
use libblockchainstor::BlockchainDb;
use libblockchainstor::libblockchain::BlockHeaderHasher;
use crate::app_key_store::AppKeyStore;

/// Store a Root CA PFX file as the genesis block in the PFX blockchain
///
/// This function validates that:
/// 1. The PFX file is a valid Root Certificate Authority
/// 2. No genesis block (height 0) already exists in the blockchain
/// 3. Encrypts the PFX file using hybrid encryption with the app public key
/// 4. Stores the encrypted PFX as the genesis block if validation passes
///
/// # Arguments
///
/// * `pfx_path` - Path to the Root CA PFX file
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `hasher` - Block header hasher for creating the genesis block
/// * `app_key_store` - Application key store (provides derived password for PFX decryption and public key for encryption)
///
/// # Returns
///
/// * `Result<([u8; 16], u32)>` - The block UID and height (0) on success
///
/// # Errors
///
/// Returns an error if:
/// - The PFX file cannot be loaded
/// - The certificate is not a Root CA
/// - A genesis block already exists in the blockchain
/// - Hybrid encryption fails
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::store_root_ca_pfx;
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
/// let (block_uid, height) = store_root_ca_pfx(
///     "RootCA.pfx",
///     &pfx_chain,
///     &hasher,
///     &app_key_store
/// )?;
///
/// assert_eq!(height, 0); // Genesis block
/// ```
pub fn store_root_ca_pfx<P: AsRef<Path>, H: BlockHeaderHasher>(
    pfx_path: P,
    pfx_chain: &BlockchainDb,
    hasher: &H,
    app_key_store: &AppKeyStore,
) -> Result<([u8; 16], u32)> {
    // Load and validate the PFX file using the derived password from AppKeyStore
    let pfx_container = PfxContainer::load_from_file(
        pfx_path.as_ref(),
        app_key_store.get_derived_password(),
        CertificateUsageType::RootCA,
    ).map_err(|e| anyhow!("Failed to load PFX file: {}", e))?;
    
    // Validate it's a Root CA
    if pfx_container.usage_type != CertificateUsageType::RootCA {
        bail!("PFX file is not a Root CA certificate (type: {:?})", pfx_container.usage_type);
    }
    
    if !pfx_container.is_ca() {
        bail!("PFX file is not a Certificate Authority");
    }
    
    // Check if genesis block (height 0) already exists
    let mut iter = pfx_chain.iter()
        .map_err(|e| anyhow!("Failed to create blockchain iterator: {}", e))?;
    
    // Check if there are any blocks in the chain
    if iter.next().is_some() {
        bail!("Genesis block already exists in the PFX blockchain. Cannot store Root CA.");
    }
    
    // Serialize the PFX container to bytes for storage
    let pfx_bytes = std::fs::read(pfx_path.as_ref())
        .map_err(|e| anyhow!("Failed to read PFX file: {}", e))?;
    
    // Encrypt the PFX bytes using hybrid encryption with the app public key
    let encrypted_data = hybrid_encrypt(app_key_store.get_public_key(), &pfx_bytes)
        .map_err(|e| anyhow!("Failed to encrypt PFX file: {}", e))?;
    
    // Serialize encrypted data to bytes for blockchain storage
    let encrypted_bytes = encrypted_data.to_bytes();
    
    // Store encrypted PFX as genesis block (will be height 0)
    let (block, height, _signature) = pfx_chain.store_block(hasher, encrypted_bytes)
        .map_err(|e| anyhow!("Failed to store genesis block: {}", e))?;
    
    // Verify it's actually the genesis block
    if height != 0 {
        bail!("Expected genesis block (height 0), but got height {}", height);
    }
    
    Ok((block.block_header.block_uid, height))
}

/// Retrieve the Root CA PFX from the genesis block of the PFX blockchain
///
/// This function:
/// 1. Retrieves the genesis block (height 0) from the blockchain
/// 2. Decrypts the encrypted PFX data using the app private key
/// 3. Loads the decrypted PFX bytes into a PfxContainer
/// 4. Validates it's a Root CA certificate
///
/// # Arguments
///
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `app_key_store` - Application key store (provides private key for decryption and derived password)
///
/// # Returns
///
/// * `Result<PfxContainer>` - The Root CA PfxContainer on success
///
/// # Errors
///
/// Returns an error if:
/// - No genesis block exists in the blockchain
/// - Decryption fails
/// - The decrypted data is not a valid PFX file
/// - The PFX is not a Root CA certificate
///
/// # Example
/// ```no_run
/// use pki_chain::get_root_ca_pfx;
/// use libblockchainstor::BlockchainDb;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
///
/// let root_ca = get_root_ca_pfx(&pfx_chain, &app_key_store)?;
/// assert_eq!(root_ca.usage_type, CertificateUsageType::RootCA);
/// ```
pub fn get_root_ca_pfx(
    pfx_chain: &BlockchainDb,
    app_key_store: &AppKeyStore,
) -> Result<PfxContainer> {
    // Retrieve the genesis block (height 0) directly from the height tree
    let (genesis_block, _uid) = pfx_chain.get_block_by_height(0)
        .map_err(|e| anyhow!("Failed to retrieve genesis block: {}", e))?;
    
    let encrypted_bytes = genesis_block.block_data;
    
    // Deserialize encrypted data
    let encrypted_data = HybridEncryptedData::from_bytes(&encrypted_bytes)
        .map_err(|e| anyhow!("Failed to deserialize encrypted data: {}", e))?;
    
    // Decrypt using app private key
    let private_key = app_key_store.get_private_key_rsa()
        .map_err(|e| anyhow!("Failed to get private key: {}", e))?;
    
    let pfx_bytes = hybrid_decrypt(&private_key, &encrypted_data)
        .map_err(|e| anyhow!("Failed to decrypt PFX data: {}", e))?;
    
    // Load PFX container from decrypted bytes using from_pfx
    let pfx_container = PfxContainer::from_pfx(
        &pfx_bytes,
        app_key_store.get_derived_password(),
        CertificateUsageType::RootCA,
    ).map_err(|e| anyhow!("Failed to load PFX from decrypted data: {}", e))?;
    
    // Validate it's a Root CA
    if pfx_container.usage_type != CertificateUsageType::RootCA {
        bail!("Retrieved PFX is not a Root CA certificate (type: {:?})", pfx_container.usage_type);
    }
    
    if !pfx_container.is_ca() {
        bail!("Retrieved PFX is not a Certificate Authority");
    }
    
    Ok(pfx_container)
}

