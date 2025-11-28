use libcertcrypto::{PfxContainer, CertificateUsageType};
use std::path::Path;
use anyhow::{Result, anyhow, bail};
use libblockchainstor::BlockchainDb;
use libblockchainstor::libblockchain::traits::BlockHeaderHasher;

/// Store a Root CA PFX file as the genesis block in the PFX blockchain
///
/// This function validates that:
/// 1. The PFX file is a valid Root Certificate Authority
/// 2. No genesis block (height 0) already exists in the blockchain
/// 3. Stores the PFX file as the genesis block if validation passes
///
/// # Arguments
///
/// * `pfx_path` - Path to the Root CA PFX file
/// * `password` - Password to decrypt the PFX file
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `hasher` - Block header hasher for creating the genesis block
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
/// - Database operations fail
///
/// # Example
/// ```no_run
/// use pki_chain::store_root_ca_pfx;
/// use libblockchainstor::BlockchainDb;
/// use libblockchain::hasher::Sha256Hasher;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let hasher = Sha256Hasher::new();
///
/// let (block_uid, height) = store_root_ca_pfx(
///     "RootCA.pfx",
///     "password123",
///     &pfx_chain,
///     &hasher
/// )?;
///
/// assert_eq!(height, 0); // Genesis block
/// ```
pub fn store_root_ca_pfx<P: AsRef<Path>, H: BlockHeaderHasher>(
    pfx_path: P,
    password: &str,
    pfx_chain: &BlockchainDb,
    hasher: &H,
) -> Result<([u8; 16], u32)> {
    // Load and validate the PFX file
    let pfx_container = PfxContainer::load_from_file(
        pfx_path.as_ref(),
        password,
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
    
    // Store as genesis block (will be height 0)
    let (block, height, _signature) = pfx_chain.store_block(hasher, pfx_bytes)
        .map_err(|e| anyhow!("Failed to store genesis block: {}", e))?;
    
    // Verify it's actually the genesis block
    if height != 0 {
        bail!("Expected genesis block (height 0), but got height {}", height);
    }
    
    Ok((block.block_header.block_uid, height))
}


