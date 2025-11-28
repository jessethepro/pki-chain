use anyhow::{Result, anyhow};
use libblockchainstor::BlockchainDb;
use libblockchainstor::libblockchain::traits::BlockHeaderHasher;
use sha2::{Sha256, Digest};

/// SHA-256 hasher implementation for blockchain validation
struct Sha256Hasher;

impl BlockHeaderHasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn hash_size(&self) -> usize {
        32 // SHA-256 produces 32-byte hashes
    }
}

/// Statistics for a blockchain database
#[derive(Debug)]
pub struct BlockchainStats {
    /// Total number of blocks in the blockchain
    pub total_blocks: u32,
    /// Height of the highest block (total_blocks - 1)
    pub highest_block_height: u32,
    /// Whether the blockchain passed validation
    pub is_valid: bool,
    /// Validation error message if validation failed
    pub validation_error: Option<String>,
}

impl BlockchainStats {
    /// Create a new BlockchainStats with default values
    fn new() -> Self {
        Self {
            total_blocks: 0,
            highest_block_height: 0,
            is_valid: false,
            validation_error: None,
        }
    }
}

/// Gather statistics for a blockchain database
///
/// This function:
/// 1. Counts the total number of blocks
/// 2. Finds the highest block height
/// 3. Validates the blockchain integrity
///
/// # Arguments
///
/// * `blockchain` - Reference to the blockchain database
///
/// # Returns
///
/// * `Result<BlockchainStats>` - Statistics about the blockchain
///
/// # Example
/// ```no_run
/// use pki_chain::statistics::get_blockchain_stats;
/// use libblockchainstor::BlockchainDb;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
///
/// let stats = get_blockchain_stats(&pfx_chain)?;
/// println!("Total blocks: {}", stats.total_blocks);
/// ```
pub fn get_blockchain_stats(
    blockchain: &BlockchainDb,
) -> Result<BlockchainStats> {
    let mut stats = BlockchainStats::new();
    
    // Create iterator to count blocks and find highest height
    let mut iter = blockchain.iter()
        .map_err(|e| anyhow!("Failed to create blockchain iterator: {}", e))?;
    
    let mut block_count = 0u32;
    let mut highest_height = 0u32;
    
    // Iterate through all blocks
    while let Some((_uid, _data)) = iter.next() {
        block_count += 1;
    }
    
    // If we have blocks, the highest height is block_count - 1
    if block_count > 0 {
        highest_height = block_count - 1;
    }
    
    stats.total_blocks = block_count;
    stats.highest_block_height = highest_height;
    
    // Validate the blockchain using SHA-256 hasher
    let hasher = Sha256Hasher;
    match blockchain.validate(&hasher) {
        Ok(()) => {
            stats.is_valid = true;
            stats.validation_error = None;
        }
        Err(e) => {
            stats.is_valid = false;
            stats.validation_error = Some(e.to_string());
        }
    }
    
    Ok(stats)
}

/// Print statistics for the PFX and Certificate blockchains
///
/// This function gathers and displays statistics for both blockchain databases,
/// including block counts, heights, and validation status.
///
/// # Arguments
///
/// * `pfx_chain` - Reference to the PFX blockchain database
/// * `certificate_chain` - Reference to the certificate blockchain database
///
/// # Example
/// ```no_run
/// use pki_chain::statistics::print_blockchain_statistics;
/// use libblockchainstor::BlockchainDb;
///
/// let pfx_chain = BlockchainDb::open("../data/pfx")?;
/// let cert_chain = BlockchainDb::open("../data/certificates")?;
///
/// print_blockchain_statistics(&pfx_chain, &cert_chain)?;
/// ```
pub fn print_blockchain_statistics(
    pfx_chain: &BlockchainDb,
    certificate_chain: &BlockchainDb,
) -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║          PKI BLOCKCHAIN STATISTICS                         ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    
    // Get PFX chain statistics
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ PFX BLOCKCHAIN                                              │");
    println!("├─────────────────────────────────────────────────────────────┤");
    
    let pfx_stats = get_blockchain_stats(pfx_chain)?;
    
    if pfx_stats.total_blocks == 0 {
        println!("│ Status: EMPTY                                               │");
        println!("│ No blocks stored in PFX blockchain                          │");
    } else {
        println!("│ Total Blocks:        {:>5}                                  │", pfx_stats.total_blocks);
        println!("│ Highest Block:       {:>5} (height)                         │", pfx_stats.highest_block_height);
        println!("│                                                             │");
        
        if pfx_stats.is_valid {
            println!("│ Validation:          ✓ PASSED                               │");
        } else {
            println!("│ Validation:          ✗ FAILED                               │");
            if let Some(ref error) = pfx_stats.validation_error {
                println!("│ Error:               {}                        │", 
                    truncate_string(error, 38));
            }
        }
    }
    
    println!("└─────────────────────────────────────────────────────────────┘\n");
    
    // Get Certificate chain statistics
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ CERTIFICATE BLOCKCHAIN                                      │");
    println!("├─────────────────────────────────────────────────────────────┤");
    
    let cert_stats = get_blockchain_stats(certificate_chain)?;
    
    if cert_stats.total_blocks == 0 {
        println!("│ Status: EMPTY                                               │");
        println!("│ No blocks stored in Certificate blockchain                 │");
    } else {
        println!("│ Total Blocks:        {:>5}                                  │", cert_stats.total_blocks);
        println!("│ Highest Block:       {:>5} (height)                         │", cert_stats.highest_block_height);
        println!("│                                                             │");
        
        if cert_stats.is_valid {
            println!("│ Validation:          ✓ PASSED                               │");
        } else {
            println!("│ Validation:          ✗ FAILED                               │");
            if let Some(ref error) = cert_stats.validation_error {
                println!("│ Error:               {}                        │", 
                    truncate_string(error, 38));
            }
        }
    }
    
    println!("└─────────────────────────────────────────────────────────────┘\n");
    
    // Overall summary
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ OVERALL SUMMARY                                             │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Total PKI Entries:   {:>5} (PFX + Certificates)             │", 
        pfx_stats.total_blocks + cert_stats.total_blocks);
    
    let all_valid = pfx_stats.is_valid && cert_stats.is_valid;
    if all_valid {
        println!("│ Integrity:           ✓ ALL CHAINS VALID                     │");
    } else {
        println!("│ Integrity:           ✗ VALIDATION ISSUES DETECTED           │");
    }
    
    println!("└─────────────────────────────────────────────────────────────┘\n");
    
    Ok(())
}

/// Truncate a string to a maximum length, adding "..." if truncated
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:<width$}", s, width = max_len)
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
