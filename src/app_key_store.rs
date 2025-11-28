use secrecy::{Secret, ExposeSecret};
use libcertcrypto::{PfxContainer, CertificateUsageType, CertificateTools, PKey, Private, Public};
use anyhow::Result;
use std::path::Path;

/// Secure in-memory storage for application private key
/// 
/// This struct provides secure storage for the application's private key
/// with automatic memory zeroization on drop. The private key is never
/// exposed in logs or debug output.
pub struct AppKeyStore {
    /// Private key stored securely (zeroized on drop)
    private_key: Secret<Vec<u8>>,
    /// Public key for hybrid encryption operations  
    public_key: PKey<Public>,
    /// SHA-256 hash of the private key (used for password derivation)
    key_hash: String,
}

impl AppKeyStore {
    /// Load application PFX file and extract private key securely
    /// 
    /// # Arguments
    /// * `pfx_path` - Path to the application PFX file
    /// * `password` - Password to decrypt the PFX file
    /// 
    /// # Returns
    /// * `Result<Self>` - AppKeyStore instance with private key loaded
    /// 
    /// # Example
    /// ```no_run
    /// use pki_chain::AppKeyStore;
    /// 
    /// let key_store = AppKeyStore::load_from_pfx(
    ///     "key/pki-chain-app.pfx",
    ///     "my-secure-password"
    /// )?;
    /// ```
    pub fn load_from_pfx<P: AsRef<Path>>(pfx_path: P, password: &str) -> Result<Self> {
        // Load PFX container - use Application type for self-signed application certificates
        let pfx_bytes = std::fs::read(pfx_path)?;
        let pfx = PfxContainer::from_pfx(&pfx_bytes, password, CertificateUsageType::Application)?;
        
        // Load the private key (OpenSSL PKey)
        let private_key = pfx.load_private_key()?;
        
        // Extract public key from private key  
        let public_key = pfx.load_public_key()?;
        
        // Get private key DER for hashing
        let private_key_der = private_key.private_key_to_der()
            .map_err(|e| anyhow::anyhow!("Failed to encode private key to DER: {}", e))?;
        
        // Calculate SHA-256 hash for password derivation
        let hash_bytes = CertificateTools::hash_sha256(&private_key_der)?;
        let key_hash = hex::encode(hash_bytes);
        
        // Wrap in Secret to prevent accidental exposure
        Ok(Self {
            private_key: Secret::new(private_key_der),
            public_key,
            key_hash,
        })
    }
    
    /// Get the derived password (SHA-256 hash) for PKI operations
    /// 
    /// This password is used for all CA and user certificates in the PKI chain.
    /// It's derived from the SHA-256 hash of the application's private key.
    /// 
    /// # Returns
    /// * `&str` - The SHA-256 hash as a hexadecimal string
    pub fn get_derived_password(&self) -> &str {
        &self.key_hash
    }
    
    /// Get a reference to the public key for hybrid encryption
    /// 
    /// Use this to encrypt AES keys in hybrid encryption operations.
    /// 
    /// # Returns
    /// * `&PKey<Public>` - Reference to the OpenSSL public key
    /// 
    /// # Example
    /// ```no_run
    /// use libcertcrypto::hybrid_encrypt;
    /// 
    /// let encrypted = hybrid_encrypt(
    ///     app_key_store.get_public_key(),
    ///     plaintext_data
    /// )?;
    /// ```
    pub fn get_public_key(&self) -> &PKey<Public> {
        &self.public_key
    }
    
    /// Get the RSA private key for decryption operations
    /// 
    /// This reconstructs the PKey from the stored DER.
    /// Use for hybrid decryption or other cryptographic operations.
    /// 
    /// # Returns
    /// * `Result<PKey<Private>>` - The OpenSSL private key
    /// 
    /// # Example
    /// ```no_run
    /// let private_key = app_key_store.get_private_key_rsa()?;
    /// let decrypted = hybrid_decrypt(&private_key, encrypted_data)?;
    /// ```
    pub fn get_private_key_rsa(&self) -> Result<PKey<Private>> {
        PKey::private_key_from_der(self.private_key.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to decode private key from DER: {}", e))
    }
    
    /// Execute a closure with temporary access to the private key
    /// 
    /// This method provides controlled access to the raw private key bytes.
    /// Use sparingly and ensure the key material is not stored or logged.
    /// 
    /// # Arguments
    /// * `f` - Closure that receives a reference to the private key DER bytes
    /// 
    /// # Returns
    /// * `R` - The return value of the closure
    /// 
    /// # Example
    /// ```no_run
    /// key_store.with_private_key(|key_der| {
    ///     // Use key_der for cryptographic operations
    ///     // DO NOT store or log the key!
    ///     verify_signature(key_der)
    /// });
    /// ```
    pub fn with_private_key<F, R>(&self, f: F) -> R 
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.private_key.expose_secret())
    }
    
    /// Get a copy of the private key DER bytes
    /// 
    /// WARNING: This exposes the private key! Use only when absolutely necessary
    /// and ensure the returned value is properly zeroized after use.
    /// 
    /// # Returns
    /// * `Vec<u8>` - DER-encoded private key
    pub fn get_private_key_der(&self) -> Vec<u8> {
        self.private_key.expose_secret().clone()
    }
    
    /// Calculate SHA-256 hash of arbitrary data using the same algorithm
    /// 
    /// This is a utility method for consistent hashing across the application.
    /// 
    /// # Arguments
    /// * `data` - Data to hash
    /// 
    /// # Returns
    /// * `String` - SHA-256 hash as hexadecimal string
    pub fn hash_sha256(data: &[u8]) -> String {
        CertificateTools::hash_sha256(data)
            .map(|bytes| hex::encode(bytes))
            .unwrap_or_else(|_| String::new())
    }
}

// secrecy::Secret automatically zeroizes memory on drop
// This implementation is here for documentation purposes
impl Drop for AppKeyStore {
    fn drop(&mut self) {
        // The Secret<Vec<u8>> will be zeroized automatically
        // when it goes out of scope, ensuring the private key
        // is securely erased from memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_sha256() {
        let data = b"test data";
        let hash1 = AppKeyStore::hash_sha256(data);
        let hash2 = AppKeyStore::hash_sha256(data);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be 64 hex characters (256 bits)
        assert_eq!(hash1.len(), 64);
    }
    
    #[test]
    fn test_hash_sha256_different_inputs() {
        let hash1 = AppKeyStore::hash_sha256(b"data1");
        let hash2 = AppKeyStore::hash_sha256(b"data2");
        
        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }
}
