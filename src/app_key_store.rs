use secrecy::{Secret, ExposeSecret};
use libcertcrypto::{PfxContainer, CertificateUsageType};
use anyhow::Result;
use sha2::{Sha256, Digest};
use std::path::Path;
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use rsa::{RsaPublicKey, RsaPrivateKey};

/// Secure in-memory storage for application private key
/// 
/// This struct provides secure storage for the application's private key
/// with automatic memory zeroization on drop. The private key is never
/// exposed in logs or debug output.
pub struct AppKeyStore {
    /// Private key bytes stored securely (zeroized on drop)
    private_key_pem: Secret<String>,
    /// Public key for hybrid encryption operations
    public_key: RsaPublicKey,
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
        // Load PFX container - use User type for application certificates
        let pfx = PfxContainer::load_from_file(
            pfx_path, 
            password, 
            CertificateUsageType::User
        )?;
        
        // Load the private key
        let private_key = pfx.load_private_key()?;
        
        // Extract public key from private key
        let public_key = RsaPublicKey::from(&private_key);
        
        // Convert to PEM format
        let private_key_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to encode private key to PEM: {}", e))?;
        
        let pem_string = private_key_pem.to_string();
        let pem_bytes = pem_string.as_bytes();
        
        // Calculate SHA-256 hash for password derivation
        let mut hasher = Sha256::new();
        hasher.update(pem_bytes);
        let key_hash = format!("{:x}", hasher.finalize());
        
        // Wrap in Secret to prevent accidental exposure
        Ok(Self {
            private_key_pem: Secret::new(pem_string),
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
    /// * `&RsaPublicKey` - Reference to the RSA public key
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
    pub fn get_public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
    
    /// Get the RSA private key for decryption operations
    /// 
    /// This reconstructs the RsaPrivateKey from the stored PEM.
    /// Use for hybrid decryption or other cryptographic operations.
    /// 
    /// # Returns
    /// * `Result<RsaPrivateKey>` - The RSA private key
    /// 
    /// # Example
    /// ```no_run
    /// let private_key = app_key_store.get_private_key_rsa()?;
    /// let decrypted = hybrid_decrypt(&private_key, encrypted_data)?;
    /// ```
    pub fn get_private_key_rsa(&self) -> Result<RsaPrivateKey> {
        RsaPrivateKey::from_pkcs8_pem(self.private_key_pem.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to decode private key from PEM: {}", e))
    }
    
    /// Execute a closure with temporary access to the private key
    /// 
    /// This method provides controlled access to the raw private key bytes.
    /// Use sparingly and ensure the key material is not stored or logged.
    /// 
    /// # Arguments
    /// * `f` - Closure that receives a reference to the private key PEM string
    /// 
    /// # Returns
    /// * `R` - The return value of the closure
    /// 
    /// # Example
    /// ```no_run
    /// key_store.with_private_key(|key_pem| {
    ///     // Use key_pem for cryptographic operations
    ///     // DO NOT store or log the key!
    ///     verify_signature(key_pem)
    /// });
    /// ```
    pub fn with_private_key<F, R>(&self, f: F) -> R 
    where
        F: FnOnce(&str) -> R,
    {
        f(self.private_key_pem.expose_secret())
    }
    
    /// Get a copy of the private key PEM string
    /// 
    /// WARNING: This exposes the private key! Use only when absolutely necessary
    /// and ensure the returned value is properly zeroized after use.
    /// 
    /// # Returns
    /// * `String` - PEM-encoded private key
    pub fn get_private_key_pem(&self) -> String {
        self.private_key_pem.expose_secret().clone()
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
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
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
