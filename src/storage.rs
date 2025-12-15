//! Storage Module
//!
//! Provides a unified abstraction over dual blockchain storage for PKI certificate management.
//! This module manages the storage and retrieval of X.509 certificates and their associated
//! private keys in separate blockchain instances, maintaining consistency through signature
//! verification and transactional operations.
//!
//! # Architecture
//!
//! The storage layer uses two parallel blockchain instances:
//! - **Certificate Chain**: Stores X.509 certificates in PEM format
//! - **Private Key Chain**: Stores RSA private keys in DER format
//!
//! Both chains are kept in sync through:
//! 1. Height-based indexing (certificates at height N correspond to keys at height N)
//! 2. Signature verification (each block pair has matching signatures)
//! 3. Transactional rollback (failed key storage rolls back certificate storage)
//!
//! # Example
//!
//! ```no_run
//! use pki_chain::storage::Storage;
//! use anyhow::Result;
//!
//! fn example() -> Result<()> {
//!     let storage = Storage::new("key/app.key")?;
//!     
//!     if storage.is_empty()? {
//!         println!("Blockchain is empty");
//!     }
//!     
//!     if storage.validate()? {
//!         println!("Blockchain validation successful");
//!     }
//!     
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use libblockchain::blockchain::BlockChain;

/// Storage abstraction for PKI certificate and private key blockchain management.
///
/// Manages two parallel blockchain instances that store certificates and their corresponding
/// private keys. Ensures consistency through height-based indexing and signature verification.
///
/// # Fields
///
/// * `certificate_chain` - Blockchain storing X.509 certificates in PEM format
/// * `private_chain` - Blockchain storing RSA private keys in DER format
/// * `subject_name_to_height` - Thread-safe HashMap mapping certificate common names to blockchain heights
///
/// # Thread Safety
///
/// The entire `Storage` struct is typically wrapped in `Arc<Storage>` for safe sharing across threads.
/// The `subject_name_to_height` field uses `Mutex` for concurrent access protection when multiple
/// threads (e.g., socket server connections) need to query or update the mapping.
pub struct Storage {
    // Initialize blockchain storage for certificates and private keys
    pub certificate_chain: BlockChain,
    pub private_chain: BlockChain,
    pub subject_name_to_height: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl Storage {
    /// Creates a new Storage instance with dual blockchain initialization.
    ///
    /// Initializes two separate blockchain instances for certificates and private keys,
    /// using the provided application key for encryption. The `subject_name_to_height`
    /// HashMap is initialized empty and should be populated by the caller (typically
    /// in `start_socket_server()`) by iterating the certificate blockchain.
    ///
    /// # Arguments
    ///
    /// * `app_key_path` - Path to the application encryption key file
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - Storage instance or error if blockchain initialization fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The application key file cannot be read
    /// - Blockchain directories cannot be created
    /// - Database initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pki_chain::storage::Storage;
    /// use std::sync::Arc;
    ///
    /// let storage = Arc::new(Storage::new("key/pki-chain-app.key")?);
    /// // Populate subject_name_to_height from blockchain
    /// for (height, block_result) in storage.certificate_chain.iter().enumerate() {
    ///     if let Ok(block) = block_result {
    ///         if let Ok(cert) = openssl::x509::X509::from_pem(&block.block_data) {
    ///             let subject_name = /* extract from cert */;
    ///             storage.subject_name_to_height.lock().unwrap().insert(subject_name, height as u64);
    /// #           break; // for doc test
    ///         }
    ///     }
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new(app_key_path: &str) -> Result<Self> {
        Ok(Storage {
            // Initialize blockchain storage for certificates and private keys
            certificate_chain: BlockChain::new("data/certificates", app_key_path)?,
            private_chain: BlockChain::new("data/private_keys", app_key_path)?,
            subject_name_to_height: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Stores a certificate and private key pair in their respective blockchains.
    ///
    /// This method performs a transactional operation:
    /// 1. Stores the certificate in the certificate blockchain
    /// 2. Stores the private key in the private key blockchain
    /// 3. Creates matching signatures for both blocks
    /// 4. Rolls back certificate storage if private key storage fails
    ///
    /// # Arguments
    ///
    /// * `private_key` - The RSA private key to store
    /// * `certificate` - The X.509 certificate to store
    ///
    /// # Returns
    ///
    /// * `Result<u64>` - The blockchain height where the pair was stored
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate PEM conversion fails
    /// - Private key DER conversion fails
    /// - Blockchain storage operations fail
    /// - Signature generation or storage fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::storage::Storage;
    /// # use openssl::rsa::Rsa;
    /// # use openssl::pkey::PKey;
    /// # use openssl::x509::X509;
    /// # fn example(storage: &Storage, key: &PKey<openssl::pkey::Private>, cert: &X509) -> anyhow::Result<()> {
    /// let height = storage.store_key_certificate(&key, &cert)?;
    /// println!("Stored at height: {}", height);
    /// # Ok(())
    /// # }
    /// ```
    pub fn store_key_certificate(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        certificate: &openssl::x509::X509,
    ) -> Result<u64> {
        // Save certificate to blockchain
        let certificate_height = self
            .certificate_chain
            .put_block(certificate.to_pem()?)
            .context("Failed to store Root CA certificate in blockchain")?;

        // Store private key with rollback on failure
        let private_key_height = self
            .private_chain
            .put_block(private_key.private_key_to_der()?)
            .or_else(|e| {
                // Rollback certificate block if private key storage fails
                let _ = self.certificate_chain.delete_latest_block();
                Err(e)
            })?;
        if private_key_height == certificate_height {
            let certificate_block = self
                .certificate_chain
                .get_block_by_height(private_key_height)?;
            let certificate_signature: Result<Vec<u8>> = (|| {
                let mut signer = openssl::sign::Signer::new(
                    openssl::hash::MessageDigest::sha256(),
                    &private_key,
                )
                .context("Failed to create signer for certificate signature")?;
                let signature = signer
                    .sign_oneshot_to_vec(&certificate_block.block_data)
                    .context("Failed to sign certificate block data")?;
                Ok(signature)
            })();
            let signature = certificate_signature?;
            let cert_signature_height = self
                .certificate_chain
                .put_signature(private_key_height, signature.clone())?;
            let key_signature_height = self
                .private_chain
                .put_signature(private_key_height, signature)?;
            assert_eq!(
                self.certificate_chain
                    .get_signature_by_height(cert_signature_height)?,
                self.private_chain
                    .get_signature_by_height(key_signature_height)?,
                "Stored signatures do not match"
            );
        }

        Ok(certificate_height)
    }

    /// Checks if both blockchains are empty.
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if both chains have zero blocks, false otherwise
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::storage::Storage;
    /// # fn example(storage: &Storage) -> anyhow::Result<()> {
    /// if storage.is_empty()? {
    ///     println!("No certificates stored yet");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.certificate_chain.block_count()? == 0 && self.private_chain.block_count()? == 0)
    }

    /// Verifies that a private key matches the one stored at the specified height.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key to verify
    /// * `height` - The blockchain height to check
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if keys match, false otherwise
    pub fn verify_stored_key(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        height: u64,
    ) -> Result<bool> {
        let stored_key = {
            let block = self.private_chain.get_block_by_height(height)?;
            openssl::pkey::PKey::private_key_from_der(&block.block_data)
                .context("Failed to parse stored Root CA key")?
        };
        Ok(stored_key.private_key_to_der()? == private_key.private_key_to_der()?)
    }

    /// Verifies that a certificate matches the one stored at the specified height.
    ///
    /// # Arguments
    ///
    /// * `certificate` - The certificate to verify
    /// * `height` - The blockchain height to check
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if certificates match, false otherwise
    pub fn verify_stored_certificate(
        &self,
        certificate: &openssl::x509::X509,
        height: u64,
    ) -> Result<bool> {
        let stored_cert = {
            let block = self.certificate_chain.get_block_by_height(height)?;
            openssl::x509::X509::from_pem(&block.block_data)
                .context("Failed to parse stored Root CA certificate")?
        };
        Ok(stored_cert.to_pem()? == certificate.to_pem()?)
    }

    /// Verifies that both a certificate and private key match those stored at the specified height.
    ///
    /// This is a convenience method that calls both `verify_stored_key` and
    /// `verify_stored_certificate`.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key to verify
    /// * `certificate` - The certificate to verify
    /// * `height` - The blockchain height to check
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if both match, false otherwise
    pub fn verify_stored_key_certificate_pair(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        certificate: &openssl::x509::X509,
        height: u64,
    ) -> Result<bool> {
        Ok(self.verify_stored_key(private_key, height)?
            && self.verify_stored_certificate(certificate, height)?)
    }

    /// Validates the integrity of both blockchains.
    ///
    /// Performs comprehensive validation:
    /// 1. Verifies that certificate and key signatures match at each height
    /// 2. Validates blockchain integrity (hashes, timestamps, etc.)
    /// 3. Ensures both chains have consistent state
    ///
    /// # Returns
    ///
    /// * `Result<bool>` - True if validation succeeds, false if integrity check fails
    ///
    /// # Errors
    ///
    /// Returns an error if blockchain operations fail during validation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::storage::Storage;
    /// # fn example(storage: &Storage) -> anyhow::Result<()> {
    /// if storage.validate()? {
    ///     println!("Blockchain integrity verified");
    /// } else {
    ///     println!("Validation failed - possible tampering detected");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(&self) -> Result<bool> {
        let cert_iter = self.certificate_chain.iter();
        for cert_block in cert_iter {
            let cert_block = cert_block?;
            let height = cert_block.block_header.height;
            let cert_signature = self.certificate_chain.get_signature_by_height(height)?;
            let key_signature = self.private_chain.get_signature_by_height(height)?;
            if cert_signature != key_signature {
                return Ok(false);
            }
        }
        self.certificate_chain.validate()?;
        self.private_chain.validate()?;
        Ok(true)
    }
}
