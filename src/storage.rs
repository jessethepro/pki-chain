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
//!

#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]

use anyhow::anyhow;
use anyhow::{Context, Result};
use libblockchain::blockchain::BlockChain;
use openssl::pkey::PKey;
use std::path::Path;

use crate::pki_generator::{generate_root_ca, CertificateData};
use crate::private_key_storage::EncryptedKeyStore;

pub const ROOT_CA_SUBJECT_COMMON_NAME: &str = "MenaceLabs Root CA";
pub const API_INTERMEDIATE_CA_COMMON_NAME: &str = "intermediate API CA";
pub const API_TLS_COMMON_NAME: &str = "api.menacelabs.com";

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
    /// Blockchain storing X.509 certificates in PEM format
    pub certificate_chain: BlockChain,
    /// Blockchain storing RSA private keys in DER format
    pub private_chain: BlockChain,
    /// Thread-safe HashMap mapping certificate common names to blockchain heights
    pub subject_name_to_height: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Encrypted key store for private keys
    pub encrypted_key_store: EncryptedKeyStore,
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
    ///         if let Ok(cert) = openssl::x509::X509::from_der(&block.block_data) {
    ///             let subject_name = /* extract from cert */;
    ///             storage.subject_name_to_height.lock().unwrap().insert(subject_name, height as u64);
    /// #           break; // for doc test
    ///         }
    ///     }
    /// }
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new<P: AsRef<Path>>(app_key_path: P) -> Result<Self> {
        let private_key = (|| -> Result<PKey<openssl::pkey::Private>> {
            let pem_path = app_key_path
                .as_ref()
                .to_str()
                .ok_or_else(|| anyhow!("Invalid private key path"))?;

            let pem_data = std::fs::read(pem_path)
                .with_context(|| format!("Failed to read private key from {}", pem_path))?;

            use std::io::Write;
            print!("Enter password for App Key (press Enter if none): ");
            std::io::stdout().flush()?;
            let pwd = rpassword::read_password()?;

            let key = if !pwd.is_empty() {
                PKey::private_key_from_pem_passphrase(&pem_data, pwd.as_bytes())
                    .context("Failed to decrypt private key with password")?
            } else {
                PKey::private_key_from_pem(&pem_data).context("Failed to parse private key PEM")?
            };

            Ok(key)
        })()?;
        let private_chain = BlockChain::new("data/private_keys", private_key.clone())
            .context("Failed to initialize Private Key blockchain")?;
        let certificate_chain = BlockChain::new("data/certificates", private_key.clone())
            .context("Failed to initialize Certificate blockchain")?;
        let encrypted_key_store = EncryptedKeyStore::new(private_key.clone())
            .context("Failed to initialize Encrypted Key Store")?;
        Ok(Storage {
            // Initialize blockchain storage for certificates and private keys
            certificate_chain,
            private_chain,
            subject_name_to_height: std::sync::Mutex::new(std::collections::HashMap::new()),
            encrypted_key_store,
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
        // Check blockchains are in sync
        let cert_block_count = self.certificate_chain.block_count()?;
        let key_block_count = self.private_chain.block_count()?;
        if cert_block_count != key_block_count {
            return Err(anyhow::anyhow!(
                "Certificate and Private Key blockchains are out of sync: certs={}, keys={}",
                cert_block_count,
                key_block_count
            ));
        }
        // Sign certificate der bytes with private key
        // to create matching signatures for both blockchains
        // This ensures that the certificate and private key
        // correspond to each other at the same height
        let certificate_der = certificate.to_der()?;
        let private_key_sig_of_cert = (|| -> Result<Vec<u8>> {
            let mut signer =
                openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &private_key)
                    .context("Failed to create signer for certificate signature")?;
            let signature = signer
                .sign_oneshot_to_vec(&certificate_der)
                .context("Failed to sign certificate block data")?;
            Ok(signature)
        })()?;
        // Save certificate to blockchain as der bytes
        let certificate_height = self
            .certificate_chain
            .put_block(certificate_der)
            .context("Failed to store Root CA certificate in blockchain")?;
        // Store certificate signature
        let cert_signature_height = self
            .certificate_chain
            .put_signature(certificate_height, private_key_sig_of_cert.clone())?;

        // Store private key with rollback on failure
        let private_key_hash = openssl::hash::hash(
            openssl::hash::MessageDigest::sha512(),
            &private_key.private_key_to_der()?,
        )
        .expect("SHA-512 hashing failed")
        .to_vec();

        let private_key_height = self
            .private_chain
            .put_block(private_key_hash)
            .or_else(|e| {
                // Rollback certificate block if private key storage fails
                let _ = self.certificate_chain.delete_latest_block();
                Err(e)
            })?;
        // Store private key signature
        let key_signature_height = self
            .private_chain
            .put_signature(private_key_height, private_key_sig_of_cert.clone())?;
        assert_eq!(
            self.certificate_chain
                .get_signature_by_height(cert_signature_height)?,
            self.private_chain
                .get_signature_by_height(key_signature_height)?,
            "Stored signatures do not match"
        );
        // Store the private key in the encrypted key store
        self.encrypted_key_store
            .store_key(private_key_height, private_key.clone())
            .context("Failed to store private key in encrypted key store")?;

        // Update subject name to height mapping
        let subject_name = certificate
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|data| data.to_string())
            .context("Certificate missing Common Name")?;
        self.subject_name_to_height
            .lock()
            .unwrap()
            .insert(subject_name, certificate_height);
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

    pub fn initialize(&self) -> Result<()> {
        // Initialize Root CA
        let (root_private_key, root_certificate) = generate_root_ca(CertificateData {
            subject_common_name: ROOT_CA_SUBJECT_COMMON_NAME.to_string(),
            issuer_common_name: ROOT_CA_SUBJECT_COMMON_NAME.to_string(),
            organization: "MenaceLabs".to_string(),
            organizational_unit: "CY".to_string(),
            country: "BR".to_string(),
            state: "SP".to_string(),
            locality: "Sao Jose dos Campos".to_string(),
            cert_type: crate::pki_generator::CertificateDataType::RootCA,
            validity_days: 365 * 10, // 10 years
        })
        .context("Failed to generate Root CA")?;
        println!("✓ Root CA generated");
        // Save to blockchain
        let height = self
            .store_key_certificate(&root_private_key, &root_certificate)
            .context("Failed to store Root CA in blockchain")?;
        println!("✓ Root CA certificate and private key stored in blockchain as the genesis block");

        // Verify storage
        if self.verify_stored_key_certificate_pair(&root_private_key, &root_certificate, height)? {
            println!("✓ Stored Root CA key-certificate pair verified successfully");
        } else {
            println!("✗ Verification of stored Root CA key-certificate pair failed");
            return Err(anyhow::anyhow!(
                "Stored Root CA key-certificate pair verification failed"
            ));
        }
        match height {
            0 => Ok(0),
            _ => Err(anyhow::anyhow!(
                "Unexpected height for Root CA storage: {}",
                height
            )),
        }?;
        Ok(())
    }

    pub fn populate_subject_name_index(&self) -> Result<usize> {
        let mut map = self.subject_name_to_height.lock().unwrap();
        map.clear();
        let cert_iter = self.certificate_chain.iter();
        for block_result in cert_iter {
            let block = block_result?;
            let height = block.block_header.height;
            let certificate = openssl::x509::X509::from_der(&block.block_data)
                .context("Failed to parse stored certificate")?;
            let subject_name = certificate
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|entry| entry.data().as_utf8().ok())
                .map(|data| data.to_string())
                .context("Certificate missing Common Name")?;
            map.insert(subject_name, height);
        }
        Ok(map.len())
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
    pub(crate) fn verify_stored_key(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        height: u64,
    ) -> Result<bool> {
        let stored_key = self.encrypted_key_store.retrieve_key(height)?;
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
    pub(crate) fn verify_stored_certificate(
        &self,
        certificate: &openssl::x509::X509,
        height: u64,
    ) -> Result<bool> {
        let stored_cert = {
            let block = self.certificate_chain.get_block_by_height(height)?;
            openssl::x509::X509::from_der(&block.block_data)
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
    pub(crate) fn verify_stored_key_certificate_pair(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        certificate: &openssl::x509::X509,
        height: u64,
    ) -> Result<bool> {
        let key_matches = self.verify_stored_key(private_key, height)?;
        let cert_matches = self.verify_stored_certificate(certificate, height)?;
        Ok(key_matches && cert_matches)
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
    pub fn validate_certificates(&self) -> Result<bool> {
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
