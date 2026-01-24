//! Storage Layer for PKI Certificate Authority
//!
//! This module implements the storage layer for managing X.509 certificates,
//! private keys, and Certificate Revocation Lists (CRLs) using blockchain technology.
//!
//! # Architecture
//!
//! The storage layer uses three separate blockchains:
//! - **Certificates**: Stores X.509 certificates (encrypted with app.crt public key)
//! - **Private Keys**: Stores private key hashes and signatures (encrypted with Root CA public key)
//! - **CRL**: Stores Certificate Revocation Lists (encrypted with app.crt public key)
//!
//! # State Machine
//!
//! Storage follows a typestate pattern with three states:
//! - `NoExist`: Fresh installation, no blockchains exist
//! - `Initialized`: Blockchains exist, Root CA created at height 0
//! - `Ready`: First admin user + intermediate CA created (heights 1, 2)
//!
//! # Modes
//!
//! - **API Mode**: Read-only access to certificates and CRL (no private keys)
//! - **Admin Mode**: Full access including private key blockchain
//!
//! # Encryption
//!
//! - Certificate/CRL blockchain: Encrypted with app.crt public key
//! - Private key blockchain: Encrypted with Root CA public key
//! - Root CA private key: PKCS#8 password-protected in genesis block

#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]

use crate::configs::AppConfig;
use crate::encryption::{deserialize_encrypted_data, EncryptedData};
use crate::pki_generator::{
    generate_key_pair, generate_root_ca, CertificateData, CertificateDataType,
};
use anyhow::{anyhow, Context, Result};
use libblockchain::blockchain::{
    open_read_only_chain, open_read_write_chain, BlockChain, ReadOnly, ReadWrite,
};
use openssl::pkey::{PKey, Public};
use openssl::symm::Cipher;
use openssl::x509::X509;
use std::collections::HashMap;
use std::fs;

/// Represents the current state of the storage system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageState {
    /// Blockchains do not exist or are empty
    NoExist,
    /// Blockchains exist with Root CA at height 0
    Initialized,
    /// First admin user and intermediate CA have been created
    Ready,
}

/// State: CA system does not exist yet (fresh installation)
pub struct NoExist {
    config: AppConfig,
}

/// State: Blockchains exist and Root CA has been created
pub struct Initialized {
    certificate_chain: BlockChain<ReadWrite>,
    private_key_chain: BlockChain<ReadWrite>,
    crl_chain: BlockChain<ReadWrite>,
    app_public_key: PKey<Public>,
    root_ca_cert: X509,
    subject_name_to_height: HashMap<String, u64>,
}

/// State: First admin user and intermediate CA have been created
pub struct Ready {
    certificate_chain: BlockChain<ReadWrite>,
    private_key_chain: BlockChain<ReadWrite>,
    crl_chain: BlockChain<ReadWrite>,
    app_public_key: PKey<Public>,
    root_ca_cert: X509,
    admin_intermediate_height: u64,
    admin_user_height: u64,
    subject_name_to_height: HashMap<String, u64>,
}

/// Main storage container with typestate pattern
pub struct Storage<State> {
    state: State,
}

// ============================================================================
// Storage<NoExist> - Initial state, check if blockchains exist
// ============================================================================

impl Storage<NoExist> {
    /// Create a new storage instance in NoExist state
    ///
    /// Checks if blockchains exist on disk. Does not create them.
    pub fn new() -> Result<Self> {
        let config = AppConfig::load().context("Failed to load configuration")?;

        Ok(Storage {
            state: NoExist { config },
        })
    }

    /// Check if blockchains already exist on disk
    pub fn blockchains_exist(&self) -> bool {
        let cert_exists = self.state.config.blockchains.certificate_path.exists();
        let key_exists = self.state.config.blockchains.private_key_path.exists();
        let crl_exists = self.state.config.blockchains.crl_path.exists();

        cert_exists && key_exists && crl_exists
    }

    /// Initialize the CA system: create blockchains and Root CA
    ///
    /// # Arguments
    ///
    /// * `root_ca_password` - Password to protect Root CA private key (PKCS#8)
    ///
    /// # State Transition
    ///
    /// NoExist -> Initialized
    pub fn initialize(self, root_ca_password: String) -> Result<Storage<Initialized>> {
        let config = &self.state.config;

        println!("🔧 Initializing PKI Certificate Authority...");

        // Load application public key for encrypting certificate/CRL data
        let app_public_key = Self::load_app_public_key(config)?;
        println!("✓ Application public key loaded");

        // Create blockchain directories if they don't exist
        fs::create_dir_all(&config.blockchains.certificate_path)
            .context("Failed to create certificate blockchain directory")?;
        fs::create_dir_all(&config.blockchains.private_key_path)
            .context("Failed to create private key blockchain directory")?;

        fs::create_dir_all(&config.blockchains.crl_path)
            .context("Failed to create CRL blockchain directory")?;

        // Open blockchains in read-write mode
        let certificate_chain = open_read_write_chain(config.blockchains.certificate_path.clone())
            .context("Failed to open certificate blockchain")?;
        println!("✓ Certificate blockchain opened");

        let private_key_chain = open_read_write_chain(config.blockchains.private_key_path.clone())
            .context("Failed to open private key blockchain")?;
        println!("✓ Private key blockchain opened");

        let crl_chain = open_read_write_chain(config.blockchains.crl_path.clone())
            .context("Failed to open CRL blockchain")?;
        println!("✓ CRL blockchain opened");

        // Check if Root CA already exists
        if certificate_chain.block_count()? > 0 {
            return Err(anyhow!(
                "Blockchains already contain data. Use open() instead."
            ));
        }

        // Generate Root CA
        println!("🔐 Generating Root CA...");
        let (root_private_key, root_ca_cert) = generate_root_ca(CertificateData {
            subject_common_name: config.root_ca_defaults.root_ca_common_name.clone(),
            issuer_common_name: config.root_ca_defaults.root_ca_common_name.clone(),
            organization: config.root_ca_defaults.root_ca_organization.clone(),
            organizational_unit: config.root_ca_defaults.root_ca_organizational_unit.clone(),
            country: config.root_ca_defaults.root_ca_country.clone(),
            state: config.root_ca_defaults.root_ca_state.clone(),
            locality: config.root_ca_defaults.root_ca_locality.clone(),
            cert_type: CertificateDataType::RootCA,
            validity_days: config.root_ca_defaults.root_ca_validity_days,
            is_admin: false,
        })?;
        println!("✓ Root CA generated");

        // Encrypt Root CA certificate with app public key
        let encrypted_cert =
            EncryptedData::encrypt_data(root_ca_cert.to_der()?, app_public_key.clone())?;

        // Store Root CA certificate at height 0
        let cert_height = certificate_chain.put_block(encrypted_cert.serialize_encrypted_data())?;
        assert_eq!(cert_height, 0, "Root CA certificate must be at height 0");
        println!("✓ Root CA certificate stored at height 0");

        // Encrypt Root CA private key with password (PKCS#8)
        let encrypted_root_key = root_private_key.private_key_to_pem_pkcs8_passphrase(
            Cipher::aes_256_cbc(),
            root_ca_password.as_bytes(),
        )?;

        // Store encrypted Root CA private key at height 0
        let key_height = private_key_chain.put_block(encrypted_root_key)?;
        assert_eq!(key_height, 0, "Root CA private key must be at height 0");
        println!("✓ Root CA private key stored at height 0 (PKCS#8 encrypted)");

        // Initialize empty CRL blockchain (no genesis block needed)
        println!("✓ CRL blockchain initialized (empty)");

        // Build subject name index
        let mut subject_name_to_height = HashMap::new();
        let root_subject = root_ca_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|data| data.to_string())
            .context("Root CA missing Common Name")?;
        subject_name_to_height.insert(root_subject, 0);

        println!("✅ PKI Certificate Authority initialized successfully!");

        Ok(Storage {
            state: Initialized {
                certificate_chain,
                private_key_chain,
                crl_chain,
                app_public_key,
                root_ca_cert,
                subject_name_to_height,
            },
        })
    }

    /// Load application public key from certificate file
    fn load_app_public_key(config: &AppConfig) -> Result<PKey<Public>> {
        let cert_pem = fs::read(&config.key_exports.app_cert_path).with_context(|| {
            format!(
                "Failed to read application certificate from {}",
                config.key_exports.app_cert_path.display()
            )
        })?;

        let cert = X509::from_pem(&cert_pem).context("Failed to parse application certificate")?;

        let public_key = cert
            .public_key()
            .context("Failed to extract public key from certificate")?;

        Ok(public_key)
    }
}

// ============================================================================
// Storage<Initialized> - Root CA exists, can create admin user
// ============================================================================

impl Storage<Initialized> {
    /// Open existing blockchains in Initialized state
    ///
    /// Verifies Root CA exists at height 0 in all required blockchains.
    pub fn open() -> Result<Self> {
        let config = AppConfig::load().context("Failed to load configuration")?;

        // Load application public key
        let app_public_key = Storage::<NoExist>::load_app_public_key(&config)?;

        // Open blockchains
        let certificate_chain = open_read_write_chain(config.blockchains.certificate_path.clone())
            .context("Failed to open certificate blockchain")?;

        let private_key_chain = open_read_write_chain(config.blockchains.private_key_path.clone())
            .context("Failed to open private key blockchain")?;

        let crl_chain = open_read_write_chain(config.blockchains.crl_path.clone())
            .context("Failed to open CRL blockchain")?;

        // Verify Root CA exists at height 0
        if certificate_chain.block_count()? < 1 {
            return Err(anyhow!("Certificate blockchain is empty - Root CA missing"));
        }

        if private_key_chain.block_count()? < 1 {
            return Err(anyhow!(
                "Private key blockchain is empty - Root CA key missing"
            ));
        }

        // Load and decrypt Root CA certificate
        let root_ca_block = certificate_chain.get_block_by_height(0)?;
        let encrypted_cert_data = deserialize_encrypted_data(&root_ca_block.block_data())?;

        // Load app private key to decrypt
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        let root_cert_der = encrypted_cert_data.decrypt_data(app_private_key)?;
        let root_ca_cert =
            X509::from_der(&root_cert_der).context("Failed to parse Root CA certificate")?;

        // Build subject name index
        let mut subject_name_to_height = HashMap::new();
        let root_subject = root_ca_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|data| data.to_string())
            .context("Root CA missing Common Name")?;
        subject_name_to_height.insert(root_subject, 0);

        Ok(Storage {
            state: Initialized {
                certificate_chain,
                private_key_chain,
                crl_chain,
                app_public_key,
                root_ca_cert,
                subject_name_to_height,
            },
        })
    }

    /// Create first admin user with intermediate CA
    ///
    /// # Arguments
    ///
    /// * `admin_data` - Certificate data for admin user
    /// * `root_ca_password` - Password to unlock Root CA private key
    ///
    /// # Returns
    ///
    /// Tuple of (Storage<Ready>, admin_cert_pem, admin_key_pem)
    ///
    /// # State Transition
    ///
    /// Initialized -> Ready
    pub fn create_admin(
        self,
        admin_data: CertificateData,
        root_ca_password: String,
    ) -> Result<(Storage<Ready>, Vec<u8>, Vec<u8>)> {
        println!("👤 Creating first admin user...");

        // Load Root CA private key
        let root_key_block = self.state.private_key_chain.get_block_by_height(0)?;
        let root_private_key = PKey::private_key_from_pem_passphrase(
            &root_key_block.block_data(),
            root_ca_password.as_bytes(),
        )
        .context("Failed to decrypt Root CA private key - invalid password?")?;
        println!("✓ Root CA private key unlocked");

        // Generate admin intermediate CA
        let (admin_intermediate_key, admin_intermediate_cert) = generate_key_pair(
            CertificateData {
                subject_common_name: "Admin User Intermediate".to_string(),
                issuer_common_name: self
                    .state
                    .root_ca_cert
                    .subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .next()
                    .and_then(|e| e.data().as_utf8().ok())
                    .map(|d| d.to_string())
                    .context("Root CA missing CN")?,
                organization: admin_data.organization.clone(),
                organizational_unit: admin_data.organizational_unit.clone(),
                country: admin_data.country.clone(),
                state: admin_data.state.clone(),
                locality: admin_data.locality.clone(),
                cert_type: CertificateDataType::IntermediateCA,
                validity_days: 365 * 5, // 5 years
                is_admin: false,
            },
            &root_private_key,
        )?;
        println!("✓ Admin intermediate CA generated");

        // Encrypt and store intermediate CA certificate
        let encrypted_intermediate_cert = EncryptedData::encrypt_data(
            admin_intermediate_cert.to_der()?,
            self.state.app_public_key.clone(),
        )?;
        let admin_intermediate_height = self
            .state
            .certificate_chain
            .put_block(encrypted_intermediate_cert.serialize_encrypted_data())?;
        println!(
            "✓ Admin intermediate CA stored at height {}",
            admin_intermediate_height
        );

        // Encrypt and store intermediate CA private key (with App public key)
        let encrypted_intermediate_key = EncryptedData::encrypt_data(
            admin_intermediate_key.private_key_to_der()?,
            self.state.app_public_key.clone(),
        )?;
        self.state
            .private_key_chain
            .put_block(encrypted_intermediate_key.serialize_encrypted_data())?;
        println!("✓ Admin intermediate CA private key stored");

        // Get admin intermediate CA CN for user cert issuer
        let admin_intermediate_cn = admin_intermediate_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .context("Admin intermediate CA missing CN")?;

        // Generate admin user certificate
        let admin_user_data = CertificateData {
            issuer_common_name: admin_intermediate_cn,
            ..admin_data
        };
        let (admin_user_key, admin_user_cert) =
            generate_key_pair(admin_user_data, &admin_intermediate_key)?;
        println!("✓ Admin user certificate generated");

        // Encrypt and store admin user certificate
        let encrypted_user_cert = EncryptedData::encrypt_data(
            admin_user_cert.to_der()?,
            self.state.app_public_key.clone(),
        )?;
        let admin_user_height = self
            .state
            .certificate_chain
            .put_block(encrypted_user_cert.serialize_encrypted_data())?;
        println!(
            "✓ Admin user certificate stored at height {}",
            admin_user_height
        );

        // Encrypt and store admin user private key (with App public key)
        let encrypted_user_key = EncryptedData::encrypt_data(
            admin_user_key.private_key_to_der()?,
            self.state.app_public_key.clone(),
        )?;
        self.state
            .private_key_chain
            .put_block(encrypted_user_key.serialize_encrypted_data())?;
        println!("✓ Admin user private key stored");

        // Update subject name index
        let mut subject_name_to_height = self.state.subject_name_to_height;

        let intermediate_subject = admin_intermediate_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .context("Intermediate CA missing CN")?;
        subject_name_to_height.insert(intermediate_subject, admin_intermediate_height);

        let user_subject = admin_user_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .context("User cert missing CN")?;
        subject_name_to_height.insert(user_subject, admin_user_height);

        println!("✅ First admin user created successfully!");

        // Export certificate and private key as PEM for download
        let admin_cert_pem = admin_user_cert.to_pem()?;
        let admin_key_pem = admin_user_key.private_key_to_pem_pkcs8()?;

        Ok((
            Storage {
                state: Ready {
                    certificate_chain: self.state.certificate_chain,
                    private_key_chain: self.state.private_key_chain,
                    crl_chain: self.state.crl_chain,
                    app_public_key: self.state.app_public_key,
                    root_ca_cert: self.state.root_ca_cert,
                    admin_intermediate_height,
                    admin_user_height,
                    subject_name_to_height,
                },
            },
            admin_cert_pem,
            admin_key_pem,
        ))
    }
}

// ============================================================================
// Storage<Ready> - Admin exists, system ready for operations
// ============================================================================

impl Storage<Ready> {
    /// Open existing blockchains in Ready state
    ///
    /// Verifies Root CA and admin user exist in blockchains.
    pub fn open() -> Result<Self> {
        let config = AppConfig::load().context("Failed to load configuration")?;

        // Load application keys
        let app_public_key = Storage::<NoExist>::load_app_public_key(&config)?;
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        // Open blockchains
        let certificate_chain = open_read_write_chain(config.blockchains.certificate_path.clone())
            .context("Failed to open certificate blockchain")?;

        let private_key_chain = open_read_write_chain(config.blockchains.private_key_path.clone())
            .context("Failed to open private key blockchain")?;

        let crl_chain = open_read_write_chain(config.blockchains.crl_path.clone())
            .context("Failed to open CRL blockchain")?;

        // Verify minimum blocks exist (Root CA + Intermediate + User = 3)
        let cert_count = certificate_chain.block_count()?;
        if cert_count < 3 {
            return Err(anyhow!("Certificate blockchain has {} blocks, need at least 3 (Root + Intermediate + User)", cert_count));
        }

        // Load Root CA certificate
        let root_ca_block = certificate_chain.get_block_by_height(0)?;
        let encrypted_cert_data = deserialize_encrypted_data(&root_ca_block.block_data())?;
        let root_cert_der = encrypted_cert_data.decrypt_data(app_private_key.clone())?;
        let root_ca_cert =
            X509::from_der(&root_cert_der).context("Failed to parse Root CA certificate")?;

        // Admin is typically at heights 1 (intermediate) and 2 (user)
        let admin_intermediate_height = 1;
        let admin_user_height = 2;

        // Build subject name index by iterating through all certificates
        let mut subject_name_to_height = HashMap::new();
        let cert_count = certificate_chain.block_count()?;

        for height in 0..cert_count {
            let block = certificate_chain.get_block_by_height(height)?;
            let encrypted_cert_data = deserialize_encrypted_data(&block.block_data())?;
            let cert_der = encrypted_cert_data.decrypt_data(app_private_key.clone())?;
            let cert = X509::from_der(&cert_der).context("Failed to parse certificate")?;

            let subject_cn = cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok())
                .map(|d| d.to_string())
                .context("Certificate missing CN")?;

            subject_name_to_height.insert(subject_cn, height);
        }

        Ok(Storage {
            state: Ready {
                certificate_chain,
                private_key_chain,
                crl_chain,
                app_public_key,
                root_ca_cert,
                admin_intermediate_height,
                admin_user_height,
                subject_name_to_height,
            },
        })
    }

    /// Get certificate count
    pub fn certificate_count(&self) -> Result<u64> {
        self.state.certificate_chain.block_count()
    }

    /// Get CRL count
    pub fn crl_count(&self) -> Result<u64> {
        self.state.crl_chain.block_count()
    }

    /// List all intermediate CA common names
    pub fn list_intermediate_cas(&self) -> Result<Vec<String>> {
        let config = AppConfig::load().context("Failed to load config")?;
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        let mut intermediate_cas = Vec::new();
        let cert_count = self.state.certificate_chain.block_count()?;

        // Get Root CA CN for comparison
        let root_ca_cn = self
            .state
            .root_ca_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .context("Root CA missing CN")?;

        // Skip height 0 (Root CA), check all other certificates
        for height in 1..cert_count {
            let block = self.state.certificate_chain.get_block_by_height(height)?;
            let encrypted_cert_data = deserialize_encrypted_data(&block.block_data())?;
            let cert_der = encrypted_cert_data.decrypt_data(app_private_key.clone())?;
            let cert = X509::from_der(&cert_der).context("Failed to parse certificate")?;

            // Check if this is an intermediate CA:
            // 1. Issued by Root CA (issuer CN matches Root CA CN)
            // 2. Subject CN contains "Intermediate CA" (naming convention)
            let issuer_cn = cert
                .issuer_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok())
                .map(|d| d.to_string());

            let subject_cn = cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok())
                .map(|d| d.to_string())
                .context("Certificate missing CN")?;

            // Check if this is an intermediate CA:
            // 1. Issued by Root CA (issuer CN matches Root CA CN)
            // 2. NOT a user certificate (user certs have " Admin" in OU or are signed by intermediate)
            // Simple heuristic: anything issued directly by Root CA is an intermediate CA
            if let Some(issuer) = issuer_cn {
                if issuer == root_ca_cn {
                    // This certificate was issued by Root CA, so it's an intermediate CA
                    intermediate_cas.push(subject_cn);
                }
            }
        }

        Ok(intermediate_cas)
    }

    /// Get certificate by subject common name
    pub fn get_certificate_by_subject(&self, subject_cn: &str) -> Result<Option<X509>> {
        if let Some(&height) = self.state.subject_name_to_height.get(subject_cn) {
            let block = self.state.certificate_chain.get_block_by_height(height)?;

            // Load app private key to decrypt
            let config = AppConfig::load().context("Failed to load config")?;
            let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
                .context("Failed to read application private key")?;
            let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
                .context("Failed to parse application private key")?;

            // Decrypt certificate
            let encrypted_cert_data = deserialize_encrypted_data(&block.block_data())?;
            let cert_der = encrypted_cert_data.decrypt_data(app_private_key)?;
            let cert = X509::from_der(&cert_der).context("Failed to parse certificate")?;

            Ok(Some(cert))
        } else {
            Ok(None)
        }
    }

    /// Create intermediate CA certificate signed by Root CA
    ///
    /// # Arguments
    ///
    /// * `cert_data` - Certificate data for the intermediate CA
    /// * `root_ca_password` - Password to decrypt Root CA private key
    ///
    /// # Returns
    ///
    /// Tuple of (certificate_pem, private_key_pem) for download
    pub fn create_intermediate(
        &self,
        cert_data: CertificateData,
        root_ca_password: String,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        println!("🔧 Creating intermediate CA...");

        // Load Root CA private key from blockchain
        let root_key_block = self.state.private_key_chain.get_block_by_height(0)?;
        let root_private_key = PKey::private_key_from_pem_passphrase(
            &root_key_block.block_data(),
            root_ca_password.as_bytes(),
        )
        .context("Failed to decrypt Root CA private key - invalid password?")?;
        println!("✓ Root CA private key unlocked");

        // Set issuer to Root CA common name
        let root_ca_cn = self
            .state
            .root_ca_cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .context("Root CA missing CN")?;

        let cert_data_with_issuer = CertificateData {
            issuer_common_name: root_ca_cn,
            is_admin: false,
            ..cert_data
        };

        // Generate intermediate CA certificate
        let (intermediate_key, intermediate_cert) =
            generate_key_pair(cert_data_with_issuer, &root_private_key)?;
        println!("✓ Intermediate CA certificate generated");

        // Generate self signature for blockchain integrity check between
        // private key and certificate chains
        let self_signature = || -> Result<Vec<u8>> {
            let mut signer = openssl::sign::Signer::new(
                openssl::hash::MessageDigest::sha256(),
                &intermediate_key,
            )
            .context("Failed to create signer for self-signature")?;
            signer
                .update(&intermediate_cert.to_der()?)
                .context("Failed to update signer with certificate data")?;
            let signature = signer
                .sign_to_vec()
                .context("Failed to generate self-signature")?;
            Ok(signature)
        }()?;

        // Encrypt and store intermediate CA certificate
        let encrypted_intermediate_cert = EncryptedData::encrypt_data(
            intermediate_cert.to_der()?,
            self.state.app_public_key.clone(),
        )?;
        let intermediate_height = self
            .state
            .certificate_chain
            .put_block(encrypted_intermediate_cert.serialize_encrypted_data())?;
        println!(
            "✓ Intermediate CA certificate stored at height {}",
            intermediate_height
        );
        // Private key chain and certificate chain store the same signature to verify
        // height integrity between them
        self.state
            .certificate_chain
            .put_signature(intermediate_height, self_signature.clone())?;

        // Encrypt and store intermediate CA private key (with App public key)
        let encrypted_intermediate_key = EncryptedData::encrypt_data(
            intermediate_key.private_key_to_der()?,
            self.state.app_public_key.clone(),
        )?;
        self.state
            .private_key_chain
            .put_block(encrypted_intermediate_key.serialize_encrypted_data())?;
        println!("✓ Intermediate CA private key stored");

        self.state
            .private_key_chain
            .put_signature(intermediate_height, self_signature)?;

        // Export as PEM for download
        let cert_pem = intermediate_cert.to_pem()?;
        let key_pem = intermediate_key.private_key_to_pem_pkcs8()?;

        println!("✅ Intermediate CA created successfully!");

        Ok((cert_pem, key_pem))
    }

    /// Create user certificate signed by an intermediate CA
    ///
    /// # Arguments
    ///
    /// * `cert_data` - Certificate data for the user
    /// * `intermediate_ca_cn` - Common name of the intermediate CA to use as issuer
    ///
    /// # Returns
    ///
    /// Tuple of (certificate_pem, private_key_pem) for download
    pub fn create_user_certificate(
        &self,
        cert_data: CertificateData,
        intermediate_ca_cn: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        println!("👤 Creating user certificate...");

        // Load app private key for decryption
        let config = AppConfig::load().context("Failed to load config")?;
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        // Get intermediate CA certificate
        let intermediate_height = self
            .state
            .subject_name_to_height
            .get(intermediate_ca_cn)
            .context("Intermediate CA not found")?;

        let intermediate_cert_block = self
            .state
            .certificate_chain
            .get_block_by_height(*intermediate_height)?;
        let encrypted_intermediate_cert_data =
            deserialize_encrypted_data(&intermediate_cert_block.block_data())?;
        let intermediate_cert_der =
            encrypted_intermediate_cert_data.decrypt_data(app_private_key.clone())?;
        let _intermediate_cert = X509::from_der(&intermediate_cert_der)
            .context("Failed to parse intermediate CA certificate")?;
        println!("✓ Intermediate CA certificate loaded");

        // Get intermediate CA private key
        let intermediate_key_block = self
            .state
            .private_key_chain
            .get_block_by_height(*intermediate_height)?;
        let encrypted_intermediate_key_data =
            deserialize_encrypted_data(&intermediate_key_block.block_data())?;

        // Decrypt intermediate private key with app private key
        // (intermediate keys are encrypted with app key, not root key)
        let intermediate_key_der =
            encrypted_intermediate_key_data.decrypt_data(app_private_key.clone())?;
        let intermediate_private_key = PKey::private_key_from_der(&intermediate_key_der)
            .context("Failed to parse intermediate CA private key")?;
        println!("✓ Intermediate CA private key loaded");

        // Set issuer to intermediate CA common name
        let cert_data_with_issuer = CertificateData {
            issuer_common_name: intermediate_ca_cn.to_string(),
            is_admin: false,
            ..cert_data
        };

        // Generate user certificate
        let (user_key, user_cert) =
            generate_key_pair(cert_data_with_issuer, &intermediate_private_key)?;
        println!("✓ User certificate generated");

        let certificate_signature = || -> Result<Vec<u8>> {
            let mut signer =
                openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &user_key)
                    .context("Failed to create signer for certificate signature")?;
            signer
                .update(&user_cert.to_der()?)
                .context("Failed to update signer with certificate data")?;
            let signature = signer
                .sign_to_vec()
                .context("Failed to generate certificate signature")?;
            Ok(signature)
        }()?;

        // Encrypt and store user certificate
        let encrypted_user_cert =
            EncryptedData::encrypt_data(user_cert.to_der()?, self.state.app_public_key.clone())?;
        let user_height = self
            .state
            .certificate_chain
            .put_block(encrypted_user_cert.serialize_encrypted_data())?;
        println!("✓ User certificate stored at height {}", user_height);

        self.state
            .certificate_chain
            .put_signature(user_height, certificate_signature.clone())?;

        // Encrypt and store user private key (with app public key)
        let encrypted_user_key = EncryptedData::encrypt_data(
            user_key.private_key_to_der()?,
            self.state.app_public_key.clone(),
        )?;
        self.state
            .private_key_chain
            .put_block(encrypted_user_key.serialize_encrypted_data())?;
        println!("✓ User private key stored");

        self.state
            .private_key_chain
            .put_signature(user_height, certificate_signature)?;

        // Export as PEM for download
        let cert_pem = user_cert.to_pem()?;
        let key_pem = user_key.private_key_to_pem_pkcs8()?;

        println!("✅ User certificate created successfully!");

        Ok((cert_pem, key_pem))
    }

    /// List all certificates available for revocation (excluding Root CA)
    ///
    /// Returns Vec of (common_name, serial_number) tuples
    pub fn list_certificates_for_revocation(&self) -> Result<Vec<(String, String)>> {
        let config = AppConfig::load().context("Failed to load config")?;
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        let mut certificates = Vec::new();
        let cert_count = self.state.certificate_chain.block_count()?;

        // Skip height 0 (Root CA cannot be revoked)
        for height in 1..cert_count {
            let block = self.state.certificate_chain.get_block_by_height(height)?;
            let encrypted_cert_data = deserialize_encrypted_data(&block.block_data())?;
            let cert_der = encrypted_cert_data.decrypt_data(app_private_key.clone())?;
            let cert = X509::from_der(&cert_der).context("Failed to parse certificate")?;

            let subject_cn = cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok())
                .map(|d| d.to_string())
                .context("Certificate missing CN")?;

            // Get serial number as hex string
            let serial = cert.serial_number();
            let serial_hex = serial
                .to_bn()
                .context("Failed to convert serial to BigNum")?
                .to_hex_str()
                .context("Failed to convert serial to hex")?
                .to_string();

            certificates.push((subject_cn, serial_hex));
        }

        Ok(certificates)
    }

    /// Revoke a certificate by serial number
    ///
    /// Adds certificate to CRL blockchain. This operation is immutable.
    ///
    /// # Arguments
    ///
    /// * `serial_number` - Hex string of certificate serial number
    /// * `reason` - Optional revocation reason
    ///
    /// # Returns
    ///
    /// Common name of the revoked certificate
    pub fn revoke_certificate(&self, serial_number: &str, reason: Option<&str>) -> Result<String> {
        println!("🚫 Revoking certificate with serial: {}", serial_number);

        let config = AppConfig::load().context("Failed to load config")?;
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        // Find the certificate with this serial number
        let cert_count = self.state.certificate_chain.block_count()?;
        let mut target_cert: Option<X509> = None;
        let mut target_height: Option<u64> = None;

        for height in 1..cert_count {
            let block = self.state.certificate_chain.get_block_by_height(height)?;
            let encrypted_cert_data = deserialize_encrypted_data(&block.block_data())?;
            let cert_der = encrypted_cert_data.decrypt_data(app_private_key.clone())?;
            let cert = X509::from_der(&cert_der).context("Failed to parse certificate")?;

            let serial = cert.serial_number();
            let serial_hex = serial
                .to_bn()
                .context("Failed to convert serial to BigNum")?
                .to_hex_str()
                .context("Failed to convert serial to hex")?
                .to_string();

            if serial_hex == serial_number {
                target_cert = Some(cert);
                target_height = Some(height);
                break;
            }
        }

        let cert = target_cert.context("Certificate with serial number not found")?;
        let height = target_height.context("Certificate height not found")?;

        let subject_cn = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|d| d.to_string())
            .context("Certificate missing CN")?;

        println!("✓ Found certificate: {} at height {}", subject_cn, height);

        // Create revocation entry with timestamp, serial, CN, and reason
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get timestamp")?
            .as_secs();

        let revocation_data = serde_json::json!({
            "serial_number": serial_number,
            "common_name": subject_cn,
            "revocation_timestamp": timestamp,
            "reason": reason.unwrap_or("Not specified"),
            "blockchain_height": height,
        });

        let revocation_json =
            serde_json::to_vec(&revocation_data).context("Failed to serialize revocation data")?;

        // Encrypt and store in CRL blockchain
        let encrypted_revocation =
            EncryptedData::encrypt_data(revocation_json, self.state.app_public_key.clone())?;
        let crl_height = self
            .state
            .crl_chain
            .put_block(encrypted_revocation.serialize_encrypted_data())?;

        println!(
            "✓ Revocation record stored in CRL blockchain at height {}",
            crl_height
        );
        println!("✅ Certificate revoked successfully!");

        Ok(subject_cn)
    }

    /// Check if a certificate is revoked by serial number
    ///
    /// Scans CRL blockchain for matching serial number
    pub fn is_certificate_revoked(&self, serial_number: &str) -> Result<bool> {
        let config = AppConfig::load().context("Failed to load config")?;
        let app_private_key_pem = fs::read(&config.key_exports.app_key_path)
            .context("Failed to read application private key")?;
        let app_private_key = PKey::private_key_from_pem(&app_private_key_pem)
            .context("Failed to parse application private key")?;

        let crl_count = self.state.crl_chain.block_count()?;

        for height in 0..crl_count {
            let block = self.state.crl_chain.get_block_by_height(height)?;
            let encrypted_data = deserialize_encrypted_data(&block.block_data())?;
            let revocation_json = encrypted_data.decrypt_data(app_private_key.clone())?;

            let revocation: serde_json::Value = serde_json::from_slice(&revocation_json)
                .context("Failed to parse revocation data")?;

            if let Some(revoked_serial) = revocation["serial_number"].as_str() {
                if revoked_serial == serial_number {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

// ============================================================================
// API Mode - Read-only access to certificates and CRL
// ============================================================================

/// API Mode: Read-only access to certificates and CRL (no private keys)
pub struct APIStorage {
    certificate_chain: BlockChain<ReadOnly>,
    crl_chain: BlockChain<ReadOnly>,
    subject_name_to_height: HashMap<String, u64>,
}

impl APIStorage {
    /// Open blockchains in read-only API mode
    pub fn open() -> Result<Self> {
        let config = AppConfig::load().context("Failed to load configuration")?;

        // Open blockchains in read-only mode
        let certificate_chain = open_read_only_chain(config.blockchains.certificate_path.clone())
            .context("Failed to open certificate blockchain")?;

        let crl_chain = open_read_only_chain(config.blockchains.crl_path.clone())
            .context("Failed to open CRL blockchain")?;

        // Build subject name index (requires decryption - TODO)
        let subject_name_to_height = HashMap::new();

        Ok(APIStorage {
            certificate_chain,
            crl_chain,
            subject_name_to_height,
        })
    }

    /// Get certificate count
    pub fn certificate_count(&self) -> Result<u64> {
        self.certificate_chain.block_count()
    }

    /// Get CRL count
    pub fn crl_count(&self) -> Result<u64> {
        self.crl_chain.block_count()
    }
}

// ============================================================================
// Admin Mode - Full access including private keys
// ============================================================================

/// Admin Mode: Full access to all blockchains including private keys
pub struct AdminStorage {
    certificate_chain: BlockChain<ReadWrite>,
    private_key_chain: BlockChain<ReadWrite>,
    crl_chain: BlockChain<ReadWrite>,
    app_public_key: PKey<Public>,
    root_ca_cert: X509,
    subject_name_to_height: HashMap<String, u64>,
}

impl AdminStorage {
    /// Open blockchains in admin mode
    pub fn open() -> Result<Self> {
        // For now, delegate to Storage<Ready>::open() and convert
        let ready = Storage::<Ready>::open()?;

        Ok(AdminStorage {
            certificate_chain: ready.state.certificate_chain,
            private_key_chain: ready.state.private_key_chain,
            crl_chain: ready.state.crl_chain,
            app_public_key: ready.state.app_public_key,
            root_ca_cert: ready.state.root_ca_cert,
            subject_name_to_height: ready.state.subject_name_to_height,
        })
    }

    /// Get certificate count
    pub fn certificate_count(&self) -> Result<u64> {
        self.certificate_chain.block_count()
    }

    /// Get private key count
    pub fn private_key_count(&self) -> Result<u64> {
        self.private_key_chain.block_count()
    }

    /// Get CRL count
    pub fn crl_count(&self) -> Result<u64> {
        self.crl_chain.block_count()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Determine the current state of storage without fully opening it
///
/// This function checks if blockchains exist and inspects their contents
/// to determine whether the system is uninitialized, initialized with Root CA,
/// or ready with admin user.
///
/// # Returns
///
/// * `StorageState::NoExist` - Blockchains don't exist or are empty
/// * `StorageState::Initialized` - Root CA exists at height 0
/// * `StorageState::Ready` - Admin intermediate CA and user cert exist (heights 1, 2)
///
/// # Errors
///
/// Returns an error if:
/// - Configuration cannot be loaded
/// - Blockchains exist but cannot be opened
/// - Storage is in an inconsistent state (mismatched block counts)
///
/// # Example
///
/// ```no_run
/// # use pki_chain::storage::{check_storage_state, StorageState};
/// match check_storage_state()? {
///     StorageState::NoExist => println!("Need to initialize"),
///     StorageState::Initialized => println!("Need to create admin"),
///     StorageState::Ready => println!("System ready"),
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn check_storage_state() -> Result<StorageState> {
    let config = AppConfig::load().context("Failed to load configuration")?;

    // Check if blockchains exist on disk
    let cert_exists = config.blockchains.certificate_path.exists();
    let key_exists = config.blockchains.private_key_path.exists();
    let crl_exists = config.blockchains.crl_path.exists();

    if !cert_exists || !key_exists || !crl_exists {
        return Ok(StorageState::NoExist);
    }

    // Open blockchains in read-only mode to check contents
    let cert_chain = open_read_only_chain(config.blockchains.certificate_path.clone())
        .context("Failed to open certificate blockchain for state check")?;
    let key_chain = open_read_only_chain(config.blockchains.private_key_path.clone())
        .context("Failed to open private key blockchain for state check")?;

    let cert_count = cert_chain.block_count()?;
    let key_count = key_chain.block_count()?;

    // Verify blockchains are in sync
    if cert_count != key_count {
        return Err(anyhow!(
            "Storage in inconsistent state: {} certificates, {} keys",
            cert_count,
            key_count
        ));
    }

    // Determine state based on block count
    match cert_count {
        0 => Ok(StorageState::NoExist),
        1 => Ok(StorageState::Initialized),
        n if n >= 3 => Ok(StorageState::Ready),
        _ => Err(anyhow!(
            "Storage in inconsistent state: expected 0, 1, or 3+ blocks, found {}",
            cert_count
        )),
    }
}

/// Clear all storage (destructive operation)
pub fn clear_storage() -> Result<()> {
    let config = AppConfig::load().context("Failed to load configuration")?;

    println!("⚠️  Clearing all storage...");

    // Remove certificate blockchain
    if config.blockchains.certificate_path.exists() {
        fs::remove_dir_all(&config.blockchains.certificate_path)
            .context("Failed to remove certificate blockchain")?;
        println!("✓ Certificate blockchain removed");
    }

    // Remove private key blockchain
    if config.blockchains.private_key_path.exists() {
        fs::remove_dir_all(&config.blockchains.private_key_path)
            .context("Failed to remove private key blockchain")?;
        println!("✓ Private key blockchain removed");
    }

    // Remove CRL blockchain
    if config.blockchains.crl_path.exists() {
        fs::remove_dir_all(&config.blockchains.crl_path)
            .context("Failed to remove CRL blockchain")?;
        println!("✓ CRL blockchain removed");
    }

    println!("✅ Storage cleared successfully");
    Ok(())
}

pub fn complete_pki_storage_validation(
    certificate_chain: &BlockChain<ReadWrite>,
    private_key_chain: &BlockChain<ReadWrite>,
) -> Result<()> {
    let signatures_synced = || -> Result<bool> {
        let cert_count = certificate_chain.block_count()?;
        let key_count = private_key_chain.block_count()?;

        if cert_count != key_count {
            return Ok(false);
        }

        for height in 0..cert_count {
            let cert_signature = certificate_chain.get_signature_by_height(height)?;
            let key_signature = private_key_chain.get_signature_by_height(height)?;

            if cert_signature != key_signature {
                return Ok(false);
            }
        }

        Ok(true)
    }()?;
    if !signatures_synced {
        return Err(anyhow!(
            "Certificate and private key blockchains are out of sync"
        ));
    }

    Ok(())
}
