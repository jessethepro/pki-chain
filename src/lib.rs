//! PKI Chain - Blockchain-backed Certificate Authority Library
//!
//! A production-ready Public Key Infrastructure system that stores certificates and private keys
//! in tamper-proof blockchain storage. This library provides the core functionality for building
//! and managing a complete three-tier CA hierarchy.
//!
//! # Overview
//!
//! PKI Chain implements a traditional PKI hierarchy with blockchain-enhanced storage:
//!
//! ```text
//! Root CA (self-signed, pathlen=1)
//!   └── Intermediate CA (signed by Root, pathlen=0)
//!       └── User Certificate (signed by Intermediate, CA=false)
//! ```
//!
//! All certificates and private keys are stored in dual blockchain instances, providing:
//! - **Tamper Detection**: Any modification to stored certificates is immediately detectable
//! - **Transactional Safety**: Failed operations automatically roll back
//! - **Signature Verification**: Cross-validation between certificate and key storage
//! - **Height-Based Indexing**: O(1) lookups for certificates by blockchain height
//!
//! # Features
//!
//! - 🔐 **Blockchain Storage**: Dual blockchain instances for certificates and keys
//! - 🔗 **Three-Tier PKI**: Complete CA hierarchy implementation
//! - 🔒 **Strong Cryptography**: 4096-bit RSA with SHA-256 signatures
//! - 🔄 **Transactional Operations**: Automatic rollback on failures
//! - ✅ **Integrity Validation**: Cross-chain signature verification
//!
//! # Quick Start
//!
//! ## As an Application
//!
//! ```bash
//! # Generate application key (first run)
//! ./generate_app_keypair.sh
//!
//! # Build and run
//! cargo build --release
//! ./target/release/pki-chain
//! ```
//!
//! ## As a Library
//!
//! Add to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! pki-chain = { git = "https://github.com/jessethepro/pki-chain.git" }
//! ```
//!
//! Use in your code:
//!
//! ```no_run
//! use pki_chain::storage::Storage;
//! use pki_chain::generate_root_ca::RsaRootCABuilder;
//! use anyhow::Result;
//!
//! fn main() -> Result<()> {
//!     // Initialize storage
//!     let storage = Storage::new("key/app.key")?;
//!     
//!     // Generate Root CA
//!     let (private_key, certificate) = RsaRootCABuilder::new()
//!         .subject_common_name("My Root CA".to_string())
//!         .organization("My Organization".to_string())
//!         .organizational_unit("IT".to_string())
//!         .country("US".to_string())
//!         .state("CA".to_string())
//!         .locality("San Francisco".to_string())
//!         .validity_days(365 * 10)
//!         .build()?;
//!     
//!     // Store in blockchain
//!     let height = storage.store_key_certificate(&private_key, &certificate)?;
//!     println!("Root CA stored at height: {}", height);
//!     
//!     // Validate blockchain
//!     if storage.validate()? {
//!         println!("Blockchain integrity verified");
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Module Overview
//!
//! ## [`storage`]
//!
//! Core blockchain storage abstraction that manages dual blockchain instances for certificates
//! and private keys. Provides transactional operations with automatic rollback.
//!
//! ```no_run
//! use pki_chain::storage::Storage;
//!
//! let storage = Storage::new("key/app.key")?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! ## [`generate_root_ca`]
//!
//! Builder for creating self-signed Root CA certificates. Root CAs are the trust anchor
//! of the PKI hierarchy.
//!
//! ```no_run
//! use pki_chain::generate_root_ca::RsaRootCABuilder;
//!
//! let (key, cert) = RsaRootCABuilder::new()
//!     .subject_common_name("Root CA".to_string())
//!     .organization("ACME Corp".to_string())
//!     .organizational_unit("Security".to_string())
//!     .country("US".to_string())
//!     .state("CA".to_string())
//!     .locality("San Francisco".to_string())
//!     .validity_days(3650)
//!     .build()?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! ## [`generate_intermediate_ca`]
//!
//! Builder for creating Intermediate CA certificates signed by the Root CA.
//!
//! ```no_run
//! use pki_chain::generate_intermediate_ca::RsaIntermediateCABuilder;
//! # use openssl::pkey::PKey;
//! # use openssl::x509::X509;
//! # fn example(root_key: PKey<openssl::pkey::Private>, root_cert: X509) -> anyhow::Result<()> {
//!
//! let (key, cert) = RsaIntermediateCABuilder::new(root_key, root_cert)
//!     .subject_common_name("Intermediate CA".to_string())
//!     .organization("ACME Corp".to_string())
//!     .organizational_unit("Operations".to_string())
//!     .country("US".to_string())
//!     .state("CA".to_string())
//!     .locality("San Francisco".to_string())
//!     .validity_days(1825)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## [`generate_user_keypair`]
//!
//! Builder for creating end-user certificates signed by an Intermediate CA.
//!
//! ```no_run
//! use pki_chain::generate_user_keypair::RsaUserKeyPairBuilder;
//! # use openssl::pkey::PKey;
//! # use openssl::x509::X509;
//! # fn example(int_key: PKey<openssl::pkey::Private>, int_cert: X509) -> anyhow::Result<()> {
//!
//! let (key, cert) = RsaUserKeyPairBuilder::new(int_key, int_cert)
//!     .subject_common_name("user@example.com".to_string())
//!     .organization("ACME Corp".to_string())
//!     .organizational_unit("Engineering".to_string())
//!     .country("US".to_string())
//!     .state("CA".to_string())
//!     .locality("San Francisco".to_string())
//!     .validity_days(365)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## [`external_interface`]
//!
//! Unix socket server for external IPC. Provides a JSON-based API for certificate operations.
//!
//! # Architecture Details
//!
//! ## Blockchain Storage
//!
//! The system uses two parallel blockchain instances:
//!
//! - **Certificate Chain**: Stores X.509 certificates in PEM format
//! - **Private Key Chain**: Stores RSA private keys in DER format
//!
//! Both chains maintain consistency through:
//! 1. Height-based indexing (cert at height N ↔ key at height N)
//! 2. Signature verification (matching signatures prove pairing)
//! 3. Transactional rollback (failed key storage rolls back cert storage)
//!
//! ## Certificate Hierarchy
//!
//! The PKI implements a three-tier hierarchy:
//!
//! 1. **Root CA**: Self-signed, `pathlen=1`, long validity (5-20 years)
//! 2. **Intermediate CA**: Signed by Root, `pathlen=0`, medium validity (3-5 years)
//! 3. **User Certificate**: Signed by Intermediate, `CA=false`, short validity (1-2 years)
//!
//! This structure follows industry best practices where the Root CA private key
//! can be kept offline after initial setup.
//!
//! # Security Considerations
//!
//! ## Key Management
//!
//! - **Application Key**: Master encryption key for blockchain databases. Must be kept secure.
//! - **Root CA Key**: Should be moved to offline/air-gapped storage after generation.
//! - **Intermediate CA Keys**: Can remain online for certificate issuance.
//!
//! ## Threat Model
//!
//! - ✅ Tamper detection through blockchain validation
//! - ✅ Rollback protection via transactional operations
//! - ✅ Signature verification between certificate and key pairs
//! - ⚠️ No network-based access control (Unix socket is local-only)
//! - ⚠️ Application key compromise grants full database access
//!
//! # Examples
//!
//! ## Complete PKI Setup
//!
//! ```no_run
//! use pki_chain::storage::Storage;
//! use pki_chain::generate_root_ca::RsaRootCABuilder;
//! use pki_chain::generate_intermediate_ca::RsaIntermediateCABuilder;
//! use pki_chain::generate_user_keypair::RsaUserKeyPairBuilder;
//! use anyhow::Result;
//!
//! fn setup_pki() -> Result<()> {
//!     // Initialize storage
//!     let storage = Storage::new("key/app.key")?;
//!     
//!     // Generate Root CA
//!     let (root_key, root_cert) = RsaRootCABuilder::new()
//!         .subject_common_name("Root CA".to_string())
//!         .organization("ACME Corp".to_string())
//!         .organizational_unit("Security".to_string())
//!         .country("US".to_string())
//!         .state("CA".to_string())
//!         .locality("San Francisco".to_string())
//!         .validity_days(3650)
//!         .build()?;
//!     storage.store_key_certificate(&root_key, &root_cert)?;
//!     
//!     // Generate Intermediate CA
//!     let (int_key, int_cert) = RsaIntermediateCABuilder::new(root_key, root_cert)
//!         .subject_common_name("Operations CA".to_string())
//!         .organization("ACME Corp".to_string())
//!         .organizational_unit("Operations".to_string())
//!         .country("US".to_string())
//!         .state("CA".to_string())
//!         .locality("San Francisco".to_string())
//!         .validity_days(1825)
//!         .build()?;
//!     storage.store_key_certificate(&int_key, &int_cert)?;
//!     
//!     // Generate User Certificate
//!     let (user_key, user_cert) = RsaUserKeyPairBuilder::new(int_key, int_cert)
//!         .subject_common_name("john.doe@acme.com".to_string())
//!         .organization("ACME Corp".to_string())
//!         .organizational_unit("Engineering".to_string())
//!         .country("US".to_string())
//!         .state("CA".to_string())
//!         .locality("San Francisco".to_string())
//!         .validity_days(365)
//!         .build()?;
//!     storage.store_key_certificate(&user_key, &user_cert)?;
//!     
//!     // Validate entire chain
//!     assert!(storage.validate()?);
//!     println!("PKI setup complete and validated");
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Error Handling
//!
//! All public APIs return `anyhow::Result<T>` for flexible error handling:
//!
//! ```no_run
//! use pki_chain::storage::Storage;
//! use anyhow::{Context, Result};
//!
//! fn example() -> Result<()> {
//!     let storage = Storage::new("key/app.key")
//!         .context("Failed to initialize storage - check app key exists")?;
//!     
//!     if !storage.is_empty()? {
//!         println!("Blockchain already initialized");
//!     }
//!     
//!     Ok(())
//! }
//! ```

pub mod external_interface;
pub mod generate_intermediate_ca;
pub mod generate_root_ca;
pub mod generate_user_keypair;
pub mod storage;
