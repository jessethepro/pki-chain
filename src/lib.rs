//! PKI Chain - Blockchain-backed Certificate Authority Library
//!
//! A production-ready Public Key Infrastructure system with hybrid storage: certificates in
//! blockchain (DER format) and private keys in AES-256-GCM encrypted files. This library provides
//! the core functionality for building and managing a complete three-tier CA hierarchy.
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
//! The hybrid storage architecture provides:
//! - **Tamper Detection**: Certificates stored in blockchain, hashes validate key integrity
//! - **Transactional Safety**: Failed operations automatically roll back
//! - **Encrypted Private Keys**: AES-256-GCM encryption with random nonces
//! - **Hash-Based Verification**: SHA-256 hashes stored in blockchain validate key files
//! - **Height-Based Indexing**: O(1) lookups for certificates by blockchain height
//!
//! # Features
//!
//! - � **Terminal User Interface**: Cursive-based TUI for interactive certificate management
//! - 🔐 **Hybrid Storage**:
//!   - Certificates in blockchain (DER format)
//!   - Private keys in AES-256-GCM encrypted files (enables offline/cold storage)
//!   - SHA-256 hashes and signatures in key blockchain
//! - 🔗 **Three-Tier PKI**: Complete CA hierarchy implementation
//! - 🔒 **Strong Cryptography**: 4096-bit RSA with SHA-256 signatures
//! - 🔄 **Transactional Operations**: Automatic rollback on failures
//! - ✅ **Integrity Validation**: Hash-based verification of private keys
//! - 🧵 **Thread Safety**: Arc-wrapped Protocol with concurrent access support
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
//! **Note**: The Unix socket API is currently disabled in favor of the TUI interface.
//! To re-enable socket communication, uncomment the socket server code in `src/main.rs`.
//!
//! Add to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! pki-chain = { git = "https://github.com/jessethepro/pki-chain.git" }
//! ```
//!
//! Use in your code (when socket server is enabled):
//!
//! ```no_run
//! use pki_chain::{Request, Response, SOCKET_PATH};
//! use std::os::unix::net::UnixStream;
//! use std::io::{Read, Write};
//!
//! fn request_certificate() -> anyhow::Result<()> {
//!     // Connect to PKI Chain socket
//!     let mut stream = UnixStream::connect(SOCKET_PATH)?;
//!     
//!     // Create certificate request
//!     let request = Request::CreateUser {
//!         subject_common_name: "user@example.com".to_string(),
//!         organization: "ACME Corp".to_string(),
//!         organizational_unit: "Engineering".to_string(),
//!         locality: "San Francisco".to_string(),
//!         state: "CA".to_string(),
//!         country: "US".to_string(),
//!         validity_days: 365,
//!         issuer_common_name: "Operations CA".to_string(),
//!     };
//!     
//!     // Send request (4-byte length prefix + JSON)
//!     let json = serde_json::to_string(&request)?;
//!     stream.write_all(&(json.len() as u32).to_le_bytes())?;
//!     stream.write_all(json.as_bytes())?;
//!     
//!     // Read response
//!     let mut len_buf = [0u8; 4];
//!     stream.read_exact(&mut len_buf)?;
//!     let mut response_buf = vec![0u8; u32::from_le_bytes(len_buf) as usize];
//!     stream.read_exact(&mut response_buf)?;
//!     
//!     let response: Response = serde_json::from_slice(&response_buf)?;
//!     println!("Response: {:?}", response);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Public API
//!
//! This library exposes a protocol-based API for PKI certificate management operations:
//!
//! ## [`Request`]
//!
//! Enum defining all supported certificate operations through the Protocol layer.
//!
//! Supported operations:
//! - `CreateIntermediate` - Create a new Intermediate CA
//! - `CreateUser` - Create a user certificate
//! - `ListCertificates` - List certificates with filtering
//! - `PKIStatus` - Get system status and validation results
//! - `ValidateCertificate` - Validate certificate chain
//!
//! ## [`Response`]
//!
//! Enum containing type-safe responses for each request type:
//!
//! - `CreateIntermediate` - Returns certificate details and blockchain height
//! - `CreateUser` - Returns certificate details and blockchain height
//! - `ListCertificates` - Returns array of certificates
//! - `PKIStatus` - Returns system metrics and validation status
//! - `ValidateCertificate` - Returns validation results for certificate chain
//! - `Error` - Error message
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
//! ## Request a User Certificate
//!
//! ```no_run
//! use pki_chain::{Request, Response, SOCKET_PATH};
//! use std::os::unix::net::UnixStream;
//! use std::io::{Read, Write};
//!
//! fn create_user_cert() -> anyhow::Result<()> {
//!     let mut stream = UnixStream::connect(SOCKET_PATH)?;
//!     
//!     let request = Request::CreateUser {
//!         subject_common_name: "alice@example.com".to_string(),
//!         organization: "ACME Corp".to_string(),
//!         organizational_unit: "Engineering".to_string(),
//!         locality: "San Francisco".to_string(),
//!         state: "CA".to_string(),
//!         country: "US".to_string(),
//!         validity_days: 365,
//!         issuer_common_name: "Operations CA".to_string(),
//!     };
//!     
//!     // Send request
//!     let json = serde_json::to_string(&request)?;
//!     stream.write_all(&(json.len() as u32).to_le_bytes())?;
//!     stream.write_all(json.as_bytes())?;
//!     
//!     // Read response
//!     let mut len_buf = [0u8; 4];
//!     stream.read_exact(&mut len_buf)?;
//!     let mut buf = vec![0u8; u32::from_le_bytes(len_buf) as usize];
//!     stream.read_exact(&mut buf)?;
//!     
//!     match serde_json::from_slice::<Response>(&buf)? {
//!         Response::CreateUserResponse { message, height, .. } => {
//!             println!("{} at height {}", message, height);
//!         }
//!         Response::Error { message } => {
//!             eprintln!("Error: {}", message);
//!         }
//!         _ => {}
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Get PKI System Status
//!
//! ```no_run
//! use pki_chain::{Request, Response, SOCKET_PATH};
//! use std::os::unix::net::UnixStream;
//! use std::io::{Read, Write};
//!
//! fn check_status() -> anyhow::Result<()> {
//!     let mut stream = UnixStream::connect(SOCKET_PATH)?;
//!     
//!     let request = Request::PKIStatus;
//!     let json = serde_json::to_string(&request)?;
//!     stream.write_all(&(json.len() as u32).to_le_bytes())?;
//!     stream.write_all(json.as_bytes())?;
//!     
//!     let mut len_buf = [0u8; 4];
//!     stream.read_exact(&mut len_buf)?;
//!     let mut buf = vec![0u8; u32::from_le_bytes(len_buf) as usize];
//!     stream.read_exact(&mut buf)?;
//!     
//!     if let Response::PKIStatusResponse {
//!         total_certificates,
//!         total_keys,
//!         certificate_chain_valid,
//!         ..
//!     } = serde_json::from_slice(&buf)?
//!     {
//!         println!("Certificates: {}, Keys: {}, Valid: {}",
//!             total_certificates, total_keys, certificate_chain_valid);
//!     }
//!     
//!     Ok(())
//! }
//! ```
pub mod configs;
pub mod pki_generator;
mod private_key_storage;
pub mod protocol;
pub mod storage;
// Public API - only expose Request/Response enums, socket path, and protocol functions
pub use pki_generator::{CertificateData, CertificateDataType};
pub use protocol::{Request, Response};
