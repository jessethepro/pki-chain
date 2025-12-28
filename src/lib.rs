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
//! Add to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! pki-chain = { git = "https://github.com/jessethepro/pki-chain.git" }
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
pub mod configs;
pub mod pki_generator;
pub mod private_key_storage;
pub mod protocol;
pub mod storage;
// Public API - only expose Request/Response enums, socket path, and protocol functions
pub use pki_generator::{CertificateData, CertificateDataType};
pub use protocol::{Request, Response};
