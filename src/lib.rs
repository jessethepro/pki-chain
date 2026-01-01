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
//! - 🌐 **HTTPS Web Server**: Secure web interface with REST API (Axum + Tokio)
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
//! # Generate TLS certificates for web server (first run)
//! ./generate-certs.sh
//!
//! # Build and run
//! cargo build --release
//! ./target/release/pki-chain
//!
//! # Access web interface at https://localhost:3000
//! # REST API endpoint: GET /api/status
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
//! - **Application Key**: Password-protected PKCS#8 file for blockchain database encryption. Stored at `key/pki-chain-app.key`.
//! - **Root CA Key**: Password-protected PKCS#8 file for encrypting other private keys. Stored at `exports/keystore/root_private_key.pkcs8`.
//! - **Other Private Keys**: Encrypted with RSA+AES-GCM-256 hybrid encryption using Root CA public key. Stored in `exports/keystore/{height}.key.enc`.
//!
//! ## Threat Model
//!
//! ### Application Key Compromise
//!
//! **Exposure**: Application key compromise grants access to:
//! - ✅ **Public certificates** (X.509 certificates in DER format)
//! - ✅ **Certificate chain structure** (blockchain heights and relationships)
//! - ✅ **Private key hashes** (SHA-512 hashes for integrity verification)
//! - ✅ **Certificate signatures** (used for pairing verification)
//!
//! **Protection**: Private keys remain encrypted by Root CA private key:
//! - ❌ **Private keys are NOT exposed** - encrypted with Root CA public key (RSA-OAEP + AES-GCM-256)
//! - 🔒 Private keys stored in `exports/keystore/` are double-encrypted
//! - 🔐 Root CA key compromise is required to decrypt private keys
//!
//! ### Read-Only Mode
//!
//! When private key generation is not required, the encrypted keystore can be unloaded from the system:
//! - **Available**: Certificate verification, chain validation, blockchain queries
//! - **Unavailable**: Certificate generation, key pair creation
//! - **Use Case**: Auditing, verification-only deployments, cold storage scenarios
//!
//! ### Key Protection Strategy
//!
//! Both App Key and Root Key are password-protected PKCS#8 files:
//! - 🔑 **App Key**: Protects blockchain data (certificates, hashes, signatures)
//! - 🔑 **Root Key**: Protects private key material (actual cryptographic keys)
//! - 🔐 **Defense in Depth**: Compromise of one key does not expose private keys
//! - 💾 **Offline Storage**: Root CA key can be kept on air-gapped media after initial setup
//! - 🔄 **Key Rotation**: Blockchain immutability means app key cannot be rotated without migration
//!
//! ### Additional Protections
//!
//! - ✅ Tamper detection through blockchain validation
//! - ✅ Rollback protection via transactional operations
//! - ✅ Signature verification between certificate and key pairs
//! - ✅ In-memory keys zeroized on drop (secrecy + zeroize crates)
//! - ⚠️ No network-based access control (local filesystem access only)
//!
pub mod configs;
pub mod key_archive;
pub mod pki_generator;
pub mod private_key_storage;
pub mod protocol;
pub mod storage;
pub mod webserver;
// Public API - only expose Request/Response enums, socket path, and protocol functions
pub use pki_generator::{CertificateData, CertificateDataType};
pub use protocol::{Request, Response};
