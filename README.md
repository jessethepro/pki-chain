# PKI Chain

**A production-ready blockchain-backed Public Key Infrastructure (PKI) certificate authority system with HTTPS web interface.**

Built in Rust with enterprise-grade cryptography, PKI Chain provides a complete three-tier CA hierarchy (Root CA → Intermediate CA → User Certificates) with hybrid storage: certificates in blockchain (DER format), private keys in encrypted files (PKCS#8 for Root CA, RSA+AES-GCM-256 hybrid encryption for others), and SHA-512 integrity hashes in blockchain via [libblockchain](https://github.com/jessethepro/libblockchain). Features TOML-based configuration and in-memory key management.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Highlights

✨ **HTTPS Web Interface** - Manage certificates through secure web interface  
🔐 **Hybrid Storage** - Certificates in blockchain (DER), keys encrypted with AES-256-GCM  
🏗️ **Complete PKI** - Root CA, Intermediate CAs, and User certificates  
🔒 **RSA-4096** - Industry-standard cryptography with SHA-256 signatures  
🎯 **Fast Lookups** - O(1) certificate retrieval with in-memory indexing

## Features

- 🌐 **HTTPS Web Server**: Secure web interface for certificate management with REST API
- ⚙️ **Configuration Management**: TOML-based configuration for paths and storage settings
- 🔐 **Hybrid Storage Architecture**: 
  - Certificates stored as DER in blockchain (encrypted with app key)
  - Root CA: PKCS#8 PEM with password protection
  - Other keys: RSA + AES-GCM-256 hybrid encryption (AES key encrypted with Root CA public key via RSA-OAEP)
  - SHA-512 hashes and signatures in key blockchain (encrypted with app key)
- 🔑 **In-Memory Key Management**: Secure runtime key storage with zeroize on drop
- 🔗 **Three-Tier PKI Hierarchy**: Complete CA chain (Root → Intermediate → User)
- 🔒 **Strong Cryptography**: 4096-bit RSA keys with SHA-256 signatures
- 🔄 **Transactional Safety**: Automatic rollback on storage failures
- ✅ **Certificate Validation**: OpenSSL X509Store-based chain validation with hash verification
- 🎯 **Height-Based Indexing**: O(1) certificate lookups with thread-safe Mutex-protected HashMap
- 🧵 **Clean Architecture**: Protocol layer wraps Storage with Request/Response pattern
- 📊 **Real-Time Status**: View blockchain statistics and certificate inventory


## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# 2. Generate master encryption key (REQUIRED for first run)
./generate_app_keypair.sh

# 3. Build the application
cargo build --release

# 4. Generate TLS certificates for web server
./generate-certs.sh

# 5. Run the web server
./target/release/pki-chain
```

On first run, the application automatically initializes the Root CA (height 0) in the blockchain. Access the web interface at `https://localhost:3000` to:
- View PKI system status and statistics
- Manage certificates via REST API

## Architecture

### Core Components

```
┌──────────────────────────────────────────────────────────────┐
│                   PKI Chain Application                       │
│                        main.rs                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  1. Load config.toml                                   │  │
│  │  2. Create Storage::new() - Single instance            │  │
│  │     • Loads app key into memory                        │  │
│  │     • Opens RocksDB blockchains (once)                 │  │
│  │  3. Initialize Root CA if empty                        │  │
│  │  4. Populate subject name index                        │  │
│  │  5. Start webserver::start_webserver()                │  │
│  └────────────────────┬───────────────────────────────────┘  │
│                       │                                       │
│  ┌────────────────────▼───────────────────────────────────┐  │
│  │          HTTPS Web Server (Axum + Tokio)               │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  Static Files: web_root/                        │  │  │
│  │  │  REST API: /api/status                           │  │  │
│  │  │  TLS: web_certs/server/                          │  │  │
│  │  │  Port: 3000                                      │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │                                                          │  │
│  │  Arc<Protocol> for async handler sharing                │  │
│  └─────────────────────┬────────────────────────────────────┘  │
│                        │                                       │
│       ┌────────────────▼────────────────┐                      │
│       │     Protocol (Request/Response) │                      │
│       │  - Wraps Storage instance       │                      │
│       │  - Certificate validation logic │                      │
│       │  - Thread-safe via &self        │                      │
│       └────────────┬────────────────────┘                      │
│                    │                                           │
│       ┌────────────▼────────────────┐                          │
│       │   Storage (Created Once)    │                          │
│       │  - Transactional Operations │                          │
│       │  - Signature Verification   │                          │
│       │  - Mutex<subject→height map>│                          │
│       └────────────┬─────────────────┘                         │
│                    │                                           │
│       ┌────────────┴─────────────────────────────┐            │
│       │                                          │            │
│  ┌────▼────────┐          ┌──────────▼─────────┐            │
│  │ Certificate │          │  Private Key       │            │
│  │ Blockchain  │          │  Blockchain        │            │
│  │ (DER)       │          │  (SHA-512 Hashes)  │            │
│  │ RocksDB     │          │  + Signatures CF   │            │
│  │ Encrypted   │          │  RocksDB           │            │
│  │ w/ App Key  │          │  Encrypted w/ App  │            │
│  └─────────────┘          └────────────────────┘            │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │     Encrypted Key Store (Filesystem)          │          │
│  │  exports/keystore/ (configurable)             │          │
│  │  - Root (h=0): PKCS#8 PEM + password          │          │
│  │  - Others: RSA + AES-GCM-256 hybrid           │          │
│  │    Format: [AES Len(u32)][Enc AES Key]       │          │
│  │            [Nonce(12)][Tag(16)][Data Len]    │          │
│  │            [Encrypted Data]                   │          │
│  │    AES key encrypted with Root CA pub key    │          │
│  └──────────────────────────────────────────────┘          │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │  In-Memory Key Storage (Runtime)              │          │
│  │  - App key: Encrypts blockchain databases     │          │
│  │  - Root key: Encrypts other private keys      │          │
│  │  - Loaded once at startup                     │          │
│  │  - Zeroized on drop for security              │          │
│  └──────────────────────────────────────────────┘          │
│                                                              │
│  Configuration: config.toml (paths, storage settings)       │
└──────────────────────────────────────────────────────────────┘
```

### PKI Hierarchy

```
Root CA (self-signed, pathlen=1)
  └── Intermediate CA (signed by Root, pathlen=0)
      └── User Certificate (signed by Intermediate, CA=false)
```

## Installation

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries
- Linux/Unix system (for Unix socket support)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# Generate application encryption key (FIRST RUN ONLY)
./generate_app_keypair.sh

# Generate TLS certificates for web server (FIRST RUN ONLY)
./generate-certs.sh

# Build the project
cargo build --release

# Run the web server
./target/release/pki-chain
```

**Important**: The `key/pki-chain-app.key` file is the master key loaded into memory for encrypting blockchain databases. The Root CA private key (stored in memory after first decryption) is used to encrypt/decrypt other private keys. Both keys are zeroized on drop for security. **Keep the app key file secure and backed up**. Loss of the app key means permanent loss of access to blockchain data; loss of the Root CA key file means permanent loss of access to encrypted private keys.

## Usage

### Web Interface

Run the application to launch the HTTPS web server:

```bash
./target/release/pki-chain
```

Access the web interface at `https://localhost:3000`

**Web Interface Features:**

- **PKI Status Dashboard**: View blockchain statistics and certificate inventory
- **REST API**: JSON endpoints for programmatic access
  - `GET /api/status` - System status and statistics
- **Static Web Interface**: HTML/CSS/JS interface in `web_root/` directory

**Note**: Browser will show security warning due to self-signed TLS certificate (expected for local development).

### Typical Workflow

```
1. First Run:
   $ ./generate_app_keypair.sh        # Create master encryption key
   $ ./generate-certs.sh              # Generate TLS certificates
   $ ./target/release/pki-chain       # Start HTTPS server (initializes Root CA)

2. Access Web Interface:
   Navigate to https://localhost:3000
   - View PKI status dashboard
   - Access REST API at /api/status

3. Verify Storage:
   Check GET /api/status response for:
   - Certificate count
   - Blockchain validation status
   - Tracked subject names

4. Integration via API:
   Use REST endpoints for programmatic certificate management
```

## Testing

### End-to-End Testing

Use the provided test script to validate the complete PKI hierarchy:

```bash
./test_keypair_generation.sh
```

This script:
- Generates Root CA → Intermediate CA → 5 User certificates
- Validates the complete certificate chain
- Tests certificate exports and integrity

## Initial Certificate Structure

On first run, the application automatically initializes the Root CA in the blockchain:

### Height 0: Root CA
- **Subject CN**: `MenaceLabs Root CA`
- **Type**: Self-signed Root Certificate Authority
- **Constraints**: CA=true, pathlen=1 (can sign one level of CAs)
- **Validity**: 10 years (3650 days)
- **Usage**: Signs Intermediate CAs
- **Storage**: Private key stored as password-protected PKCS#8 PEM in `exports/keystore/root_private_key.pkcs8`

### User-Created Certificates
All certificates created via the TUI are stored at **heights 1 and above**:
- **Intermediate CAs**: Height 1+ (pathlen=0, configurable validity)
- **User Certificates**: Height 1+ (CA=false, configurable validity)
- **Private Keys**: Encrypted with hybrid RSA + AES-GCM-256 scheme
  - AES-256 session key encrypts the private key
  - Root CA public key encrypts the AES session key
  - Stored as `{height}.key.enc` files

## Configuration

### Configuration File

Edit `config.toml` to customize paths and settings:

```toml
[blockchains]
certificate_path = "data/certificates"
private_key_path = "data/private_keys"

[app_keyring]
app_key_path = "key"
app_key_name = "app-key"
root_key_name = "root-key"

[key_exports]
directory = "exports/keystore"
```

### Key Paths

- **Application Key**: `key/pki-chain-app.key` (loaded into kernel keyring)
- **Certificate Storage**: `data/certificates/` (configurable, RocksDB database)
- **Private Key Storage**: `data/private_keys/` (configurable, RocksDB database with SHA-512 hashes)
- **Encrypted Key Store**: `exports/keystore/` (configurable, encrypted private keys)
  - Root CA: `root_private_key.pkcs8` (PKCS#8 PEM format)
  - Others: `{height}.key.enc` (hybrid RSA + AES-GCM-256)

### Certificate Parameters

- **RSA Key Size**: 4096 bits
- **Signature Algorithm**: SHA-256 with RSA
- **Private Key Hashing**: SHA-512 (stored in private key blockchain)
- **Root CA**: pathlen=1, validity 10 years (default)
- **Intermediate CA**: pathlen=0, validity configurable (default: 5 years)
- **User Certificates**: CA=false, validity configurable (default: 1 year)
- **Encryption**:
  - Root CA: PKCS#8 PEM with AES-256-CBC (password-protected)
  - Others: Hybrid RSA-OAEP + AES-256-GCM

## Development

### Project Structure

```
pki-chain/
├── src/
│   ├── lib.rs                       # Library interface with comprehensive API docs
│   ├── main.rs                      # Application entry point
│   ├── webserver.rs                 # HTTPS web server (Axum + Tokio)
│   ├── protocol.rs                  # Protocol layer (owns Storage, Request/Response interface)
│   ├── storage.rs                   # Blockchain storage abstraction with in-memory keys
│   ├── pki_generator.rs             # Unified certificate generation for all types
│   ├── private_key_storage.rs       # Encrypted key store (PKCS#8 + hybrid encryption)
│   └── configs.rs                   # TOML configuration parsing
├── .github/
│   └── copilot-instructions.md      # AI coding assistant instructions
├── config.toml                     # Configuration file
├── generate_app_keypair.sh          # Application key generator
├── test_keypair_generation.sh       # End-to-end test suite
└── change_pfx_password.sh           # PFX password utility
```

### Building Documentation

Generate and view the API documentation:

```bash
cargo doc --open
```

### Dependencies

Key dependencies and their purposes:
- [`libblockchain`](https://github.com/jessethepro/libblockchain) - Custom blockchain storage engine with RocksDB backend
- `openssl` (0.10) - RSA-4096 key generation, X.509 certificate operations, SHA-256/SHA-512 hashing
- `axum` (0.8) - Web framework for HTTPS server and REST API
- `tokio` (1.48) - Async runtime for web server
- `axum-server` (0.8) - TLS/HTTPS support
- `keyutils` (0.4) - Linux kernel keyring integration for secure key management
- `anyhow` (1.0) - Ergonomic error handling with context chains
- `serde`/`serde_json` (1.0) - Data serialization
- `rpassword` (7.3) - Secure password input without echo
- `toml` (0.9) - TOML configuration file parsing
- `zeroize` (1.8) - Secure memory clearing for cryptographic keys

### Development Dependencies
- Standard Rust toolchain (1.70+)
- System OpenSSL development libraries (`libssl-dev` on Debian/Ubuntu)
- Linux kernel keyring support

## Security Considerations

### Best Practices

1. **Protect the Application Key**: The `key/pki-chain-app.key` file is loaded into memory and zeroized on drop. Store the file securely and back it up.

2. **Root CA Private Key**: The Root CA private key is stored as password-protected PKCS#8 in `exports/keystore/root_private_key.pkcs8`. This password is required on every startup. Store the password securely (e.g., password manager).

3. **Certificate Validation**: Always validate certificates using `openssl verify` before deployment.

4. **Blockchain Integrity**: Regularly validate blockchain integrity using the "Validate Blockchain" menu option.

5. **Keyring Security**: The Linux kernel keyring stores keys in memory. Ensure your system is properly secured and use full-disk encryption.

### Threat Model

- **Tamper Protection**: Blockchain storage detects unauthorized modifications via SHA-512 hashing
- **Rollback Protection**: Transaction-based operations prevent partial writes
- **Signature Verification**: Cross-chain validation ensures key-certificate consistency
- **Encryption at Rest**: Private keys encrypted with PKCS#8 (Root) or hybrid RSA+AES-GCM (others)
- **No Network Exposure**: TUI-only interface, no socket server

## Troubleshooting

### Common Issues

**"Failed to initialize storage"**
- Ensure `key/pki-chain-app.key` exists (run `./generate_app_keypair.sh`)
- Check file permissions on `data/` directories
- Verify keyring support on your Linux system

**"Failed to load app key into keyring"**
- Incorrect password for PKCS#8 file
- Keyring not available (requires Linux kernel keyring support)
- Check app key file is valid PKCS#8 format

**"Blockchain validation failed"**
- Possible data corruption or tampering detected
- Check blockchain integrity with validation tool
- Restore from backup if available

**"Failed to parse certificate"**
- Certificate data may be corrupted
- Verify blockchain integrity

**"Failed to decrypt private key"**
- Root CA key not found in keyring
- Possible file corruption in encrypted key store
- Check `exports/keystore/` permissions

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [libblockchain](https://github.com/jessethepro/libblockchain) for tamper-proof storage
- Uses OpenSSL for cryptographic operations
- Inspired by traditional PKI systems with blockchain enhancements

## Contact

- GitHub: [@jessethepro](https://github.com/jessethepro)
- Repository: [pki-chain](https://github.com/jessethepro/pki-chain)

---

**Note**: This is a demonstration project. For production use, conduct a thorough security audit and implement additional access controls, logging, and monitoring as required by your security policies.
