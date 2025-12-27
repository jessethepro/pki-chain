# PKI Chain

**A production-ready blockchain-backed Public Key Infrastructure (PKI) certificate authority system with an interactive terminal UI.**

Built in Rust with enterprise-grade cryptography, PKI Chain provides a complete three-tier CA hierarchy (Root CA → Intermediate CA → User Certificates) with hybrid storage: certificates in blockchain (DER format), private keys in encrypted files (PKCS#8 for Root CA, RSA+AES-GCM-256 hybrid encryption for others), and SHA-512 integrity hashes in blockchain via [libblockchain](https://github.com/jessethepro/libblockchain). Features TOML-based configuration and Linux kernel keyring integration for secure key management.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Highlights

✨ **Interactive TUI** - Manage certificates through a modern terminal interface  
🔐 **Hybrid Storage** - Certificates in blockchain (DER), keys encrypted with AES-256-GCM  
🏗️ **Complete PKI** - Root CA, Intermediate CAs, and User certificates  
🔒 **RSA-4096** - Industry-standard cryptography with SHA-256 signatures  
🎯 **Fast Lookups** - O(1) certificate retrieval with in-memory indexing

## Features

- � **Terminal User Interface**: Modern cursive-based TUI for interactive certificate management
- 📝 **Interactive Forms**: Create both Intermediate CA and User certificates with form-based input and validation
- ⚙️ **Configuration Management**: TOML-based configuration for paths and keyring settings
- 🔐 **Hybrid Storage Architecture**: 
  - Certificates stored as DER in blockchain
  - Root CA: PKCS#8 PEM with password protection
  - Other keys: RSA + AES-GCM-256 hybrid encryption (AES key encrypted with Root CA public key)
  - SHA-512 hashes and signatures in key blockchain
- 🔑 **Keyring Integration**: Linux kernel keyring for secure in-memory key management
- 🔗 **Three-Tier PKI Hierarchy**: Complete CA chain (Root → Intermediate → User)
- 🔒 **Strong Cryptography**: 4096-bit RSA keys with SHA-256 signatures
- 🔄 **Transactional Safety**: Automatic rollback on storage failures
- ✅ **Certificate Validation**: OpenSSL X509Store-based chain validation with hash verification
- 🎯 **Height-Based Indexing**: O(1) certificate lookups with thread-safe Mutex-protected HashMap
- 🧵 **Thread Safety**: Protocol layer with Storage ownership and concurrent access support
- 📊 **Real-Time Status**: View blockchain statistics and certificate inventory
- 🏗️ **Protocol Layer**: All storage operations through Request/Response interface ensuring clean abstraction

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# 2. Generate master encryption key (REQUIRED for first run)
./generate_app_keypair.sh

# 3. Build the application
cargo build --release

# 4. Run the TUI
./target/release/pki-chain
```

On first run, the application automatically initializes the Root CA (height 0) in the blockchain. Use the interactive menu to:
- Create new Intermediate CA certificates (height 1+)
- Create User certificates signed by any Intermediate CA
- Validate blockchain integrity
- View system status and statistics

## Architecture

### Core Components

```
┌──────────────────────────────────────────────────────────────┐
│                   PKI Chain Application                       │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │           Cursive Terminal UI (Main Thread)            │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  Main Menu                                       │  │  │
│  │  │  1. Create Intermediate Certificate              │  │  │
│  │  │  2. Create User Certificate                      │  │  │
│  │  │  3. Validate Blockchain                          │  │  │
│  │  │  4. View System Status                           │  │  │
│  │  │  5. Exit                                         │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │                                                          │  │
│  │  Forms: EditView, SelectView, LinearLayout, Dialog      │  │
│  │  Validation: Required fields, Country code, Duplicates  │  │
│  └─────────────────────┬────────────────────────────────────┘  │
│                        │                                       │
│       ┌────────────────▼────────────────┐                      │
│       │   Arc<Protocol> (Thread-Safe)   │                      │
│       │  - Request/Response Interface   │                      │
│       │  - Storage Ownership            │                      │
│       │  - Certificate Validation       │                      │
│       └────────────┬────────────────────┘                      │
│                    │                                           │
│       ┌────────────▼────────────────┐                          │
│       │   Storage (Owned by Protocol)│                         │
│       │  - Transactional Operations  │                         │
│       │  - Signature Verification    │                         │
│       │  - Mutex<subject→height map> │                         │
│       └────────────┬─────────────────┘                         │
│                    │                                           │
│       ┌────────────┴─────────────────────────────┐            │
│       │                                          │            │
│  ┌────▼────────┐          ┌──────────▼─────────┐            │
│  │ Certificate │          │  Private Key       │            │
│  │ Blockchain  │          │  Blockchain        │            │
│  │ (DER)       │          │  (SHA-256 Hashes)  │            │
│  │ RocksDB     │          │  + Signatures CF   │            │
│  └─────────────┘          │  RocksDB           │            │
│                           └────────────────────┘            │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │     Encrypted Key Store (Filesystem)          │          │
│  │  exports/keystore/ (configurable)             │          │
│  │  - Root (h=0): PKCS#8 PEM + password          │          │
│  │  - Others: RSA + AES-GCM-256 hybrid           │          │
│  │    Format: [AES Len][Enc AES Key][Nonce]     │          │
│  │            [Tag][Data Len][Encrypted Data]   │          │
│  └──────────────────────────────────────────────┘          │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │  Linux Kernel Keyring (In-Memory Keys)        │          │
│  │  - App key loaded from PKCS#8 file            │          │
│  │  - Root key for encryption/decryption         │          │
│  └──────────────────────────────────────────────┘          │
│                                                              │
│  Configuration: config.toml (paths, keyring settings)       │
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

# Build the project
cargo build --release

# Run the application
./target/release/pki-chain
```

**Important**: The `key/pki-chain-app.key` file is the master key loaded into the Linux kernel keyring for secure operations. The Root CA private key stored in the keyring is used to encrypt/decrypt other private keys. **Keep it secure and backed up**. Loss of this key means permanent loss of access to stored certificates.

## Usage

### Terminal User Interface

Run the application to launch the interactive TUI:

```bash
./target/release/pki-chain
```

**TUI Features:**

1. **Create Intermediate Certificate**
   - Interactive form with all Distinguished Name fields
   - Fields: Common Name (CN), Organization (O), Organizational Unit (OU), Locality (L), State (ST), Country (C)
   - Configurable validity period (default: 1825 days / 5 years)
   - Real-time validation:
     - All fields required
     - Country code must be exactly 2 letters
     - Validity must be positive
     - Duplicate subject name detection
   - Automatic blockchain storage with transactional safety

2. **Create User Certificate**
   - Interactive form with all Distinguished Name fields
   - Dropdown menu to select issuing Intermediate CA
   - Fields: Common Name (CN), Organization (O), Organizational Unit (OU), Locality (L), State (ST), Country (C), Issuer CA
   - Configurable validity period (default: 365 days / 1 year)
   - Real-time validation:
     - All fields required
     - Country code must be exactly 2 letters
     - Validity must be positive
     - Duplicate subject name detection
   - Automatic blockchain storage with transactional safety

3. **Validate Blockchain**
   - Runs `validate()` on both certificate and private key chains
   - Displays block counts and validation status
   - Ensures signature consistency between chains

4. **View System Status**
   - Certificate blockchain statistics
   - Private key blockchain statistics
   - List of all tracked subject names
   - Block heights and validation state

5. **Exit**
   - Gracefully shutdown application

### Typical Workflow

```
1. First Run:
   $ ./generate_app_keypair.sh        # Create master encryption key
   $ ./target/release/pki-chain       # Initialize with 3-tier TLS hierarchy

2. Create Intermediate CA:
   - Select "Create Intermediate Certificate"
   - Fill form fields:
     CN: "Operations CA"
     O: "ACME Corp"
     OU: "IT Department"
     L: "Seattle"
     ST: "Washington"
     C: "US"
     Validity: 1825 (days)
   - Press OK to generate and store
   - Blockchain automatically assigns height (e.g., height 3)

3. Create User Certificate:
   - Select "Create User Certificate"
   - Choose issuing CA from dropdown (e.g., "Operations CA")
   - Fill form fields:
     CN: "john.doe@example.com"
     O: "ACME Corp"
     OU: "Engineering"
     L: "Seattle"
     ST: "Washington"
     C: "US"
     Validity: 365 (days)
   - Press OK to generate and store
   - Blockchain automatically assigns height (e.g., height 4)

4. Verify Storage:
   - Select "View System Status"
   - Check certificate count increased
   - Verify new subject names in tracked list

5. Validate Integrity:
   - Select "Validate Blockchain"
   - Confirms both chains are valid
   - Shows total block count
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
│   ├── ui.rs                        # Terminal user interface (TUI)
│   ├── protocol.rs                  # Protocol layer (owns Storage, Request/Response interface)
│   ├── storage.rs                   # Blockchain storage abstraction with keyring integration
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
- `cursive` (0.21) - Terminal user interface framework for interactive forms and menus
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

1. **Protect the Application Key**: The `key/pki-chain-app.key` file is loaded into the kernel keyring. Store it securely and back it up.

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
