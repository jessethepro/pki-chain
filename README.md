# PKI Chain

**A production-ready blockchain-backed Public Key Infrastructure (PKI) certificate authority with secure web-based management interface.**

Built in Rust with enterprise-grade cryptography, PKI Chain provides a complete three-tier CA hierarchy (Root CA → Intermediate CA → User Certificates) with state-driven authentication, Maud HTML templates, and comprehensive logging. Features hybrid storage: certificates in blockchain (DER format), private keys encrypted with RSA+AES-GCM-256, and SHA-512 integrity hashes via [libblockchain](https://github.com/jessethepro/libblockchain).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/github/v/release/jessethepro/pki-chain)](https://github.com/jessethepro/pki-chain/releases)

## Highlights

🌐 **Web-Based Management** - Complete HTTPS interface with state-driven authentication  
🔐 **Secure Login** - X.509 certificate + private key upload with challenge-response verification  
🎨 **Maud Templates** - Server-side HTML rendering with custom styling  
📊 **Comprehensive Logging** - Daily rotating logs with tracing framework  
🏗️ **Complete PKI** - Root CA, Intermediate CAs, and User certificates  
🔒 **RSA-4096** - Industry-standard cryptography with SHA-256 signatures  
🎯 **Fast Lookups** - O(1) certificate retrieval with in-memory indexing

## Features

### Web Interface & Authentication
- 🌐 **HTTPS Web Server**: Secure Axum-based interface on port 3000
- 🔐 **State-Driven Authentication**: NoExist → Initialized → CreateAdmin → Ready → Authenticated
- 📜 **X.509 Certificate Login**: Upload certificate + private key for authentication
- 🔑 **Challenge-Response**: Cryptographic proof of private key ownership
- 💾 **Auto-Download Credentials**: Certificate and key files after admin creation
- 🎨 **Custom UI**: Maud HTML templates with plum purple styling (rgb(46, 15, 92))

### PKI Management
- 🏗️ **Three-Tier Hierarchy**: Root CA → Intermediate CA → User Certificates
- 🔒 **4096-bit RSA Keys**: Strong cryptography with SHA-256 signatures
- 📋 **Admin Dashboard**: Manage certificates and view system status
- ✅ **Certificate Validation**: OpenSSL-based chain validation
- 🔄 **Transactional Safety**: Automatic rollback on storage failures

### Security & Storage
- 🔐 **Hybrid Storage Architecture**: 
  - Certificates stored as DER in blockchain (encrypted with app key)
  - Root CA: PKCS#8 PEM with password protection
  - Other keys: RSA + AES-GCM-256 hybrid encryption
  - SHA-512 hashes and signatures in blockchain
- 🔑 **In-Memory Key Management**: Secure runtime storage with zeroize on drop
- 🛡️ **Password-Protected Root CA**: Never stored in plaintext
- 🔐 **Encrypted Private Keys**: Hybrid RSA-OAEP + AES-GCM-256

### Logging & Monitoring
- 📝 **Tracing Framework**: Structured logging with tracing-subscriber
- 🔄 **Daily Log Rotation**: Automatic rotation via tracing-appender
- 📊 **Dual Output**: Console + file logging (logs/webserver.log)
- 🚫 **No Panics**: All errors caught, logged, and handled gracefully
- 🔍 **Error Context**: Detailed error information for debugging


## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# 2. Generate master encryption key (REQUIRED for first run)
./generate_app_keypair.sh

# 3. Generate TLS certificates for HTTPS server
./generate-webserver-certs.sh

# 4. Build the application
cargo build --release

# 5. Start the web server
./target/release/pki-chain

# 6. Access the web interface
# Open browser: https://127.0.0.1:3000
```

### First-Time Setup Workflow

1. **Initialize** - Create Root CA with password (web form)
2. **Create Admin** - First admin user + intermediate CA (auto-downloads certificate + key)
3. **Login** - Upload certificate + private key + enter Root CA password
4. **Authenticated** - Access admin dashboard to manage certificates

## Web Interface

Access the web application at **https://127.0.0.1:3000**

### Available Routes

- **`/`** - State-driven landing page (shows appropriate form based on system state)
- **`/initialize`** - Create Root CA with password
- **`/create-admin`** - Create first administrator account
- **`/login`** - X.509 certificate authentication with challenge-response
- **`/admin/dashboard`** - Admin control panel
- **`/admin/create-user`** - Create user certificates
- **`/admin/create-intermediate`** - Create intermediate CAs
- **`/admin/status`** - View system statistics
- **`/logout`** - End authenticated session

### Authentication Flow

```
1. Upload X.509 Certificate (.crt file)
2. Upload Private Key (.key file)
3. Enter Root CA Password
4. Server verifies:
   ✓ Certificate exists in PKI system
   ✓ Private key matches certificate public key
   ✓ Root CA password is correct
   ✓ Challenge-response signature valid
5. Access granted to admin dashboard
```

**Security Note**: Browser will show security warning for self-signed TLS certificate (expected for local development).

## Architecture

### Component Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Browser (HTTPS)                      │
│              https://127.0.0.1:3000                         │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  Axum Web Server                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  State Machine: NoExist → Initialized →              │  │
│  │  CreateAdmin → Ready → Authenticated                 │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Maud Templates (templates.rs)                       │  │
│  │  - State-driven HTML rendering                       │  │
│  │  - Custom styling (rgb(46,15,92))                    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Tracing Framework                                   │  │
│  │  - Daily rotating logs (logs/webserver.log)          │  │
│  │  - Error/Warn/Info levels                            │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Storage Layer (storage.rs)                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Type-State Pattern:                                 │  │
│  │  Storage<NoExist> → Storage<Initialized> →          │  │
│  │  Storage<Ready>                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Certificate Index (HashMap<String, u64>)            │  │
│  │  - Subject CN → Blockchain Height                    │  │
│  │  - O(1) certificate lookups                          │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│          Three Blockchain Storage (libblockchain)           │
│  ┌──────────────────┬──────────────────┬─────────────────┐  │
│  │ Certificate      │ Private Key      │ CRL             │  │
│  │ Blockchain       │ Blockchain       │ Blockchain      │  │
│  │                  │                  │                 │  │
│  │ Height 0:        │ Height 0:        │ (Empty until    │  │
│  │   Root CA (DER)  │   Root Key Hash  │  revocations)   │  │
│  │ Height 1+:       │ Height 1+:       │                 │  │
│  │   User Certs     │   Key Hashes     │                 │  │
│  │                  │                  │                 │  │
│  │ ▲ Encrypted with │ ▲ Encrypted with │ ▲ Encrypted     │  │
│  │   app.crt key    │   Root CA key    │   with app.crt  │  │
│  └──────────────────┴──────────────────┴─────────────────┘  │
│                    RocksDB Backend                          │
└─────────────────────────────────────────────────────────────┘
```

### Key Modules

- **[main.rs](src/main.rs)** (96 lines): Entry point, launches webserver
- **[webserver.rs](src/webserver.rs)** (552 lines): Axum HTTPS server with state machine
  - CA server states: NoExist, Initialized, CreateAdmin, Ready, Authenticated
  - Tracing initialization with daily rotation
  - All panics replaced with graceful error handling
- **[templates.rs](src/templates.rs)** (411 lines): Maud HTML templates
  - State-driven page rendering
  - Custom CSS with plum purple theme
  - Certificate/key download pages
- **[storage.rs](src/storage.rs)** (784 lines): Type-state blockchain storage
  - Three separate blockchains (certificates, keys, CRL)
  - In-memory subject name index for fast lookups
  - Transactional operations with rollback
- **[pki_generator.rs](src/pki_generator.rs)** (217 lines): Certificate generation
  - Unified generation for all certificate types
  - 4096-bit RSA keys, SHA-256 signatures
- **[encryption.rs](src/encryption.rs)** (211 lines): Hybrid RSA + AES-GCM-256
- **[configs.rs](src/configs.rs)** (157 lines): TOML configuration management

### PKI Hierarchy

```
Root CA (self-signed, pathlen=1)
  └── Intermediate CA (signed by Root, pathlen=0)
      └── User Certificate (signed by Intermediate, CA=false)
```

### Storage Architecture

**Blockchain Layer** (RocksDB):
- **Certificate Chain**: X.509 certificates in DER format (encrypted with app.crt)
- **Private Key Chain**: SHA-512 hashes + signatures (encrypted with app.crt)
- **CRL Chain**: Certificate Revocation Lists (encrypted with app.crt)

**Filesystem Layer** (`exports/keystore/`):
- **Root CA Key**: PKCS#8 PEM with password protection
- **Other Keys**: Hybrid RSA-OAEP + AES-GCM-256 encryption

**In-Memory**:
- Application key loaded from `key/app.key` (decrypts blockchains)
- Certificate index: `HashMap<String, u64>` for O(1) lookups
- Secure memory handling with zeroize on drop

## Installation

### Prerequisites

- **Rust 1.70+** (tested with 1.85)
- **OpenSSL development libraries** (`libssl-dev` or `openssl-devel`)
- **Linux/Unix system** (for file permissions and TLS)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# Generate application encryption key (FIRST RUN ONLY)
./generate_app_keypair.sh
# Output: Creates key/app.key and certificate/app.crt

# Generate TLS certificates for web server (FIRST RUN ONLY)
./generate-certs.sh
# Output: Creates web_certs/server/chain.pem and server.key

# Build the project
cargo build --release

# Run the web server
./target/release/pki-chain
```

**🔒 Security Note**: `key/app.key` is the master encryption key loaded into memory. **Keep this file secure and backed up**. Loss of the app key means permanent loss of access to blockchain data.

## Usage

### Web Interface

Access the web application at **https://127.0.0.1:3000**

```bash
# Start the server
./target/release/pki-chain

# Server output:
# 🔒 PKI Chain Certificate Authority
#    HTTPS: https://127.0.0.1:3000
#    TLS Cert: web_certs/server/chain.pem
#    TLS Key: web_certs/server/server.key
#    Web Root: web_root/
#    Log Directory: logs/
# ✅ Server ready!
```

### First-Time Setup Workflow

1. **Initialize System** (creates Root CA):
   - Navigate to https://127.0.0.1:3000
   - Enter Root CA password (stored in encrypted PKCS#8 format)
   - Click "Initialize" button

2. **Create Admin User** (auto-downloads certificate + key):
   - Fill out Distinguished Name fields (CN, O, OU, L, ST, C)
   - System creates intermediate CA + user certificate
   - Browser auto-downloads `<username>.crt` and `<username>.key`

3. **Login** (X.509 certificate authentication):
   - Upload `.crt` file (certificate)
   - Upload `.key` file (private key)
   - Enter Root CA password
   - Challenge-response verification authenticates you

4. **Admin Dashboard** (certificate management):
   - Create user certificates
   - Create intermediate CAs
   - View system status
   - Certificate validation

### Logging

All webserver activity logged to `logs/webserver.log` with daily rotation:

```
2026-01-21T10:30:45.123Z INFO pki_chain::webserver: Starting PKI Chain web server
2026-01-21T10:30:45.456Z INFO pki_chain::webserver: Storage state: NoExist (fresh installation)
2026-01-21T10:31:12.789Z INFO pki_chain::webserver: Received admin creation request for CN: jesse.johnson
2026-01-21T10:31:15.234Z INFO pki_chain::webserver: Admin user created successfully: jesse.johnson
2026-01-21T10:32:03.567Z INFO pki_chain::webserver: Received login request
2026-01-21T10:32:04.890Z INFO pki_chain::webserver: User authenticated successfully: jesse.johnson
```

**Log Levels**: INFO (normal operations), WARN (recoverable issues), ERROR (failures)

## Configuration

All settings configured via `config.toml` in the project root:

```toml
[blockchains]
certificate_path = "data/certificates"   # Certificate blockchain (RocksDB)
private_key_path = "data/private_keys"   # Private key blockchain (RocksDB)
crl_path = "data/crl"                    # CRL blockchain (RocksDB)

[key_exports]
app_key_path = "key/app.key"             # Master encryption key
app_cert_path = "certificate/app.crt"    # Application certificate (public key)
root_key_name = "0.key.enc"              # Root CA private key filename
key_export_directory_path = "exports/keystore"  # Encrypted key storage

[server]
host = "127.0.0.1"                       # Web server bind address
port = 3000                              # Web server port
web_root = "web_root"                    # Static file directory
tls_cert_path = "web_certs/server/chain.pem"   # TLS certificate
tls_key_path = "web_certs/server/server.key"   # TLS private key

[root_ca_defaults]
root_ca_common_name = "MenaceLabs Root CA"
root_ca_organization = "MenaceLabs"
root_ca_organizational_unit = "CY"
root_ca_locality = "Sao Jose dos Campos"
root_ca_state = "SP"
root_ca_country = "BR"
root_ca_validity_days = 3650             # 10 years
```

All paths are relative to the project root. Adjust as needed for your deployment.

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

On first run, the web interface guides you through initialization:

### Height 0: Root CA (Created During Initialization)
- **Subject CN**: `MenaceLabs Root CA` (configurable in config.toml)
- **Type**: Self-signed Root Certificate Authority
- **Constraints**: CA=true, pathlen=1 (can sign one level of CAs)
- **Validity**: 10 years (3650 days, configurable)
- **Usage**: Signs Intermediate CAs
- **Storage**: Private key stored as password-protected PKCS#8 PEM in blockchain

### Heights 1-2: First Admin (Created During Setup)
- **Height 1**: Admin Intermediate CA (pathlen=0, signed by Root)
- **Height 2**: Admin User Certificate (signed by Admin Intermediate)
- **Private Keys**: Encrypted with Root CA public key (hybrid RSA + AES-GCM-256)

### Heights 3+: User-Created Certificates
All subsequent certificates created via admin dashboard:
- **Intermediate CAs**: pathlen=0, configurable validity
- **User Certificates**: CA=false, configurable validity
- **Encryption**: All private keys encrypted with Root CA public key

## Certificate Parameters

- **RSA Key Size**: 4096 bits
- **Signature Algorithm**: SHA-256 with RSA
- **Root CA**: pathlen=1, validity 10 years (default)
- **Intermediate CA**: pathlen=0, validity 5 years (default)
- **User Certificates**: CA=false, validity 2 years (default)
- **Encryption**:
  - Root CA: PKCS#8 PEM with password protection
  - Others: Hybrid RSA-OAEP + AES-256-GCM (AES key encrypted with Root CA public key)

## Development

### Project Structure

```
pki-chain/
├── src/
│   ├── lib.rs                       # Library interface
│   ├── main.rs                      # Application entry point
│   ├── webserver.rs                 # HTTPS web server (Axum + state machine)
│   ├── templates.rs                 # Maud HTML templates (411 lines)
│   ├── storage.rs                   # Type-state blockchain storage (784 lines)
│   ├── pki_generator.rs             # Unified certificate generation
│   ├── encryption.rs                # Hybrid RSA + AES-GCM-256 encryption
│   ├── private_key_storage.rs       # Encrypted key store utilities
│   ├── key_archive.rs               # Tar-based key backup/restore
│   └── configs.rs                   # TOML configuration parsing
├── .github/
│   └── copilot-instructions.md      # AI coding assistant instructions
├── config.toml                     # Configuration file
├── generate_app_keypair.sh          # Application key generator
├── generate-certs.sh                # TLS certificate generator
├── test_keypair_generation.sh       # End-to-end test suite
├── web_root/                        # Static web files (HTML/CSS/JS)
├── web_certs/                       # TLS certificates (generated)
├── logs/                            # Daily rotating webserver logs
├── data/                            # Blockchain databases (RocksDB)
└── exports/keystore/                # Encrypted private key storage
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

### Security Considerations

PKI Chain implements multiple layers of security:

**Authentication & Access Control:**
- X.509 certificate-based authentication (no passwords)
- Challenge-response signature verification
- Root CA password protection for key operations
- Session-based access control (authenticated vs unauthenticated)

**Encryption at Rest:**
- Root CA private key: PKCS#8 PEM with password protection
- Other private keys: Hybrid RSA-OAEP + AES-256-GCM encryption
- Blockchain data: Encrypted with application public key
- All keys zeroized in memory on drop

**Data Integrity:**
- Blockchain storage provides tamper detection
- SHA-512 hashing for private key verification
- Transaction-based operations with rollback
- Cross-chain validation (certificates ↔ key hashes)

**Logging & Monitoring:**
- Daily rotating logs in `logs/webserver.log`
- Authentication attempts logged with username
- All errors logged before displaying to user
- Graceful error handling (no panics)

**Network Security:**
- HTTPS only (TLS 1.3)
- Self-signed certificates for local development
- Localhost binding by default (127.0.0.1:3000)

## Troubleshooting

### Common Issues

**"Failed to initialize storage"**
- Ensure `key/app.key` exists (run `./generate_app_keypair.sh`)
- Check file permissions on `data/` directories
- Verify application certificate exists at `certificate/app.crt`

**"Certificate not found in PKI system" (Login Error)**
- Ensure you uploaded the correct certificate file
- Certificate must have been created through the admin dashboard
- Check logs/webserver.log for details

**"Invalid Root CA password"**
- Verify you're using the password set during initialization
- Root CA password is case-sensitive
- Check for extra spaces or special characters

**"Blockchain validation failed"**
- Possible data corruption detected
- Check blockchain integrity
- If starting fresh, run initialization again (deletes existing data)

**"Failed to open certificate blockchain"**
- RocksDB files may be locked by another process
- Check that only one instance of pki-chain is running
- Verify permissions on `data/` directory

**Browser Shows Security Warning**
- Expected for self-signed TLS certificates
- Click "Advanced" → "Proceed to localhost" (safe for local development)
- For production, use properly signed certificates

**Log Files Growing Large**
- Logs rotate daily automatically (logs/webserver.log.YYYY-MM-DD)
- Old logs must be manually archived or deleted
- Consider setting up log rotation policy

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
- Axum web framework for async HTTPS server
- Maud templating for server-side HTML rendering
- Tracing framework for comprehensive logging

## Contact

- GitHub: [@jessethepro](https://github.com/jessethepro)
- Repository: [pki-chain](https://github.com/jessethepro/pki-chain)

---

**Note**: This is a demonstration project. For production use, conduct a thorough security audit and implement additional access controls, monitoring, and hardening as required by your security policies.
