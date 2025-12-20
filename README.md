# PKI Chain

**A production-ready blockchain-backed Public Key Infrastructure (PKI) certificate authority system with an interactive terminal UI.**

Built in Rust with enterprise-grade cryptography, PKI Chain provides a complete three-tier CA hierarchy (Root CA → Intermediate CA → User Certificates) where all certificates and private keys are stored in tamper-proof blockchain storage powered by [libblockchain](https://github.com/jessethepro/libblockchain).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Highlights

✨ **Interactive TUI** - Manage certificates through a modern terminal interface  
🔐 **Blockchain Security** - Immutable storage with tamper detection  
🏗️ **Complete PKI** - Root CA, Intermediate CAs, and User certificates  
🔒 **RSA-4096** - Industry-standard cryptography with SHA-256 signatures  
🎯 **Fast Lookups** - O(1) certificate retrieval with in-memory indexing

## Features

- � **Terminal User Interface**: Modern cursive-based TUI for interactive certificate management
- 📝 **Interactive Forms**: Create both Intermediate CA and User certificates with form-based input and validation
- 🔐 **Blockchain Storage**: Dual blockchain instances ensure tamper-proof certificate and key storage
- 🔗 **Three-Tier PKI Hierarchy**: Complete CA chain (Root → Intermediate → User)
- 🔒 **Strong Cryptography**: 4096-bit RSA keys with SHA-256 signatures
- 🔄 **Transactional Safety**: Automatic rollback on storage failures
- ✅ **Certificate Validation**: OpenSSL X509Store-based chain validation with signature verification
- 🎯 **Height-Based Indexing**: O(1) certificate lookups with thread-safe Mutex-protected HashMap
- 🧵 **Thread Safety**: Arc-wrapped Protocol with concurrent access support
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

On first run, the application automatically initializes a complete 3-tier TLS certificate hierarchy in the blockchain. Use the interactive menu to:
- Create new Intermediate CA certificates
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
│       ┌────────────┴────────────────┐                          │
│       │                             │                          │
│  ┌────▼────────┐          ┌─────────▼──────┐                  │
│  │ Certificate │          │  Private Key   │                  │
│  │ Blockchain  │          │  Blockchain    │                  │
│  │ (PEM)       │          │  (DER)         │                  │
│  │ RocksDB     │          │  RocksDB       │                  │
│  └─────────────┘          └────────────────┘                  │
│                                                                │
│  Socket Server: Currently disabled (can be re-enabled)        │
└────────────────────────────────────────────────────────────────┘
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

**Important**: The `key/pki-chain-app.key` file is the master encryption key for the blockchain databases. **Keep it secure and backed up**. Loss of this key means permanent loss of access to stored certificates.

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

### Socket API (Currently Disabled)

External applications can interact with the PKI system via the Unix socket at `/tmp/pki_socket`.

#### Request Format

All requests use length-prefixed JSON:
- 4-byte little-endian length prefix
- JSON payload

#### Example: Create Intermediate CA

```json
{
  "type": "CreateIntermediate",
  "subject_common_name": "Operations CA",
  "organization": "ACME Corp",
  "organizational_unit": "IT",
  "locality": "Seattle",
  "state": "WA",
  "country": "US",
  "validity_days": 1825
}
```

#### Example: Create User Certificate

```json
{
  "type": "CreateUser",
  "subject_common_name": "john.doe@example.com",
  "organization": "ACME Corp",
  "organizational_unit": "Engineering",
  "locality": "Seattle",
  "state": "WA",
  "country": "US",
  "validity_days": 365,
  "issuer_common_name": "Operations CA"
}
```

#### Response Format

Responses use strongly-typed enums with tagged JSON:

```json
{
  "type": "CreateUserResponse",
  "message": "User certificate created successfully",
  "common_name": "john.doe@example.com",
  "organization": "ACME Corp",
  "organizational_unit": "Engineering",
  "locality": "Seattle",
  "state": "WA",
  "country": "US",
  "issuer_common_name": "Operations CA",
  "validity_days": 365,
  "height": 3
}
```

### Available Request Types

| Request Type | Description |
|-------------|-------------|
| `CreateIntermediate` | Create an Intermediate CA certificate |
| `CreateUser` | Create a User certificate (requires `issuer_common_name`) |
| `ListCertificates` | List certificates (filter: All/Intermediate/User/Root) |
| `PKIStatus` | Get PKI system status and statistics |
| `SocketTest` | Test socket connectivity |
| `GetWebClientTLSCertificate` | Retrieve pre-generated TLS certificate with full chain |

**Note**: The socket server is currently disabled in favor of the TUI interface. To re-enable, uncomment the socket server code in `src/main.rs`.

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

On first run, the application automatically initializes a complete 3-tier TLS certificate hierarchy in the blockchain:

### Height 0: Root CA
- **Subject CN**: `PKI Chain Root CA`
- **Type**: Self-signed Root Certificate Authority
- **Constraints**: CA=true, pathlen=1 (can sign one level of CAs)
- **Validity**: 5 years (1825 days)
- **Usage**: Signs Intermediate CAs
- **Export**: Private key exported to `exports/root_ca.key`

### Height 1: Intermediate TLS CA
- **Subject CN**: `webclient_intermediate_tls_ca`
- **Type**: Intermediate Certificate Authority
- **Constraints**: CA=true, pathlen=0 (can only sign end-entity certificates)
- **Validity**: 3 years (1095 days)
- **Signed By**: Root CA (Height 0)
- **Usage**: Signs TLS server certificates

### Height 2: WebClient TLS Certificate
- **Subject CN**: `webclient_cert.local`
- **Type**: TLS Server Certificate (end-entity)
- **Constraints**: CA=false
- **Extended Key Usage**: serverAuth (TLS server authentication)
- **Subject Alternative Names**:
  - DNS: localhost
  - IP: 127.0.0.1
  - IP: ::1
- **Validity**: 1 year (365 days)
- **Signed By**: Intermediate TLS CA (Height 1)
- **Usage**: Secures PKIWebClient HTTPS server

### User-Created Certificates
All certificates created via the TUI (or socket API) are stored at **heights 3 and above**.

## Configuration

### Key Paths

- **Application Key**: `key/pki-chain-app.key` (master encryption key)
- **Certificate Storage**: `data/certificates/` (RocksDB database)
- **Private Key Storage**: `data/private_keys/` (RocksDB database)
- **Unix Socket**: `/tmp/pki_socket`
- **Export Directory**: `exports/` (Root CA key exports)

### Certificate Parameters

- **RSA Key Size**: 4096 bits
- **Signature Algorithm**: SHA-256 with RSA
- **Root CA**: pathlen=1, validity 5 years (default)
- **Intermediate CA**: pathlen=0, validity configurable
- **User Certificates**: CA=false, validity configurable

## Development

### Project Structure

```
pki-chain/
├── src/
│   ├── lib.rs                       # Library interface
│   ├── main.rs                      # Application entry point
│   ├── ui.rs                        # Terminal user interface (TUI)
│   ├── protocol.rs                  # Protocol layer (owns Storage, Request/Response interface)
│   ├── storage.rs                   # Blockchain storage abstraction
│   ├── external_interface.rs        # Unix socket server (disabled)
│   ├── generate_root_ca.rs          # Root CA builder
│   ├── generate_intermediate_ca.rs  # Intermediate CA builder
│   ├── generate_user_keypair.rs     # User certificate builder
│   └── generate_webclient_tls.rs    # TLS server certificate builder
├── .github/
│   └── copilot-instructions.md      # AI coding assistant instructions
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
- [`libblockchain`](https://github.com/jessethepro/libblockchain) - Custom blockchain storage engine with hybrid encryption
- `openssl` (0.10) - RSA-4096 key generation, X.509 certificate operations, SHA-256 signatures
- `cursive` (0.21) - Terminal user interface framework for interactive forms and menus
- `anyhow` - Ergonomic error handling with context chains
- `serde`/`serde_json` - JSON serialization for socket protocol
- `rpassword` - Secure password input without echo

### Development Dependencies
- Standard Rust toolchain (1.70+)
- System OpenSSL development libraries (`libssl-dev` on Debian/Ubuntu)

## Security Considerations

### Best Practices

1. **Protect the Application Key**: The `key/pki-chain-app.key` file encrypts all blockchain data. Store it securely and back it up.

2. **Root CA Private Key**: The Root CA private key is exported to `exports/root_ca.key` on first run. This should be moved to offline/air-gapped storage immediately.

3. **Certificate Validation**: Always validate certificates using `openssl verify` before deployment.

4. **Blockchain Integrity**: Regularly validate blockchain integrity using the "Validate Blockchain" menu option.

5. **Socket Permissions**: The Unix socket at `/tmp/pki_socket` is accessible to all local users. Consider implementing access controls for production environments.

### Threat Model

- **Tamper Protection**: Blockchain storage detects unauthorized modifications
- **Rollback Protection**: Transaction-based operations prevent partial writes
- **Signature Verification**: Cross-chain validation ensures key-certificate consistency
- **No Network Exposure**: Unix socket provides local-only access

## Troubleshooting

### Common Issues

**"Failed to initialize storage"**
- Ensure `key/pki-chain-app.key` exists (run `./generate_app_keypair.sh`)
- Check file permissions on `data/` directories

**"Socket already in use"**
- Another instance is running, or socket wasn't cleaned up
- Remove: `rm /tmp/pki_socket`

**"Blockchain validation failed"**
- Possible data corruption or tampering detected
- Check blockchain integrity with validation tool
- Restore from backup if available

**"Failed to parse certificate"**
- Certificate data may be corrupted
- Verify blockchain integrity

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
