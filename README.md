# PKI Chain

A blockchain-backed Public Key Infrastructure (PKI) certificate authority system written in Rust. Provides a complete three-tier CA hierarchy (Root CA → Intermediate CA → User Certificates) with all certificates and private keys stored in tamper-proof blockchain storage.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Features

- 🔐 **Blockchain Storage**: Dual blockchain instances ensure tamper-proof certificate and key storage
- 🔗 **Three-Tier PKI Hierarchy**: Complete CA chain (Root → Intermediate → User)
- 🔒 **Strong Cryptography**: 4096-bit RSA keys with SHA-256 signatures
- 🔄 **Transactional Safety**: Automatic rollback on storage failures
- ✅ **Signature Verification**: Cross-validation between certificate and key chains
- 🔌 **Unix Socket API**: External IPC interface for certificate operations
- 🎯 **Height-Based Indexing**: O(1) certificate lookups with thread-safe Mutex-protected HashMap
- 🧵 **Thread Safety**: Arc-wrapped Storage with concurrent access support

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                      PKI Chain Application                    │
├─────────────────────────────────────────────────────────────┤
│  Main Process          │  Socket Server (Background Thread)  │
│  - Interactive Menu    │  - Unix Socket: /tmp/pki_socket    │
│  - Blockchain Init     │  - JSON Request/Response            │
│  - Root CA Generation  │  - Certificate Operations           │
└────────┬────────────────┴──────────────────┬─────────────────┘
         │                                   │
         └───────────────┬───────────────────┘
                         │
         ┌───────────────▼────────────────┐
         │   Arc<Storage> (Thread-Safe)   │
         │  - Transactional Operations    │
         │  - Signature Verification      │
         │  - Mutex<subject→height map>   │
         └───────────┬────────────────────┘
                     │
         ┌───────────┴────────────────┐
         │                            │
    ┌────▼────────┐          ┌───────▼──────┐
    │ Certificate │          │  Private Key │
    │ Blockchain  │          │  Blockchain  │
    │ (PEM)       │          │  (DER)       │
    └─────────────┘          └──────────────┘
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

### Interactive Mode

Run the application to start the interactive menu:

```bash
./target/release/pki-chain
```

**Menu Options:**
1. **Validate Blockchain** - Verify integrity of certificate and key chains
2. **Exit** - Shutdown application

### Socket API

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

```json
{
  "status": "Success",
  "message": "Certificate created successfully",
  "data": {
    "common_name": "john.doe@example.com",
    "organization": "ACME Corp"
  }
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
│   ├── main.rs                      # Application entry point
│   ├── storage.rs                   # Blockchain storage abstraction
│   ├── external_interface.rs        # Unix socket server
│   ├── generate_root_ca.rs          # Root CA builder
│   ├── generate_intermediate_ca.rs  # Intermediate CA builder
│   └── generate_user_keypair.rs     # User certificate builder
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

Key dependencies:
- [`libblockchain`](https://github.com/jessethepro/libblockchain) - Blockchain storage engine
- `openssl` - Cryptographic operations
- `anyhow` - Error handling
- `serde`/`serde_json` - Serialization
- `rpassword` - Secure password input

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
