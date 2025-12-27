# PKI Chain Copilot Instructions

## Project Overview

This is a blockchain-backed PKI (Public Key Infrastructure) certificate authority system written in Rust. It manages a complete certificate chain (Root CA → Intermediate CA → User Certificates) with all certificates and private keys stored in tamper-proof blockchain storage via the `libblockchain` dependency.

**Key Dependencies**: `openssl` (4096-bit RSA, X.509 operations), `anyhow` (error chaining with `.context()`), `serde`/`serde_json` (data serialization), `cursive` (TUI framework), `keyutils` (Linux kernel keyring), `toml` (configuration), `zeroize` (secure memory), `libblockchain` (GitHub: `jessethepro/libblockchain`)

## Architecture

### Core Components

- **Configuration System**: TOML-based configuration ([src/configs.rs](src/configs.rs), [config.toml](config.toml)) defines paths for blockchains, keyring settings, and key exports. `AppConfig::load()` reads from `config.toml` with sections: `[blockchains]` (certificate_path, private_key_path), `[app_keyring]` (app_key_path, app_key_name, root_key_name), `[key_exports]` (directory). Loaded in main.rs and passed to storage layer. (~45 lines)
- **Terminal User Interface**: Cursive-based TUI ([src/ui.rs](src/ui.rs)) provides interactive certificate management with form-based input, validation, and real-time status displays. Primary interface for certificate operations. Interacts with Protocol layer (not wrapped in Arc in UI, Protocol owns Storage). (~665 lines)
- **Protocol Layer**: Abstraction layer ([src/protocol.rs](src/protocol.rs)) that owns `Storage` and provides `process_request(&self, Request) -> Result<Response>` interface. All certificate operations flow through Protocol's request/response pattern. Enables clean separation between UI and storage logic. Created in main.rs as `Protocol::new(storage)` (not Arc-wrapped). (~450 lines)
- **PKI Generator**: Unified certificate generation module ([src/pki_generator.rs](src/pki_generator.rs)) containing `generate_root_ca()` and `generate_key_pair()` functions. Defines `CertificateData` struct and `CertificateDataType` enum. Handles all certificate types (Root CA, Intermediate CA, User, TLS) through a single code path with type-specific extensions. (~217 lines)
- **Encrypted Key Store**: Module ([src/private_key_storage.rs](src/private_key_storage.rs)) providing `EncryptedKeyStore` struct for secure private key management. Uses hybrid encryption:
  - **Root CA (height 0)**: PKCS#8 PEM format with optional password protection (AES-256-CBC when encrypted). Stored as `root_private_key.pkcs8`. Password prompted on startup.
  - **Other keys (height 1+)**: Hybrid RSA + AES-GCM-256 encryption. Random AES-256 key encrypts private key DER, then AES key is encrypted with Root CA public key using RSA-OAEP. Format: `[AES Key Len u32][Encrypted AES Key][Nonce(12)][Tag(16)][Data Len u32][Encrypted Data]`. Stored as `{height}.key.enc`.
  Methods: `store_key(height, root_pub_key, pkey)` encrypts and writes, `retrieve_key(height)` decrypts using Root CA private key from keyring. (~270 lines)
- **Hybrid Storage Architecture**: 
  - **Certificate Blockchain** (configurable via config.toml, default: `data/certificates/`): Stores X.509 certificates in DER format
  - **Private Key Blockchain** (configurable via config.toml, default: `data/private_keys/`): Stores SHA-512 hashes of private keys with signatures column family (changed from SHA-256 to SHA-512)
  - **Encrypted Key Store** (configurable via config.toml, default: `exports/keystore/`): Encrypted private keys in filesystem
    - Root CA: PKCS#8 PEM (password-protected)
    - Others: Hybrid RSA+AES-GCM-256 encryption
  - **Linux Kernel Keyring**: In-memory storage for app key and root key. App key loaded from PKCS#8 file on startup, root key added to keyring after decryption.
  - Both blockchains are RocksDB databases with blockchain validation
  - Owned by `Storage` struct, which is owned by `Protocol` (~578 lines)
- **Application Key**: Configurable path (default: `key/pki-chain-app.key`) is loaded into Linux kernel keyring on startup. Prompts for password if PKCS#8 is encrypted. Used to encrypt/decrypt blockchain databases. Generated via `./generate_app_keypair.sh`.
- **Library Interface**: ([src/lib.rs](src/lib.rs)) exposes public modules and provides comprehensive documentation for using PKI Chain as a library. Includes usage examples, architecture diagrams, and API reference. (~322 lines)
- **Three-Tier Certificate Hierarchy**:
  - Root CA (self-signed, genesis block at height 0)
  - Intermediate CAs (signed by Root, pathlen=0)
  - User Certificates (signed by Intermediate, CA=false)

### Critical Data Flow

1. **Initialization** ([main.rs](src/main.rs), [storage.rs](src/storage.rs)): On first run, generates only the Root CA and stores as the first block:
   - Height 0: Root CA (self-signed, pathlen=1, 10-year validity, subject: "MenaceLabs Root CA")
   
   Root CA private key stored as password-protected PKCS#8 PEM in `exports/keystore/root_private_key.pkcs8`. Password prompted during initialization. Subsequent runs skip generation if `storage.is_empty()` returns false. **User-created certificates (Intermediate CAs and User certs) start at height 1+**. Main loads `AppConfig` from config.toml, creates `Storage` with config (which loads app key into keyring and prompts for password), creates `Protocol::new(storage)`, then passes Protocol to TUI via `ui::run_ui()`.

2. **TUI Certificate Creation** ([ui.rs](src/ui.rs), [protocol.rs](src/protocol.rs)): Users create both Intermediate CAs and User certificates through interactive forms with real-time validation. Forms validate all DN fields (CN, O, OU, L, ST, C), country code format (exactly 2 letters), and validity period (positive integer). User certificate form includes dropdown to select issuing Intermediate CA. UI constructs `Request::CreateIntermediate` or `Request::CreateUser` with `CertificateData` struct and calls `protocol.process_request()`. Protocol retrieves signing key/cert from blockchain via `get_key_certificate_by_height()`, then calls `pki_generator::generate_key_pair()` which atomically generates the key pair and certificate based on `cert_type`.

3. **Certificate Generation** ([pki_generator.rs](src/pki_generator.rs)): All certificate types use the unified `generate_key_pair(cert_data, signing_key)` function. For Root CAs, call `generate_root_ca()` which generates a new private key and passes it to `generate_key_pair()`. The function automatically handles different certificate types via `CertificateDataType` enum, applying appropriate extensions (BasicConstraints with pathlen, KeyUsage, ExtendedKeyUsage for TLS). Returns `Result<(PKey<Private>, CertificateData)>`.

4. **Certificate Storage** ([storage.rs](src/storage.rs)): New certificates stored as DER via `put_block()` on certificate blockchain. Private keys encrypted and written to `exports/keystore/`:
   - Root CA (height 0): Password-protected PKCS#8 PEM format
   - Others (height 1+): Hybrid RSA + AES-GCM-256 format
   SHA-512 hash (changed from SHA-256) and certificate signature stored in private key blockchain. Blockchain automatically assigns heights. On failure during key storage, certificate is rolled back via `delete_latest_block()`. All operations are transactional.

5. **State Management** ([storage.rs](src/storage.rs)): In-memory `subject_name_to_height` Mutex-wrapped HashMap inside `Storage` struct maps common names to block heights for fast certificate retrieval. Populated on startup by iterating entire certificate blockchain (called from main.rs via `populate_subject_name_index()`). Validates against duplicate subject common names before creation. Thread-safe access via `.lock().unwrap()`. Protocol accesses via `protocol.storage.subject_name_to_height`.

## Key Conventions

### Unified Certificate Generation

All certificate types (Root CA, Intermediate CA, User, TLS) are generated through a unified code path in [pki_generator.rs](src/pki_generator.rs). The `CertificateData` struct contains all necessary fields including `cert_type: CertificateDataType` enum:

```rust
// For Root CA (self-signed)
let cert_data = CertificateData {
    subject_common_name: "PKI Chain Root CA".to_string(),
    issuer_common_name: "PKI Chain Root CA".to_string(), // Self-signed
    organization: "MenaceLabs".to_string(),
    organizational_unit: "CY".to_string(),
    locality: "Sao Jose dos Campos".to_string(),
    state: "SP".to_string(),
    country: "BR".to_string(),
    validity_days: 365 * 5,
    cert_type: CertificateDataType::RootCA,
};
let (private_key, cert_data) = generate_root_ca(cert_data)?;

// For Intermediate/User certificates
let (private_key, cert_data) = generate_key_pair(cert_data, signing_key)?;
```

The function automatically applies appropriate X.509 extensions based on `cert_type`:
- **RootCA**: `pathlen=1`, keyCertSign, cRLSign
- **IntermediateCA**: `pathlen=0`, keyCertSign, cRLSign
- **UserCert**: `CA=false`, digitalSignature, keyEncipherment
- **TlsCert**: `serverAuth`, SubjectAltName with localhost/127.0.0.1/::1

### Storage Format

- **Certificates**: Stored as DER in certificate blockchain (`to_der()`)
- **Private Keys**: 
  - Encrypted with AES-256-GCM in `exports/keystore/` filesystem directory
  - File format: `[nonce (12)][tag (16)][ciphertext]`
  - SHA-256 hash stored in private key blockchain main column family
  - Certificate signature stored in private key blockchain signatures column family
- **Retrieval**: 
  - Certificates: `get_block_by_height(n)` or `get_block_by_uuid(&uuid)` from libblockchain, parse with `X509::from_der()`
  - Private keys: `encrypted_key_store.retrieve_key(name)` decrypts from filesystem

### Error Handling

Use `anyhow::Context` for all blockchain operations to preserve error chains:

```rust
_certificate_chain
    .lock()
    .unwrap()
    .put_block(cert_pem)
    .context("Failed to store certificate in blockchain")?;
```

## Development Workflows

### Building and Running

```bash
# Build (requires libblockchain from GitHub)
cargo build --release

# Run application (starts socket server and interactive menu)
# Note: Release binary is at target/release/pki-chain
./target/debug/pki-chain   # or ./target/release/pki-chain
```

**First run prerequisites**: Execute `./generate_app_keypair.sh` to create `key/pki-chain-app.key` before running the application.

TUI menu options (cursive-based interface):
1. **Create Intermediate Certificate** - Interactive form for creating Intermediate CA certificates with all DN fields (CN, O, OU, L, ST, C) and validity period. Includes real-time validation.
2. **Create User Certificate** - Interactive form for creating User certificates with DN fields and validity period. Includes dropdown to select issuing Intermediate CA from existing CAs. Includes real-time validation.
3. **Validate Blockchain** - Runs `validate()` on both certificate and private key chains, displays block counts and validation status
4. **View System Status** - Shows blockchain statistics, block heights, and tracked subject names
5. **Exit** - Terminates application gracefully

### Testing PKI Operations

Use `test_keypair_generation.sh` for end-to-end testing:

```bash
./test_keypair_generation.sh
# Prompts for application PFX path, generates Root → Intermediate → 5 User certs
# Creates temporary test directory, performs full PKI hierarchy validation
```

### Shell Script Utilities

Three key scripts in project root:

1. **`generate_app_keypair.sh`**: Creates `key/pki-chain-app.key` (master key for blockchain encryption). **Critical**: This key must exist before running the application. Lost keys = unrecoverable blockchain data.

2. **`test_keypair_generation.sh`**: End-to-end PKI testing - generates complete hierarchy (Root → Intermediate → 5 User certificates), validates chain integrity, tests exports.

3. **`change_pfx_password.sh`**: Changes password on PFX files using application PFX for authentication. Usage: `./change_pfx_password.sh <app_pfx> <target_pfx>`

## Integration Points

### libblockchain Dependency

- **Source**: GitHub repository `jessethepro/libblockchain` (specified in Cargo.toml as git dependency)
- **Key APIs**: `BlockChain::new(path, key_path)`, `put_block()`, `get_block_by_height()`, `get_block_by_uuid()`, `validate()`, `block_count()`, `delete_latest_block()`, `iter()`
- **Storage**: Each blockchain uses RocksDB database with SST files and LOG snapshots in `data/certificates/` and `data/private_keys/`
- **Thread Safety**: Wrapped in `Arc<BlockChain>` for shared ownership across threads

### OpenSSL Usage

All cryptographic operations use `openssl` crate:
- Key generation: 4096-bit RSA via `openssl::rsa::Rsa::generate()`
- Certificate signing: `X509Builder` with SHA-256 digest
- Extensions: `BasicConstraints`, `KeyUsage` from `openssl::x509::extension`

## Common Pitfalls

1. **Mutex Deadlocks**: The `subject_name_to_height` HashMap is protected by a Mutex in the `Storage` struct. Always release `lock()` before blockchain operations that may take time. Use scoped blocks `{ let lock = storage.subject_name_to_height.lock().unwrap(); ... }` to force drops, or extract values immediately: `let height = storage.subject_name_to_height.lock().unwrap().get(&name).cloned();`.
2. **Block Height vs UUID**: First block is the Root CA at height 0. User-created certificates (Intermediate CAs and User certificates) start at height 1+. All blocks have UUIDs but state HashMap maps subject→height for O(1) lookups.
3. **Certificate Validation**: Intermediate CAs have `pathlen=0` (can't sign other CAs). Root CA has `pathlen=1` (can sign one level of CAs). Set via `BasicConstraints::new().ca().pathlen(n)`.
4. **Rollback Transactions**: On certificate creation failure, rollback via `storage.certificate_chain.delete_latest_block()` to maintain consistency between cert and key chains.
5. **Thread Safety**: `Storage` struct is owned by `Protocol`, which is not wrapped in Arc. The `subject_name_to_height` field is wrapped in `Mutex` for concurrent access if needed.
6. **Protocol Ownership**: `Protocol` struct owns `Storage`, not the other way around. The flow is `UI → Protocol → Storage → Blockchain`. Access storage via `protocol.storage`, not directly.
7. **Private Key Encryption**: Root CA key (height 0) uses PKCS#8 PEM. All other keys use hybrid encryption where AES session key is encrypted with Root CA public key (RSA-OAEP), then private key is encrypted with that AES key (AES-GCM-256).
8. **Keyring Integration**: App key and root key stored in Linux kernel keyring. App key loaded at startup, root key loaded after first decryption. Use `keyutils` crate for keyring operations.

## File Organization

- [src/main.rs](src/main.rs): Entry point, config loading, blockchain initialization, launches TUI (~96 lines)
- [src/ui.rs](src/ui.rs): Cursive-based terminal user interface - main menu, certificate creation forms with validation, blockchain validation view, system status dashboard (~665 lines)
- [src/storage.rs](src/storage.rs): Storage abstraction with dual blockchain management, transactional operations, initialization of 3-tier TLS hierarchy (~504 lines)
- [src/protocol.rs](src/protocol.rs): Protocol abstraction layer - Request/Response enums, `process_request()` implementation, certificate validation logic (~450 lines)
- [src/pki_generator.rs](src/pki_generator.rs): Unified certificate generation with `CertificateData` struct, `CertificateDataType` enum, `generate_root_ca()` and `generate_key_pair()` functions for all certificate types (~217 lines)
- [src/private_key_storage.rs](src/private_key_storage.rs): Encrypted key store with AES-256-GCM encryption, `EncryptedKeyStore` struct, `Zeroize` trait implementation for secure memory handling (~188 lines)
- [src/configs.rs](src/configs.rs): Configuration system with TOML parsing, `AppConfig` struct defining blockchain paths, app key path, and key export directory (~45 lines)
- [src/lib.rs](src/lib.rs): Library interface exposing public modules, comprehensive API documentation with usage examples and architecture diagrams (~322 lines)
- [config.toml](config.toml): Configuration file defining paths for blockchains, app key, and key exports
- Shell scripts: Test utilities and key generation helpers

## Constants and Paths

- **Application Key**: `key/pki-chain-app.key` (constant: `APP_KEY_PATH` in main.rs) - Used for deriving AES-256-GCM key for encrypted key store
- **Certificate Blockchain**: `data/certificates/` (configurable in config.toml, RocksDB database storing DER-encoded certificates)
- **Private Key Blockchain**: `data/private_keys/` (configurable in config.toml, RocksDB database storing SHA-512 hashes + signatures column family)
- **Encrypted Key Store**: `exports/keystore/` (configurable in config.toml, AES-256-GCM encrypted private keys, format: `[nonce(12)][tag(16)][ciphertext]`, constant: `KEYSTORE_DIR` in storage.rs)
- **Initial Hierarchy Common Names**: `ROOT_CA_SUBJECT_COMMON_NAME` = "MenaceLabs Root CA" (in storage.rs)
