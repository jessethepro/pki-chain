# PKI Chain Copilot Instructions

## Project Overview

Blockchain-backed PKI (Public Key Infrastructure) certificate authority in Rust. Three-tier hierarchy (Root CA → Intermediate CA → User Certs) with hybrid storage: certificates in blockchain (DER), private keys encrypted on filesystem (Root: PKCS#8 PEM, others: RSA+AES-GCM-256), integrity hashes in blockchain. Features HTTPS web server with REST API for certificate management.

**Critical Dependencies**: `libblockchain` (GitHub: jessethepro/libblockchain, RocksDB blockchain), `openssl` (4096-bit RSA, X.509), `anyhow` (error context), `axum` (async web framework), `tokio` (async runtime), `axum-server` (TLS support), `keyutils` (Linux keyring), `zeroize` (secure memory)

## Architecture

### Component Stack (main.rs → WebServer → Protocol → Storage → Blockchain)

1. **[main.rs](src/main.rs)** (~117 lines): Entry point. Loads `config.toml`, creates single `Storage` instance (prompts for app key password), initializes Root CA if empty, populates subject index, starts HTTPS webserver via `webserver::start_webserver()`
2. **[webserver.rs](src/webserver.rs)** (~118 lines): Axum-based HTTPS web server. Serves static files from `web_root/`, exposes REST API at `/api/status`. Wraps `Protocol` in `Arc` for async handler sharing. Uses TLS with certificates from `web_certs/server/` (generated via `generate-certs.sh`). Runs on port 3000 with Tokio runtime.
3. **[protocol.rs](src/protocol.rs)** (~591 lines): Owns `Storage`, exposes `process_request(&self, Request) -> Result<Response>`. Request/Response pattern for Create/List/Validate/Status operations. Thread-safe via `&self`, wrapped in `Arc` for webserver handlers.
4. **[storage.rs](src/storage.rs)** (~569 lines): Core storage abstraction. Manages dual blockchain + encrypted filesystem + Linux keyring. Mutex-wrapped `subject_name_to_height` HashMap for O(1) lookups.
5. **[pki_generator.rs](src/pki_generator.rs)** (~217 lines): `generate_root_ca()` and `generate_key_pair(cert_data, signing_key)`. Single code path for all cert types via `CertificateDataType` enum (RootCA/IntermediateCA/UserCert/TlsCert).
6. **[private_key_storage.rs](src/private_key_storage.rs)** (~270 lines): `EncryptedKeyStore` struct. Root CA: PKCS#8 PEM. Others: AES session key → RSA-OAEP encrypted → AES-GCM-256 encrypts DER.

### Storage Architecture (Hybrid: Blockchain + Filesystem + Keyring)

```
Certificate Blockchain (data/certificates/)     Private Key Blockchain (data/private_keys/)
├─ Block 0: Root CA (DER)                       ├─ Block 0: SHA-512 hash + signature
├─ Block 1: Intermediate CA #1 (DER)           ├─ Block 1: SHA-512 hash + signature
└─ Block 2: User Cert #1 (DER)                 └─ Block 2: SHA-512 hash + signature
         ▼ Encrypted with app key                       ▼ Encrypted with app key
                                                         
Encrypted Key Store (exports/keystore/)         Linux Kernel Keyring (in-memory)
├─ 0.key.enc: Root CA (PKCS#8 PEM, password)    ├─ app.key: Loaded from key/app.key
├─ 1.key.enc: Hybrid RSA+AES-GCM-256           └─ 0.key.enc: Root CA (after decrypt)
└─ 2.key.enc: Hybrid RSA+AES-GCM-256
```

**Height 0** = Root CA (genesis). **Heights 1+** = User-created certs (Intermediate/User). Block heights are synchronized across both blockchains (cert at height N corresponds to key at height N).

## Critical Data Flows

### 1. First-Time Initialization
```rust
main.rs:
  AppConfig::load() from config.toml
  → Storage::new(config)  // Prompts for app key password, loads into keyring
    → if storage.is_empty()? { storage.initialize()? }  // Creates Root CA at height 0
    → storage.populate_subject_name_index()?  // Builds HashMap from blockchain
  → webserver::start_webserver(config, storage)  // Starts HTTPS server on port 3000
```

**Root CA Genesis Block**: Subject="MenaceLabs Root CA", pathlen=1, 10-year validity. Private key stored as password-protected PKCS#8 PEM in `exports/keystore/0.key.enc`.

### 2. Certificate Creation Flow
```rust
WebServer → validates DN fields (CN, O, OU, L, ST, C) + country code (2 letters)
  → Request::CreateIntermediate { certificate_data } OR Request::CreateUser { ... }
  → Protocol::process_request()
    → storage.get_key_certificate_by_height(issuer_height)  // Retrieve signing key/cert
    → pki_generator::generate_key_pair(cert_data, signing_key)
      → Applies X.509 extensions based on CertificateDataType:
         RootCA: pathlen=1, keyCertSign, cRLSign
         IntermediateCA: pathlen=0, keyCertSign, cRLSign
         UserCert: CA=false, digitalSignature, keyEncipherment
    → storage.store_certificate_and_key(cert_der, pkey, height)
      → certificate_chain.put_block(cert_der)  // Height N
      → encrypted_key_store.store_key(height, root_pub_key, pkey)
        → If Root (height 0): PKCS#8 PEM
        → Else: Generate random AES-256 key, encrypt DER with AES-GCM, encrypt AES key with Root CA public key (RSA-OAEP)
      → private_key_chain.put_block(sha512_hash + signature)  // Height N
      → On failure: certificate_chain.delete_latest_block()  // Rollback
```

### 3. Mutex Deadlock Prevention
The `subject_name_to_height: Mutex<HashMap<String, u64>>` is in `Storage`. **Pattern**:
```rust
// BAD: Holds lock during blockchain I/O
let lock = storage.subject_name_to_height.lock().unwrap();
if lock.contains_key(&name) {
    storage.certificate_chain.get_block_by_height(...)?;  // DEADLOCK RISK
}

// GOOD: Extract value, release lock ASAP
let height = storage.subject_name_to_height.lock().unwrap().get(&name).cloned();
if let Some(h) = height {
    storage.certificate_chain.get_block_by_height(h)?;  // Safe
}

// GOOD: Scoped lock
{
    let lock = storage.subject_name_to_height.lock().unwrap();
    if lock.contains_key(&name) { return Err(...); }
}  // Lock dropped here
storage.certificate_chain.put_block(...)?;
```

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
  - SHA-512 hash stored in private key blockchain main column family
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

# Generate TLS certificates for HTTPS server (first run)
./generate-certs.sh

# Run application (starts HTTPS web server on port 3000)
# Note: Release binary is at target/release/pki-chain
./target/debug/pki-chain   # or ./target/release/pki-chain
```

**First run prerequisites**: 
1. Execute `./generate_app_keypair.sh` to create `key/pki-chain-app.key` before running the application
2. Execute `./generate-certs.sh` to create TLS certificates in `web_certs/` for HTTPS webserver

**Web Interface Access**:
- URL: `https://localhost:3000`
- Serves static files from `web_root/` directory
- REST API endpoint: `GET /api/status` - Returns PKI system status as JSON
- Browser will warn about self-signed certificate (expected for local development)

### Testing PKI Operations

Use `test_keypair_generation.sh` for end-to-end testing:

```bash
./test_keypair_generation.sh
# Prompts for application PFX path, generates Root → Intermediate → 5 User certs
# Creates temporary test directory, performs full PKI hierarchy validation
```

### Shell Script Utilities

Four key scripts in project root:

1. **`generate_app_keypair.sh`**: Creates `key/pki-chain-app.key` (master key for blockchain encryption). **Critical**: This key must exist before running the application. Lost keys = unrecoverable blockchain data.

2. **`generate-certs.sh`**: Generates three-tier TLS certificate chain for HTTPS webserver (Root CA → Intermediate CA → Server cert). Creates certificates in `web_certs/` directory with proper permissions. Required before first webserver run.

3. **`test_keypair_generation.sh`**: End-to-end PKI testing - generates complete hierarchy (Root → Intermediate → 5 User certificates), validates chain integrity, tests exports.

4. **`change_pfx_password.sh`**: Changes password on PFX files using application PFX for authentication. Usage: `./change_pfx_password.sh <app_pfx> <target_pfx>`

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
6. **Protocol Ownership**: `Protocol` struct owns `Storage`, not the other way around. The flow is `WebServer → Protocol → Storage → Blockchain`. Access storage via `protocol.storage`, not directly.
7. **Private Key Encryption**: Root CA key (height 0) uses PKCS#8 PEM. All other keys use hybrid encryption where AES session key is encrypted with Root CA public key (RSA-OAEP), then private key is encrypted with that AES key (AES-GCM-256).
8. **Keyring Integration**: App key and root key stored in Linux kernel keyring. App key loaded at startup, root key loaded after first decryption. Use `keyutils` crate for keyring operations.
9. **Arc Wrapping**: In webserver.rs, Protocol is wrapped in `Arc<Protocol>` for sharing across async handlers. The underlying Storage remains non-Arc, but &self methods are thread-safe due to interior Mutex on the subject name index.

## File Organization

- [src/main.rs](src/main.rs): Entry point, config loading, blockchain initialization, launches webserver (~117 lines)
- [src/webserver.rs](src/webserver.rs): Axum HTTPS server, static file serving, REST API endpoints, TLS configuration (~118 lines)
- [src/storage.rs](src/storage.rs): Storage abstraction with dual blockchain management, transactional operations, initialization of 3-tier TLS hierarchy (~569 lines)
- [src/protocol.rs](src/protocol.rs): Protocol abstraction layer - Request/Response enums, `process_request()` implementation, certificate validation logic (~591 lines)
- [src/pki_generator.rs](src/pki_generator.rs): Unified certificate generation with `CertificateData` struct, `CertificateDataType` enum, `generate_root_ca()` and `generate_key_pair()` functions for all certificate types (~217 lines)
- [src/private_key_storage.rs](src/private_key_storage.rs): Encrypted key store with AES-256-GCM encryption, `EncryptedKeyStore` struct, `Zeroize` trait implementation for secure memory handling (~270 lines)
- [src/configs.rs](src/configs.rs): Configuration system with TOML parsing, `AppConfig` struct defining blockchain paths, app key path, and key export directory (~45 lines)
- [src/lib.rs](src/lib.rs): Library interface exposing public modules, comprehensive API documentation with usage examples and architecture diagrams (~322 lines)
- [config.toml](config.toml): Configuration file defining paths for blockchains, app key, and key exports
- [web_root/](web_root/): Static files for web interface (HTML, CSS, JS)
- Shell scripts: Test utilities and key generation helpers

## Constants and Paths

- **Application Key**: `key/pki-chain-app.key` (constant: `APP_KEY_PATH` in main.rs) - Used for deriving AES-256-GCM key for encrypted key store
- **Certificate Blockchain**: `data/certificates/` (configurable in config.toml, RocksDB database storing DER-encoded certificates)
- **Private Key Blockchain**: `data/private_keys/` (configurable in config.toml, RocksDB database storing SHA-512 hashes + signatures column family)
- **Encrypted Key Store**: `exports/keystore/` (configurable in config.toml, AES-256-GCM encrypted private keys, format: `[nonce(12)][tag(16)][ciphertext]`, constant: `KEYSTORE_DIR` in storage.rs)
- **Initial Hierarchy Common Names**: `ROOT_CA_SUBJECT_COMMON_NAME` = "MenaceLabs Root CA" (in storage.rs)
