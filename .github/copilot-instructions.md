# PKI Chain Copilot Instructions

## Quick Start for AI Agents

**Before coding**: Run `cargo build` to verify the project builds successfully. The codebase compiles with only minor warnings.

**What is this?** Blockchain-backed PKI certificate authority in Rust with:
- Three-tier hierarchy: Root CA → Intermediate CA → User Certificates
- Hybrid storage: Certs in blockchain (DER), private keys encrypted in tar archive (KeyArchive)
- Web frontend: Maud HTML templates in .rs files served via Axum on port 3000
- Authentication: X509 certificate + signature verification (no passwords)
- Critical dep: `libblockchain` (GitHub: jessethepro/libblockchain)

**Key insight**: State-driven CA server (NOEXIST → INITIALIZED → CREATEADMIN → LOGIN → Authenticated). Maud templates render HTML based on server state. Admin functions + API threads launch after first admin created.

## Project Overview

Blockchain-backed PKI (Public Key Infrastructure) certificate authority in Rust. Three-tier hierarchy (Root CA → Intermediate CA → User Certs) with hybrid storage: certificates in blockchain (DER), private keys encrypted on filesystem (Root: PKCS#8 PEM, others: RSA+AES-GCM-256), integrity hashes in blockchain. Features HTTPS web server with Maud HTML templating and REST API.

**Critical Dependencies**: `libblockchain` (GitHub: jessethepro/libblockchain, RocksDB blockchain), `openssl` (4096-bit RSA, X.509), `anyhow` (error context), `axum` (async web framework), `maud` (HTML templates), `tokio` (async runtime), `axum-server` (TLS support), `zeroize` (secure memory)

## ✅ Build Status: Compiling Successfully

**The codebase compiles successfully with only warnings.** Run `cargo build` to verify before making changes.

### Current Warnings (as of 2026-01-22)

**Minor Warnings - Non-blocking**:
- ⚠️ `webserver.rs:299`: Redundant `.clone()` on `&str` from `expose_secret()` - can be removed
- ⚠️ Various unused imports and variables - safe to ignore or clean up with `cargo fix`

### Build Command
```bash
cargo build              # Debug build (fast, unoptimized)
cargo build --release    # Release build (optimized, slower)
cargo fix               # Auto-fix warnings where possible
```

**Before implementing new features**: Run `cargo build` to verify no regressions. The project is in good working order.

## Architecture

### Component Stack (main.rs → WebServer → Storage → Blockchain)

**Architecture**: State-driven web server with Maud HTML templates. CA server state determines rendered pages and available endpoints.

1. **[main.rs](../src/main.rs)** (~96 lines): Entry point. Calls `webserver::start_webserver()` to launch HTTPS server.
   
2. **[webserver.rs](../src/webserver.rs)** (~189 lines): Axum HTTPS server on port 3000.
   - **Maud Templates**: HTML rendered in .rs files based on CA server state
   - **State Management**: Shared state wrapped in `Arc<Mutex<CAServerState>>`
   - **Authentication**: X509 certificate upload + signature verification (no passwords)
   - TLS certs: `web_certs/server/` (generated via `./generate-certs.sh`)
   - Routes:
     - `GET /` - State-driven landing page (NOEXIST/INITIALIZED/CREATEADMIN/LOGIN)
     - `POST /initialize` - Create Root CA (NOEXIST → INITIALIZED)
     - `POST /create-admin` - Create first admin (INITIALIZED → CREATEADMIN)
     - `POST /login` - X509 cert + signature auth (CREATEADMIN → Authenticated)
     - Admin routes (post-login): `/admin/create-user`, `/admin/create-intermediate`, `/admin/status`, `/admin/validate`
     - API threads (post-admin): `/api/request-cert`, `/api/validate-cert`
   
3. **[storage.rs](../src/storage.rs)** (~712 lines): Typestate pattern with state machine transitions.
   - **CA Server States**:
     - `NOEXIST`: Brand new system, no RocksDB databases exist
     - `INITIALIZED`: RocksDB opened, Root CA exists at height 0
     - `CREATEADMIN`: First admin user + intermediate cert created at height 1, 2
     - `LOGIN`: HTML form for X509 cert upload + signature verification
     - `Authenticated`: Admin functions available, API threads launched
   - **Three Blockchains**: 
     - `certificate_chain`: Stores X.509 certificates (encrypted with app.crt public key)
     - `private_key_chain`: Stores private keys (Root CA: PKCS#8 password-protected, others: encrypted with Root CA public key)
     - `crl_chain`: Stores Certificate Revocation Lists (encrypted with app.crt public key)
   - **Modes**:
     - `APIStorage`: Read-only access (`BlockChain<ReadOnly>`) to certificates and CRL (no private keys)
     - `AdminStorage`: Full access (`BlockChain<ReadWrite>`) including private key blockchain
   - **State Transitions**:
     - `Storage<NoExist>` → `Storage<Initialized>` via `initialize(root_ca_password)`
     - `Storage<Initialized>` → `Storage<Ready>` via `create_admin(admin_data, root_ca_password)`
   - Thread-safe lookups: `subject_name_to_height: HashMap<String, u64>` for O(1) cert queries
   - Transactional operations with rollback on failure
   
4. **[pki_generator.rs](../src/pki_generator.rs)** (~217 lines): Unified cert generation.
   - `generate_root_ca(CertificateData)` - self-signed Root CA
   - `generate_key_pair(CertificateData, signing_key)` - all other certs
   - `CertificateDataType` enum: RootCA, IntermediateCA, UserCert, TlsCert
   
5. **[encryption.rs](../src/encryption.rs)** (~211 lines): Generic encryption utilities.
   - `EncryptedData` / `EncryptedFileData` structs
   - Hybrid RSA-OAEP + AES-GCM-256 encryption
   - Used by key_archive.rs for file-level encryption
   
6. **[key_archive.rs](../src/key_archive.rs)** (~139 lines): Tar-based key backup/restore.
   - Methods: `list_keys_in_tar()`, `add_key_to_archive()`, `get_key_from_archive()`
   - Uses encryption.rs utilities for file-level hybrid encryption
   - Stores keys in tar archive at path specified during KeyArchive::new(path)
   
7. **[configs.rs](../src/configs.rs)** (~149 lines): Configuration system with TOML parsing.
   - `AppConfig` struct for app-wide settings
   - Default values for server, blockchains, and Root CA parameters

### Storage Architecture (Hybrid: Blockchain + Filesystem)

**Simplified Encryption Model**: All private keys (except Root CA) are encrypted with `app.key` for consistent, password-free access.

```
Certificate Blockchain (data/certificates/)     Private Key Blockchain (data/private_keys/)
├─ Block 0: Root CA (DER)                       ├─ Block 0: Root CA Private Key (PKCS#8 password-protected)
├─ Block 1: Intermediate CA #1 (DER)           ├─ Block 1: Intermediate CA #1 Private Key (App key encrypted)
└─ Block 2: User Cert #1 (DER)                 └─ Block 2: User Cert #1 Private Key (App key encrypted)
         ▼ Encrypted with app key                       ▼ Encrypted with app key
                                                         
Encryption Keys (in memory at runtime)           Root CA (PKCS#8 password)
└─ App key loaded from key/app.key                ├─ Only needed for signing intermediate CAs
   (decrypts all blockchains + all private keys)  └─ Not needed for user certificate creation
```

**Height 0** = Root CA (genesis, password-protected). **Heights 1+** = Intermediate/User certs (app key encrypted). 

**KeyArchive API**: 
- `add_key_to_archive(height, pkey)` - Encrypts and stores private key in tar
- `get_key_from_archive(height)` - Retrieves and decrypts private key from tar
- `list_keys_in_tar()` - Returns HashMap<u64, String> of archived keys
- Uses encryption.rs `EncryptedFileData` for RSA-OAEP + AES-GCM-256 encryption

## Critical Data Flows

### 1. CA Server State Machine Flow
```rust
// State: NOEXIST (brand new system)
GET / → Maud template: "Initialize CA Server" button
POST /initialize → create_root_ca()
  → Storage::<NoExist>::new() → Storage::<Created>::create()
  → Storage::<Initialized>::initialize()  // Root CA at height 0
  → State transition: NOEXIST → INITIALIZED

// State: INITIALIZED (Root CA exists)
GET / → Maud template: "Create Admin User" form
POST /create-admin { admin_cert_data }
  → Storage::<Initialized>::create_admin(admin_data)
  → Creates admin intermediate CA at height 1
  → Creates admin user cert at height 2
  → State transition: INITIALIZED → CREATEADMIN
  → Launch API threads: /api/request-cert, /api/validate-cert

// State: CREATEADMIN (first admin exists)
GET / → Maud template: "Login" form (X509 cert upload)
POST /login { cert_file, signature }
  → Verify cert exists in blockchain
  → Verify signature with cert's public key
  → State transition: CREATEADMIN → Authenticated

// State: Authenticated (logged in)
GET /admin/* → Maud templates: Admin dashboard
  - /admin/create-user → Create user certificate form
  - /admin/create-intermediate → Create intermediate CA form
  - /admin/status → View blockchain statistics
  - /admin/validate → Validate certificate chain
```

**Root CA Genesis Block**: Subject="MenaceLabs Root CA", pathlen=1, 10-year validity. Private key stored as password-protected PKCS#8 PEM in `exports/keystore/0.key.enc`.

### 2. Certificate Creation Flow
```rust
WebServer → validates DN fields (CN, O, OU, L, ST, C) + country code (2 letters)
  → Storage methods directly invoked from handlers
    → pki_generator::generate_key_pair(cert_data, signing_key)
      → Applies X.509 extensions based on CertificateDataType:
         RootCA: pathlen=1, keyCertSign, cRLSign
         IntermediateCA: pathlen=0, keyCertSign, cRLSign
         UserCert: CA=false, digitalSignature, keyEncipherment
    → Storage stores certificate and key
      → certificate_chain.put_block(cert_der)  // Height N
      → Encrypt and store private key (Root: PKCS#8, others: RSA+AES-GCM)
      → private_key_chain.put_block(sha512_hash + signature)  // Height N
      → On failure: certificate_chain.delete_latest_block()  // Rollback
```

### 3. Authentication Flow (X509 Certificate + Signature)

**No passwords**: Authentication uses X509 certificate upload + cryptographic signature verification.

```rust
// POST /login handler
async fn login(Form(data): Form<LoginData>) -> Maud {
    // 1. Parse uploaded X509 certificate
    let cert = X509::from_pem(&data.cert_bytes)?;
    let subject_cn = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next()?;
    
    // 2. Check certificate exists in blockchain
    let height = storage.subject_name_to_height.get(&subject_cn)?;
    let stored_cert = storage.certificate_chain.get_block_by_height(height)?;
    if stored_cert != cert { return error_page("Certificate not found"); }
    
    // 3. Verify signature with certificate's public key
    let public_key = cert.public_key()?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    if !verifier.verify(&data.challenge, &data.signature)? {
        return error_page("Invalid signature");
    }
    
    // 4. Create authenticated session
    session.insert("user_cert_height", height)?;
    redirect("/admin/dashboard")
}
```

**Storage State Machine**: Storage uses typestate pattern with explicit state transitions:
- `Storage<NoExist>::new()` - Initial state, paths only
- `Storage<Created>::create()` - BlockChains opened, app key loaded
- `Storage<Initialized>::initialize()` - Root CA created at height 0
- `Storage<AdminCreated>::create_admin()` - Admin intermediate CA (height 1) + user cert (height 2)
- `Storage<APIMode>::open()` - Read-only mode for API threads

### 4. API Thread Lifecycle

After the first admin is created (`CREATEADMIN` state), background API threads are launched:

```rust
// After successful create_admin()
tokio::spawn(async move {
    let api_storage = Storage::<APIMode>::open()?;
    
    // Certificate request endpoint
    axum::Router::new()
        .route("/api/request-cert", post(handle_cert_request))
        .route("/api/validate-cert", post(handle_cert_validation))
        .with_state(Arc::new(api_storage))
        .run()
        .await
});
```

**API Endpoints** (separate from admin routes):
- `POST /api/request-cert` - Public endpoint for certificate requests
- `POST /api/validate-cert` - Validate certificate authenticity and revocation status

**APIMode Storage**: Read-only access to certificate blockchain - cannot create new certificates.

## Key Conventions

### Maud HTML Templates

All HTML is rendered using Maud templates in .rs files. Templates are functions that return `Markup` type:

```rust
use maud::{html, Markup, DOCTYPE};

fn render_login_page(state: &CAServerState) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                title { "PKI Chain - Login" }
                link rel="stylesheet" href="/static/style.css";
            }
            body {
                h1 { "Certificate Authority Login" }
                @if state == CAServerState::CreateAdmin {
                    form method="POST" action="/login" enctype="multipart/form-data" {
                        label { "Upload X.509 Certificate:" }
                        input type="file" name="cert" accept=".pem,.crt" required;
                        label { "Signature (base64):" }
                        input type="text" name="signature" required;
                        button type="submit" { "Login" }
                    }
                } @else {
                    p { "Admin user not yet created. Please create admin first." }
                }
            }
        }
    }
}

// Axum handler
async fn login_page(State(state): State<Arc<Mutex<CAServerState>>>) -> Markup {
    let state = state.lock().await;
    render_login_page(&state)
}
```

**Pattern**: Each page has a render function that takes state and returns Markup. State determines which UI elements are shown.

### Unified Certificate Generation

All certificate types (Root CA, Intermediate CA, User, TLS) are generated through a unified code path in [pki_generator.rs](../src/pki_generator.rs). The `CertificateData` struct contains all necessary fields including `cert_type: CertificateDataType` enum:

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

### Build and Development

```bash
# Build (requires libblockchain from GitHub)
cargo build --release

# Generate TLS certificates for HTTPS server (first run)
./generate-webserver-certs.sh

# Run application (starts HTTPS web server on port 3000)
./target/debug/pki-chain   # or ./target/release/pki-chain
```

The project compiles successfully with only minor warnings. See **Build Status** section at the top for current warnings.

**First run prerequisites**: 
1. Execute `./generate_app_keypair.sh` to create `pki-chain-app.key` (then move to `key/app.key`) before running the application
2. Execute `./generate-certs.sh` to create TLS certificates in `web_certs/` for HTTPS webserver
3. **Optional**: Use `./install_app_key_to_tpm.sh` (root required) to seal app key in TPM 2.0 for hardware-bound security

**Web Interface Access**:
- URL: `https://localhost:3000`
- Serves static files from `web_root/` directory
- Browser will warn about self-signed certificate (expected for local development)
- **Login Flow**: Web UI prompts for app key password → `/api/login` → returns success/failure
- **Dashboard**: After login, shows PKI status with refresh capability

**REST API Endpoints**:
- `GET /api/status` - Returns PKI system status (certificates, keys, validation state)
  - Response: `PKIStatusResponse` with blockchain metrics, validation flags
- `POST /api/initialize` - Initialize storage with app key password (first-time setup, **destructive**)
  - Request: `InitializeRequest { app_key_password: String }`
  - Response: `InitializeResponse { success: bool, message: String }`
  - **⚠️ Deletes all existing data** and reinitializes Root CA
- `POST /api/login` - Authenticate with app key password (creates Storage instance)
  - Request: `LoginRequest { app_key_password: String }`
  - Response: `LoginResponse { success: bool, message: String }`
  - **Critical**: This creates the `Storage` instance in `Protocol` - required before other operations

### Testing PKI Operations

Use `test_keypair_generation.sh` for end-to-end testing:

```bash
./test_keypair_generation.sh
# Prompts for application PFX path, generates Root → Intermediate → 5 User certs
# Creates temporary test directory, performs full PKI hierarchy validation
```

### Shell Script Utilities

Six key scripts in project root:

1. **`generate_app_keypair.sh`**: Creates `pki-chain-app.key` (master key for blockchain encryption) which should be moved to `key/app.key`. **Critical**: This key must exist before running the application. Lost keys = unrecoverable blockchain data.

2. **`generate-certs.sh`**: Generates three-tier TLS certificate chain for HTTPS webserver (Root CA → Intermediate CA → Server cert). Creates certificates in `web_certs/` directory with proper permissions. Required before first webserver run.

3. **`test_keypair_generation.sh`**: End-to-end PKI testing - generates complete hierarchy (Root → Intermediate → 5 User certificates), validates chain integrity, tests exports.

4. **`change_pfx_password.sh`**: Changes password on PFX files using application PFX for authentication. Usage: `./change_pfx_password.sh <app_pfx> <target_pfx>`

5. **`install_app_key_to_tpm.sh`**: **(NEW)** Seals app key into TPM 2.0 chip (requires root, Arch Linux with tpm2-tools). Binds encryption key to hardware, making it inaccessible to root user. Creates backup at `key/app.key.backup`. Requires TPM 2.0 device at `/dev/tpm0`. Uses persistent handle `0x81000001`.

6. **`retrieve_app_key_from_tpm.sh`**: **(NEW)** Retrieves sealed app key from TPM 2.0 (requires root). Demonstrates unsealing process for testing. Key can only be retrieved on same hardware where it was sealed.

## Integration Points

### libblockchain Dependency (v0.1.0)

- **Source**: GitHub repository `jessethepro/libblockchain` (specified in Cargo.toml as git dependency)
- **Type-State Pattern**: `BlockChain<ReadWrite>` for admin, `BlockChain<ReadOnly>` for API threads
- **Opening Chains**: 
  - `open_read_write_chain(path)` - Create/open with write access
  - `open_read_only_chain(path)` - Open existing in read-only mode
- **Key APIs**: `put_block(data)`, `get_block_by_height(height)`, `get_signature_by_height(height)`, `validate()`, `block_count()`, `delete_last_block()`, `iter()`
- **Block Accessors**: `block.height()`, `block.block_hash()`, `block.parent_hash()`, `block.block_data()`, `block.bytes()`
- **Storage**: RocksDB with column families: `blocks`, `signatures`, `validation_cache`
- **Thread Safety**: ⚠️ NOT thread-safe (uses `SingleThreaded` mode). Each thread needs separate connection.
- **Max Block Size**: 100MB enforced automatically
- **Hashing**: SHA-512 (64-byte hashes)

### OpenSSL Usage

All cryptographic operations use `openssl` crate:
- Key generation: 4096-bit RSA via `openssl::rsa::Rsa::generate()`
- Certificate signing: `X509Builder` with SHA-256 digest
- Extensions: `BasicConstraints`, `KeyUsage` from `openssl::x509::extension`

## Common Pitfalls

1. **Mutex Deadlocks**: The `subject_name_to_height` HashMap is protected by a Mutex in `Storage`. Always release `lock()` before blockchain I/O. Use scoped blocks `{ let lock = ...; ... }` to force drops, or extract values: `let h = map.lock().unwrap().get(&k).cloned();`.

2. **Block Height vs UUID**: Root CA is always at height 0 (genesis). User-created certs (Intermediate/User) start at height 1+. All blocks have UUIDs but the HashMap maps subject→height for O(1) lookups.

3. **Certificate Path Length**: Root CA has `pathlen=1` (can sign 1 level of CAs). Intermediate CAs have `pathlen=0` (can't sign other CAs). Set via `BasicConstraints::new().ca().pathlen(n)`.

4. **Transactional Rollback**: On cert creation failure, rollback via `certificate_chain.delete_latest_block()` to maintain sync between cert and key blockchains. Heights must match: cert@N ↔ key@N.

5. **Direct Storage Access**: WebServer handlers access Storage directly. Storage created during initialization via `Storage::new()` and passed through application state.

6. **Private Key Encryption**: 
   - **Root CA (height 0)**: PKCS#8 PEM with password protection, stored in private key blockchain
   - **All other keys (heights 1+)**: Hybrid RSA+AES-GCM-256 encrypted with `app.key`:
     - Generate random AES-256 session key
     - Encrypt session key with app public key (RSA-OAEP)
     - Encrypt private key DER with AES-GCM-256 using session key
     - Format: `[AES Len(u32)][Encrypted AES Key][Nonce(12)][Tag(16)][Data Len(u32)][Encrypted Data]`
   - **Benefit**: Intermediate CA keys can be decrypted without Root CA password, enabling user certificate creation without password prompts

7. **In-Memory Keys**: App key loaded from `key/app.key` into memory during `Storage::new()`. Used to decrypt certificate/CRL blockchains and all non-Root CA private keys. Root CA password only needed when creating intermediate CAs.

8. **State Management**: In webserver.rs, `CAServerState` is wrapped in `Arc<Mutex<CAServerState>>` for shared mutable state across handlers. Each handler locks state as needed for brief operations.

9. **libblockchain Type-State Pattern**: Use correct generic types:
   - Admin operations: `BlockChain<ReadWrite>` (can read + write)
   - API operations: `BlockChain<ReadOnly>` (read-only access)
   - Helper functions: `open_read_write_chain(path)`, `open_read_only_chain(path)`

10. **Block Accessors**: libblockchain v0.1.0 methods:
   - `block.height()` - Get block height (u64)
   - `block.block_data()` - Get data payload (Vec<u8>)
   - `block.block_hash()` - Get 64-byte SHA-512 hash
   - `block.parent_hash()` - Get parent block's hash

11. **Iterator Type Annotations**: libblockchain iterators need explicit types:
   ```rust
   for block_result in chain.iter()? {
       let block: Block = block_result?; // Explicit type needed
       // Use block
   }
   ```

12. **Thread Safety**: ⚠️ libblockchain is NOT thread-safe. Each thread must open its own connection:
   ```rust
   // ❌ BAD: Share across threads
   let chain = open_read_write_chain(path)?;
   thread::spawn(move || chain.put_block(data)); // ERROR
   
   // ✅ GOOD: Separate connection per thread
   thread::spawn(move || {
       let chain = open_read_write_chain(path.clone())?;
       chain.put_block(data)
   });
   ```

13. **HashMap Not Mutex**: Storage's `subject_name_to_height` field is `HashMap<String, u64>` (not wrapped in Mutex). Access directly without `.lock()` calls.

## File Organization

- [src/main.rs](../src/main.rs): Entry point, launches webserver (~96 lines)
- [src/webserver.rs](../src/webserver.rs): Axum HTTPS server, route handlers, authentication logic, TLS configuration (~534 lines)
- [src/templates.rs](../src/templates.rs): Maud HTML template functions for all web pages - layout, forms, admin dashboard (~378 lines)
- [src/storage.rs](../src/storage.rs): Typestate pattern storage with three blockchains, state transitions NoExist→Initialized→Ready (~712 lines)
- [src/pki_generator.rs](../src/pki_generator.rs): Unified certificate generation with `CertificateData` struct, `CertificateDataType` enum (~217 lines)
- [src/encryption.rs](../src/encryption.rs): Generic encryption utilities - `EncryptedData` and `EncryptedFileData` structs for hybrid RSA-OAEP + AES-256-GCM encryption (~211 lines)
- [src/key_archive.rs](../src/key_archive.rs): Tar-based key backup/restore system with file-level encryption (~139 lines)
- [src/configs.rs](../src/configs.rs): Configuration system with TOML parsing, `AppConfig` struct (~149 lines)
- [src/lib.rs](../src/lib.rs): Library interface exposing public modules (~6 lines)
- [config.toml](../config.toml): Configuration file defining paths for blockchains, server, and Root CA defaults
- [web_root/](../web_root/): Static files served by the web server (if needed)
- Shell scripts: `generate_app_keypair.sh`, `generate-webserver-certs.sh` for setup

## Constants and Paths

- **Application Key**: `key/app.key` (configurable in config.toml as `app_key_path`) - Used for encrypting blockchain databases. Loaded into memory as PKey object during `Storage::new()`. Generated by `generate_app_keypair.sh` script as `pki-chain-app.key`.
- **Certificate Blockchain**: `data/certificates/` (configurable in config.toml, RocksDB database storing DER-encoded certificates)
- **Private Key Blockchain**: `data/private_keys/` (configurable in config.toml, RocksDB database storing SHA-512 hashes + signatures column family)
- **Encrypted Key Store**: `exports/keystore/` (configurable in config.toml, AES-256-GCM encrypted private keys, format: Root CA as PKCS#8 PEM, others as `[AES Key Len][Encrypted AES Key][Nonce(12)][Tag(16)][Data Len][Encrypted Data]`, constant: `key_export_directory_path` in configs.rs)
- **Initial Hierarchy Common Names**: `ROOT_CA_SUBJECT_COMMON_NAME` = "MenaceLabs Root CA" (in storage.rs)
## Future Enhancements

### YubiKey/HSM Authentication Integration

**Planned**: Replace certificate file upload authentication with WebAuthn/FIDO2 hardware security key support.

**Benefits**:
- Hardware-bound authentication (private keys never leave YubiKey)
- Phishing-resistant (challenge-response with device attestation)
- No certificate file management (keys generated and stored on device)
- Standards-based (WebAuthn API supported by modern browsers)

**Implementation Approach**:
1. **Registration**: Generate key pair on YubiKey during admin creation, store public key in blockchain
2. **Authentication**: Challenge-response using `navigator.credentials.get()` (WebAuthn API)
3. **Verification**: Server validates signature against stored public key
4. **Fallback**: Keep current certificate upload for compatibility

**Limitations**:
- WebAuthn cannot sign X.509 certificates (limited to authentication challenges)
- Certificate creation still requires traditional key pairs
- YubiKey used for admin login security, not certificate signing operations

**Reference**: See `navigator.credentials.create()` and `navigator.credentials.get()` WebAuthn APIs for implementation details.