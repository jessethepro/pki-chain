# PKI Chain Copilot Instructions

## Project Overview

This is a blockchain-backed PKI (Public Key Infrastructure) certificate authority system written in Rust. It manages a complete certificate chain (Root CA → Intermediate CA → User Certificates) with all certificates and private keys stored in tamper-proof blockchain storage via the `libblockchain` dependency.

**Key Dependencies**: `openssl` (4096-bit RSA, X.509 operations), `anyhow` (error chaining with `.context()`), `serde`/`serde_json` (socket protocol), `libblockchain` (GitHub: `jessethepro/libblockchain`)

## Architecture

### Core Components

- **Terminal User Interface**: Cursive-based TUI (src/ui.rs) provides interactive certificate management with form-based input, validation, and real-time status displays. Primary interface for certificate operations.
- **Dual Blockchain Storage**: Two separate `libblockchain::blockchain::BlockChain` instances stored in `data/certificates/` and `data/private_keys/`. These are encrypted RocksDB databases with blockchain validation.
- **Application Key**: `key/pki-chain-app.key` is the master key used to encrypt/decrypt both blockchain databases. Generated via `./generate_app_keypair.sh`.
- **Unix Socket Server**: External IPC interface at `/tmp/pki_socket` for clients to request certificate operations without direct blockchain access. **Currently disabled** - socket server code is commented out in main.rs. TUI is the primary interface.
- **Three-Tier Certificate Hierarchy**:
  - Root CA (self-signed, genesis block at height 0)
  - Intermediate CAs (signed by Root, pathlen=0)
  - User Certificates (signed by Intermediate, CA=false)

### Critical Data Flow

1. **Initialization** ([main.rs](src/main.rs), [storage.rs](src/storage.rs)): On first run, generates a complete 3-tier TLS hierarchy and stores as the first three blocks:
   - Height 0: Root CA (self-signed, pathlen=1, 5-year validity)
   - Height 1: Intermediate TLS CA (signed by Root, pathlen=0, 3-year validity, CN="webclient_intermediate_tls_ca")
   - Height 2: WebClient TLS Certificate (signed by Intermediate, CA=false, 1-year validity, CN="webclient_cert.local")
   
   Validates stored certificates match generated ones. Exports Root CA private key to `exports/root_ca.key`. Subsequent runs skip generation if block_count() > 0. **User certificates created via TUI or socket API start at height 3+**.

2. **TUI Certificate Creation** ([ui.rs](src/ui.rs)): Users create Intermediate CAs through interactive forms with real-time validation. Form validates all DN fields (CN, O, OU, L, ST, C), country code format (exactly 2 letters), and validity period (positive integer). Uses `RsaIntermediateCABuilder` to generate certificates. Calls `Storage::store_key_certificate()` which atomically stores both certificate and private key with rollback on failure.

3. **Certificate Storage** ([storage.rs](src/storage.rs)): New certificates stored via `put_block()`. Blockchain automatically assigns UUIDs. On failure during private key storage, certificate is rolled back via `delete_latest_block()`. All operations are transactional.

4. **State Management** ([storage.rs](src/storage.rs)): In-memory `subject_name_to_height` Mutex-wrapped HashMap inside `Storage` struct maps common names to block heights for fast certificate retrieval. Populated on startup by iterating entire certificate blockchain (called from main.rs via `populate_subject_name_index()`). Validates against duplicate subject common names before creation. Thread-safe access via `.lock().unwrap()`.

5. **Socket Protocol** ([protocol.rs](src/protocol.rs), [external_interface.rs](src/external_interface.rs)): **Currently disabled**. Length-prefixed JSON messages (4-byte LE length + JSON payload). Protocol module provides serialization/deserialization utilities (`serialize_request`, `deserialize_request`, `serialize_response`, `deserialize_response`). Server would spawn in background thread via `std::thread::spawn()`, listen on Unix socket, handle connections serially.

## Key Conventions

### Builder Pattern Usage

All certificate generation uses builder pattern with **mandatory field validation**. All 6 Distinguished Name (DN) fields are required: CN, O, OU, Locality, State, Country. Example from [generate_root_ca.rs](src/generate_root_ca.rs):

```rust
RsaRootCABuilder::new()
    .subject_common_name("PKI Chain Root CA".to_string())
    .organization("MenaceLabs".to_string())
    .organizational_unit("CY".to_string())
    .country("BR".to_string())
    .state("SP".to_string())
    .locality("Sao Jose dos Campos".to_string())
    .validity_days(365 * 5)
    .build()  // Returns Result<(PKey<Private>, X509)>
```

**Note**: Intermediate and User builders require signing key/cert via constructor: `RsaIntermediateCABuilder::new(root_key, root_cert)`. Missing any DN field causes a runtime error in `build()`.

### Certificate Storage Format

- **Certificates**: Stored as PEM in certificate blockchain (`to_pem()`)
- **Private Keys**: Stored as DER in private key blockchain (`private_key_to_der()`)
- **Retrieval**: Use `get_block_by_height(n)` or `get_block_by_uuid(&uuid)` from libblockchain

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
2. **Validate Blockchain** - Runs `validate()` on both certificate and private key chains, displays block counts and validation status
3. **View System Status** - Shows blockchain statistics, block heights, and tracked subject names
4. **Exit** - Terminates application gracefully

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

## External Interface (Socket API)

Clients communicate via Unix socket at `/tmp/pki_socket` with JSON requests:

### Request Format

All requests are length-prefixed: 4-byte little-endian length + JSON payload. The socket server validates against duplicate common names using the in-memory state HashMap. Serialization helpers available in [protocol.rs](src/protocol.rs): `serialize_request(&request)` returns `(u32, Vec<u8>)` tuple. Deserialization via `deserialize_request(&bytes)`. Read example in `handle_client()`: `read_exact(&mut len_buf)` then `read_exact(&mut buf)`.

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

**Supported request types**: 
- `CreateIntermediate`: Create new Intermediate CA (signed by Root at height 0)
- `CreateUser`: Create user certificate (requires `issuer_common_name` field to specify signing Intermediate CA)
- `ListCertificates`: List certificates (filter: All/Intermediate/User/Root)
- `PKIStatus`: Get system status (block counts, validation state, tracked subject names)
- `SocketTest`: Connectivity test
- `GetWebClientTLSCertificate`: Retrieve pre-generated TLS cert at height 2 with full chain (Intermediate at height 1, Root at height 0). Returns certificate PEM, private key PEM, and chain array for HTTPS server configuration.

### Response Format

All responses are length-prefixed and use tagged enums. Serialization via `serialize_response(&response)`, deserialization via `deserialize_response(&bytes)`. Example response structure:

```json
{
  "type": "CreateIntermediateResponse",
  "message": "Intermediate CA created successfully",
  "common_name": "Operations CA",
  "organization": "ACME Corp",
  "organizational_unit": "IT",
  "country": "US",
  "height": 3
}
```

**Note**: Response types are strongly typed enums (not generic status/data objects). Each request type has a corresponding response variant: `CreateIntermediateResponse`, `CreateUserResponse`, `ListCertificatesResponse`, `PKIStatusResponse`, `SocketTestResponse`, `GetWebClientTLSCertificateResponse`, and `Error`. See [protocol.rs](src/protocol.rs) for complete enum definitions.

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
2. **Block Height vs UUID**: First three blocks are reserved for WebClient TLS chain (Root=0, Intermediate TLS=1, WebClient=2). User-created certificates start at height 3+. All blocks have UUIDs but state HashMap maps subject→height for O(1) lookups.
3. **Certificate Validation**: Intermediate CAs have `pathlen=0` (can't sign other CAs). Root CA has `pathlen=1` (can sign one level of CAs). Set via `BasicConstraints::new().ca().pathlen(n)`. WebClient TLS cert at height 2 has CA=false with `serverAuth` extended key usage.
4. **Socket Message Protocol**: Must send 4-byte little-endian length prefix before JSON payload (`u32::from_le_bytes(len_buf)`). Missing length = connection hangs or deserialization failure.
5. **State Initialization**: Socket server populates `storage.subject_name_to_height` on startup by iterating entire certificate blockchain (see `start_socket_server()`). O(n) operation - consider optimization for large chains.
6. **Rollback Transactions**: On certificate creation failure, rollback via `storage.certificate_chain.delete_latest_block()` to maintain consistency between cert and key chains.
7. **Thread Safety**: `Storage` struct uses `Arc<Storage>` for sharing across threads. The `subject_name_to_height` field is wrapped in `Mutex` for concurrent access from multiple socket connections.

## File Organization

- [src/main.rs](src/main.rs): Entry point, blockchain initialization, launches TUI (~97 lines)
- [src/ui.rs](src/ui.rs): Cursive-based terminal user interface - main menu, certificate creation forms with validation, blockchain validation view, system status dashboard (~331 lines)
- [src/storage.rs](src/storage.rs): Storage abstraction with dual blockchain management, transactional operations, initialization of 3-tier TLS hierarchy (~557 lines)
- [src/external_interface.rs](src/external_interface.rs): Socket server, request handlers, WebClient TLS certificate retrieval (currently disabled) (~820 lines)
- [src/protocol.rs](src/protocol.rs): IPC protocol definitions - Request/Response enums, serialization/deserialization functions for length-prefixed JSON messages (~242 lines)
- [src/generate_root_ca.rs](src/generate_root_ca.rs): Root CA builder (self-signed, pathlen=1)
- [src/generate_intermediate_ca.rs](src/generate_intermediate_ca.rs): Intermediate CA builder (pathlen=0)
- [src/generate_user_keypair.rs](src/generate_user_keypair.rs): User cert builder (CA=false)
- [src/generate_webclient_tls.rs](src/generate_webclient_tls.rs): TLS server certificate builder with `serverAuth` extension, SubjectAltName (localhost, 127.0.0.1, ::1). Exports constants `WEBCLIENT_COMMON_NAME` and `WEBCLIENT_INTERMEDIATE_COMMON_NAME` (~398 lines)
- [src/lib.rs](src/lib.rs): Library interface exposing public modules
- Shell scripts: Test utilities and key generation helpers

## Constants and Paths

- **Application Key**: `key/pki-chain-app.key` (constant: `APP_KEY_PATH`)
- **Unix Socket**: `/tmp/pki_socket` (constant: `SOCKET_PATH`)
- **Certificate Storage**: `data/certificates/` (RocksDB database + snapshots)
- **Private Key Storage**: `data/private_keys/` (RocksDB database + snapshots)
- **Export Directory**: `exports/` (Root CA key exports)
