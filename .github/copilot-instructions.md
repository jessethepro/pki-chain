# PKI Chain Copilot Instructions

## Project Overview

This is a blockchain-backed PKI (Public Key Infrastructure) certificate authority system written in Rust. It manages a complete certificate chain (Root CA → Intermediate CA → User Certificates) with all certificates and private keys stored in tamper-proof blockchain storage via the `libblockchain` dependency.

**Key Dependencies**: `openssl` (4096-bit RSA, X.509 operations), `anyhow` (error chaining with `.context()`), `serde`/`serde_json` (socket protocol), `libblockchain` (GitHub: `jessethepro/libblockchain`)

## Architecture

### Core Components

- **Dual Blockchain Storage**: Two separate `libblockchain::blockchain::BlockChain` instances stored in `data/certificates/` and `data/private_keys/`. These are encrypted sled databases with blockchain validation.
- **Application Key**: `key/pki-chain-app.key` is the master key used to encrypt/decrypt both blockchain databases. Generated via `./generate_app_keypair.sh`.
- **Unix Socket Server**: External IPC interface at `/tmp/pki_socket` for clients to request certificate operations without direct blockchain access.
- **Three-Tier Certificate Hierarchy**:
  - Root CA (self-signed, genesis block at height 0)
  - Intermediate CAs (signed by Root, pathlen=0)
  - User Certificates (signed by Intermediate, CA=false)

### Critical Data Flow

1. **Initialization** ([main.rs](src/main.rs)): On first run, generates Root CA and stores as genesis blocks (height 0) in both blockchains. Validates stored certificates match generated ones. Exports Root CA private key to `exports/root_ca.key`. Subsequent runs skip generation if block_count() > 0.
2. **Certificate Creation** ([external_interface.rs](src/external_interface.rs)): New certificates stored via `put_block()`. Blockchain automatically assigns UUIDs. On failure during private key storage, certificate is rolled back via `delete_latest_block()`.
3. **State Management** ([chain_state.rs](src/chain_state.rs)): In-memory `subject_name_to_height` HashMap maps common names to block heights for fast certificate retrieval. Initialized at socket server startup by iterating entire certificate blockchain. Validates against duplicate subject common names before creation.
4. **Socket Protocol** ([external_interface.rs](src/external_interface.rs)): Length-prefixed JSON messages (4-byte LE length + JSON payload). Server spawns in background thread via `std::thread::spawn()`, listens on Unix socket, handles connections serially.

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

Interactive menu options:
1. **Validate Blockchain** - Runs `validate()` on both certificate and private key chains, displays block counts and heights
2. **Exit** - Terminates application (socket server thread stops with main process)

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

All requests are length-prefixed: 4-byte little-endian length + JSON payload. The socket server validates against duplicate common names using the in-memory state HashMap. Read example in `handle_client()`: `read_exact(&mut len_buf)` then `read_exact(&mut buf)`.

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

**Supported request types**: `CreateIntermediate`, `CreateUser` (requires `issuer_common_name` field), `ListCertificates` (filter: All/Intermediate/User/Root), `PKIStatus`, `SocketTest`

### Response Format

```json
{
  "status": "Success",
  "message": "Intermediate CA created",
  "data": { "uid": "550e8400-e29b-41d4-a716-446655440000" }
}
```

## Integration Points

### libblockchain Dependency

- **Source**: GitHub repository `jessethepro/libblockchain` (specified in Cargo.toml as git dependency)
- **Key APIs**: `BlockChain::new(path, key_path)`, `put_block()`, `get_block_by_height()`, `get_block_by_uuid()`, `validate()`, `block_count()`, `delete_latest_block()`, `iter()`
- **Storage**: Each blockchain uses RocksDB (sled) database with SST files and LOG snapshots in `data/certificates/` and `data/private_keys/`
- **Thread Safety**: Wrapped in `Arc<BlockChain>` for shared ownership across threads

### OpenSSL Usage

All cryptographic operations use `openssl` crate:
- Key generation: 4096-bit RSA via `openssl::rsa::Rsa::generate()`
- Certificate signing: `X509Builder` with SHA-256 digest
- Extensions: `BasicConstraints`, `KeyUsage` from `openssl::x509::extension`

## Common Pitfalls

1. **Mutex Deadlocks**: Always release `lock()` before blockchain operations that may take time. Use scoped blocks `{ let lock = mutex.lock().unwrap(); ... }` to force drops.
2. **Block Height vs UUID**: Genesis Root CA is at height 0 (accessed via `get_block_by_height(0)`). All blocks have UUIDs but state HashMap maps subject→height for O(1) lookups.
3. **Certificate Validation**: Intermediate CAs have `pathlen=0` (can't sign other CAs). Root CA has `pathlen=1` (can sign one level of CAs). Set via `BasicConstraints::new().ca().pathlen(n)`.
4. **Socket Message Protocol**: Must send 4-byte little-endian length prefix before JSON payload (`u32::from_le_bytes(len_buf)`). Missing length = connection hangs or deserialization failure.
5. **State Initialization**: Socket server populates `chain_state` on startup by iterating entire certificate blockchain (see `start_socket_server()`). O(n) operation - consider optimization for large chains.
6. **Rollback Transactions**: On certificate creation failure, rollback via `certificate_chain.delete_latest_block()` to maintain consistency between cert and key chains.

## File Organization

- [src/main.rs](src/main.rs): Entry point, blockchain initialization, interactive menu
- [src/external_interface.rs](src/external_interface.rs): Socket server, request handlers (~786 lines)
- [src/generate_root_ca.rs](src/generate_root_ca.rs): Root CA builder (self-signed, pathlen=1)
- [src/generate_intermediate_ca.rs](src/generate_intermediate_ca.rs): Intermediate CA builder (pathlen=0)
- [src/generate_user_keypair.rs](src/generate_user_keypair.rs): User cert builder (CA=false)
- [src/chain_state.rs](src/chain_state.rs): In-memory state tracking
- Shell scripts: Test utilities and key generation helpers

## Constants and Paths

- **Application Key**: `key/pki-chain-app.key` (constant: `APP_KEY_PATH`)
- **Unix Socket**: `/tmp/pki_socket` (constant: `SOCKET_PATH`)
- **Certificate Storage**: `data/certificates/` (sled database + snapshots)
- **Private Key Storage**: `data/private_keys/` (sled database + snapshots)
- **Export Directory**: `exports/` (Root CA key exports)
