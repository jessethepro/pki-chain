# PKI Chain Copilot Instructions

## Project Overview

This is a blockchain-backed PKI (Public Key Infrastructure) certificate authority system written in Rust. It manages a complete certificate chain (Root CA → Intermediate CA → User Certificates) with all certificates and private keys stored in tamper-proof blockchain storage via the `libblockchain` dependency.

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

1. **Initialization** ([main.rs](src/main.rs#L16-L28)): On first run, generates Root CA and stores as genesis blocks (height 0) in both blockchains
2. **Certificate Creation** ([external_interface.rs](src/external_interface.rs#L250-L360)): New certificates stored via `put_block()`, returns UUID for lookup
3. **State Management** ([chain_state.rs](src/chain_state.rs)): In-memory `subject_name_to_height` HashMap maps common names to block UUIDs for fast certificate retrieval
4. **Socket Protocol** ([external_interface.rs](src/external_interface.rs#L155-L250)): Length-prefixed JSON messages (4-byte LE length + JSON payload)

## Key Conventions

### Builder Pattern Usage

All certificate generation uses builder pattern with **mandatory field validation**. Example from [generate_root_ca.rs](src/generate_root_ca.rs#L80-L100):

```rust
RsaRootCABuilder::new()
    .subject_common_name("PKI Chain Root CA".to_string())  // All 6 DN fields required
    .organization("MenaceLabs".to_string())
    .organizational_unit("CY".to_string())
    .country("BR".to_string())
    .state("SP".to_string())
    .locality("Sao Jose dos Campos".to_string())
    .validity_days(365 * 5)
    .build()  // Returns Result<(PKey<Private>, X509)>
```

Missing any DN field causes a runtime error in `build()`.

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
# Build (requires libblockchain in ../libblockchain)
cargo build --release

# Run application (starts socket server and interactive menu)
./target/debug/pki-chain
```

### Testing PKI Operations

Use `test_keypair_generation.sh` for end-to-end testing:

```bash
./test_keypair_generation.sh
# Prompts for application PFX path, generates Root → Intermediate → 5 User certs
```

### Generating Application Keys

The application requires a master key to encrypt blockchain databases:

```bash
./generate_app_keypair.sh  # Creates key/pki-chain-app.key
```

**Critical**: This key must exist before running the application. Lost keys = unrecoverable blockchain data.

## External Interface (Socket API)

Clients communicate via Unix socket at `/tmp/pki_socket` with JSON requests:

### Request Format (see [external_interface.rs](src/external_interface.rs#L30-L58))

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

Supported request types: `CreateIntermediate`, `CreateUser`, `ListCertificates`, `PKIStatus`, `SocketTest`

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

- **Path**: Expects sibling directory `../libblockchain` (local path dependency in Cargo.toml)
- **Key APIs**: `BlockChain::new(path, key_path)`, `put_block()`, `get_block_by_height()`, `get_block_by_uuid()`, `validate()`, `block_count()`, `iter()`
- **Storage**: Each blockchain uses sled database with snapshots (see `data/*/snap.*` files)

### OpenSSL Usage

All cryptographic operations use `openssl` crate:
- Key generation: 4096-bit RSA via `openssl::rsa::Rsa::generate()`
- Certificate signing: `X509Builder` with SHA-256 digest
- Extensions: `BasicConstraints`, `KeyUsage` from `openssl::x509::extension`

## Common Pitfalls

1. **Mutex Deadlocks**: Always release `lock()` before blockchain operations that may take time. Use scoped blocks to force drops.
2. **Block Height vs UUID**: Genesis Root CA is at height 0. Intermediate/User certs use UUIDs. State HashMap maintains subject→UUID mapping.
3. **Certificate Validation**: Intermediate CAs have `pathlen=0` (can't sign other CAs). Root CA has `pathlen=1` (can sign one level of CAs).
4. **Socket Message Protocol**: Must send 4-byte little-endian length prefix before JSON payload. Missing length prefix = deserialization failure.
5. **State Initialization**: Socket server populates `chain_state` on startup by iterating entire certificate blockchain. Heavy operation if chain is large.

## File Organization

- [src/main.rs](src/main.rs): Entry point, blockchain initialization, interactive menu
- [src/external_interface.rs](src/external_interface.rs): Socket server, request handlers (746 lines)
- [src/generate_root_ca.rs](src/generate_root_ca.rs): Root CA builder (self-signed, pathlen=1)
- [src/generate_intermediate_ca.rs](src/generate_intermediate_ca.rs): Intermediate CA builder (pathlen=0)
- [src/generate_user_keypair.rs](src/generate_user_keypair.rs): User cert builder (CA=false)
- [src/chain_state.rs](src/chain_state.rs): In-memory state tracking
- Shell scripts: Test utilities and key generation helpers
