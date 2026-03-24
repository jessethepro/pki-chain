# PKI Chain Copilot Instructions

## Big picture (where to start)
- Entry point: [src/main.rs](src/main.rs) → `comm_protocol::start_comm_server()`.
- Communication in [src/comm_protocol.rs](src/comm_protocol.rs): Unix socket server, request dispatch, CA state machine, auth handlers. There is no web interface.
- Storage core in [src/storage.rs](src/storage.rs): typestate `Storage<NoExist|Initialized|Ready>`, three blockchains + CRL + in-memory CN→height index.
- Crypto in [src/pki_generator.rs](src/pki_generator.rs) and [src/encryption.rs](src/encryption.rs): X.509 generation; RSA-OAEP + AES-GCM.
- Config: [config.toml](config.toml) via [src/configs.rs](src/configs.rs).
- There is no graphical or web interface in this project. A separate client project connects via Unix socket.

## Architecture & data flow
- Communication is exclusively via Unix sockets; all clients connect through the socket path defined in config.
- **Wire format** (binary framing, little-endian):
  1. `version: u32` — protocol version (currently `1`)
  2. `payload_size: u32` — byte length of the following payload
  3. `payload: [u8; payload_size]` — UTF-8 JSON string
- The JSON payload is parsed by the service into a `HashMap<String, String>`. The `request_type` key determines the handler branch.
- Responses are sent back on a client-supplied response socket path (`response_socket` JSON field), using the same binary framing.
- Two server entry points exist: `start_comm_server` (normal operation) and `start_setup_server` (initial admin setup, `Initialized` state only).
- Each accepted connection is handled in a dedicated thread (`std::thread::spawn`); one request per connection.
- CA state machine lives in [src/comm_protocol.rs](src/comm_protocol.rs) and drives request handling (NoExist → Initialized → CreateAdmin → Ready → Authenticated).
- Storage uses three blockchains (certs, private keys, CRL). Certs/CRL are encrypted with app key; Root CA key is PKCS#8 + password (see [src/storage.rs](src/storage.rs)).
- API auth uses requester serial + signature. Self-signed (Root CA) certs are denied.
- Revocations are immutable CRL entries; all auth paths call `is_certificate_revoked()`.

## Error handling conventions
- All per-connection handler functions return `anyhow::Result<()>`.
- Use `inspect_err(|e| tracing::error!(...))` + `?` to log and propagate errors.
- Use `tracing::error!` / `tracing::info!` etc. for all logging — no `println!` or `eprintln!`.
- Structured fields use `error = %e` (Display) or `field = ?value` (Debug) syntax.
- The `unwrap_or_log!` macro bridges legacy code; prefer `inspect_err + ?` in new code.

## Project-specific conventions
- Typestate matters: open storage with correct state (`Storage::<Initialized>::open()` / `Storage::<Ready>::open()`).
- `libblockchain` is not thread-safe: open a new chain per thread/task (see [src/storage.rs](src/storage.rs)).
- Admin certs are marked by OU suffix " Admin".
- Storage writes are transactional with rollback in `storage.rs` helpers; keep that pattern.
- `key/app.key` is the master encryption key; loss breaks access to encrypted blockchain data.
- Maximum payload size is 10 MiB; requests exceeding this are rejected before reading the body.

## Critical workflows
- Build: `cargo build` (task available) or `cargo build --release`.
- Prereqs: Rust 1.70+ and OpenSSL dev libs (`libssl-dev`/`openssl-devel`).
- First run scripts (repo root):
  - `./generate_app_keypair.sh` → creates key/app.key (and certificate/app.crt).
- Run: `./target/debug/pki-chain` or `./target/release/pki-chain`.
- Logs: rolling daily files under logs/ (`pki_chain.log`), also mirrored to stdout. Level controlled by `RUST_LOG` env var (default: `info`).

## Integration points
- `libblockchain` git dependency provides `BlockChain<ReadWrite|ReadOnly>` (RocksDB backend).
- OpenSSL handles RSA-4096, X.509, signatures (see [src/pki_generator.rs](src/pki_generator.rs)).
- Client implementations live in a separate project and communicate exclusively via the Unix socket wire protocol described above.
- API docs/examples: [API_README.md](API_README.md).
