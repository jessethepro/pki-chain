# PKI Chain Copilot Instructions

## Big picture (where to start)
- Entry point: [src/main.rs](src/main.rs) → `webserver::start_webserver()`.
- Web/UI/API: [src/webserver.rs](src/webserver.rs) (Axum routes, auth flow, REST handlers).
- HTML rendering: [src/templates.rs](src/templates.rs) (Maud render functions).
- Storage core: [src/storage.rs](src/storage.rs) (typestate `Storage<NoExist|Initialized|Ready>`, 3 blockchains, CRL).
- Crypto: [src/pki_generator.rs](src/pki_generator.rs) (cert generation), [src/encryption.rs](src/encryption.rs) (RSA‑OAEP + AES‑GCM).
- Configuration: [config.toml](config.toml) via [src/configs.rs](src/configs.rs).

## Architecture & data flow
- State-driven CA server: `CAServerState` in [src/webserver.rs](src/webserver.rs) drives UI/routes (NoExist → Initialized → CreateAdmin → Ready → Authenticated).
- Three blockchains in [src/storage.rs](src/storage.rs): certificates, private keys, CRL. Certs/CRL encrypted with app key; Root CA private key is PKCS#8 + password.
- REST API auth: requester serial + signature over payload; see `authenticate_api_request()` in [src/webserver.rs](src/webserver.rs). Endpoints: `POST /api/get-certificate`, `POST /api/verify-certificate`.
- Revocations are immutable CRL entries; login/API paths call `is_certificate_revoked()`.

## Project-specific conventions
- Typestate: open storage with the correct state (`Storage::<Initialized>::open()` / `Storage::<Ready>::open()`).
- `libblockchain` is not thread-safe: open a new chain per thread/task (see [src/storage.rs](src/storage.rs)).
- Maud templates are pure render fns returning `Markup` (see `render_*` in [src/templates.rs](src/templates.rs)).
- Admin certs are marked by OU suffix " Admin" (checked in `check_admin_status()` in [src/webserver.rs](src/webserver.rs)).
- API requests must not be Root CA: self-signed certs are denied in `authenticate_api_request()`.

## Critical workflows
- Build: `cargo build` (task available). Release: `cargo build --release`.
- First run prerequisites (repo root):
  - `./generate_app_keypair.sh` → creates app key at key/app.key
  - `./generate-webserver-certs.sh` → TLS certs in web_certs/server/
- Run: `./target/debug/pki-chain` or `./target/release/pki-chain` (HTTPS on port 3000).
- Logs: rolling files under logs/ (configured in [src/webserver.rs](src/webserver.rs)).

## Integration points
- `libblockchain` (git dep) provides `BlockChain<ReadWrite|ReadOnly>` APIs.
- OpenSSL handles RSA‑4096, X.509, signatures (see [src/pki_generator.rs](src/pki_generator.rs) and [src/webserver.rs](src/webserver.rs)).
- API docs/examples: [API_README.md](API_README.md), [test_api_quick.sh](test_api_quick.sh), [test_api_client.py](test_api_client.py).