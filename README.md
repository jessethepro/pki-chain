# PKI Chain

**A production-ready blockchain-backed Public Key Infrastructure (PKI) certificate authority with secure web-based management interface.**

Built in Rust with enterprise-grade cryptography, PKI Chain provides a complete three-tier CA hierarchy (Root CA → Intermediate CA → User Certificates) with state-driven authentication, Maud HTML templates, and comprehensive logging. Features hybrid storage: certificates in blockchain (DER format), private keys encrypted with RSA+AES-GCM-256, and SHA-512 integrity hashes via [libblockchain](https://github.com/jessethepro/libblockchain).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/github/v/release/jessethepro/pki-chain)](https://github.com/jessethepro/pki-chain/releases)

## Highlights

🌐 **Web-Based Management** - Complete HTTPS interface with state-driven authentication  
🔐 **Secure Login** - X.509 certificate + private key upload with challenge-response verification  
🎨 **Maud Templates** - Server-side HTML rendering with custom styling  
📊 **Comprehensive Logging** - Daily rotating logs with tracing framework  
🏗️ **Complete PKI** - Root CA, Intermediate CAs, and User certificates  
🔒 **RSA-4096** - Industry-standard cryptography with SHA-256 signatures  
🎯 **Fast Lookups** - O(1) certificate retrieval with in-memory indexing  
🔌 **REST API** - JSON endpoints for certificate operations with cryptographic authentication  
🚫 **Revocation System** - Immutable CRL blockchain with real-time revocation checks

## Features

### Web Interface & Authentication
- 🌐 **HTTPS Web Server**: Secure Axum-based interface on port 3000
- 🔐 **State-Driven Authentication**: NoExist → Initialized → CreateAdmin → Ready → Authenticated
- 📜 **X.509 Certificate Login**: Upload certificate + private key for authentication
- 🔑 **Challenge-Response**: Cryptographic proof of private key ownership
- � **Admin-Only Access**: Only administrators can access the web UI (verified via certificate OU field)
- �💾 **Auto-Download Credentials**: Certificate and key files after admin creation
- 🎨 **Custom UI**: Maud HTML templates with plum purple styling (rgb(46, 15, 92))

### PKI Management
- 🏗️ **Three-Tier Hierarchy**: Root CA → Intermediate CA → User Certificates
- 🔒 **4096-bit RSA Keys**: Strong cryptography with SHA-256 signatures
- 📋 **Admin Dashboard**: Manage certificates and view system status
- 📝 **Web Forms**: Create intermediate CAs and user certificates via UI
- 🎯 **Smart Certificate Creation**: User certificates don't require Root CA password
- ✅ **Certificate Validation**: OpenSSL-based chain validation
- 🔄 **Transactional Safety**: Automatic rollback on storage failures
- 🚫 **Certificate Revocation**: Permanent, immutable revocation with CRL blockchain
- 📊 **Revocation Table**: View all revoked certificates with timestamps and reasons
- 🔍 **Real-Time Revocation Checks**: Login and API requests verify certificate status

### Security & Storage
- 🔐 **Hybrid Storage Architecture**: 
  - Certificates stored as DER in blockchain (encrypted with app key)
  - Root CA: PKCS#8 PEM with password protection
  - All other keys: Encrypted with app.key (RSA + AES-GCM-256)
  - SHA-512 hashes and signatures in blockchain
- 🔑 **In-Memory Key Management**: Secure runtime storage with zeroize on drop
- 🛡️ **Password-Protected Root CA**: Only needed for signing intermediate CAs
- 🔐 **Encrypted Private Keys**: Hybrid RSA-OAEP + AES-GCM-256 with app.key

### REST API
- 🔌 **JSON Endpoints**: Machine-readable certificate operations
- 🔐 **Cryptographic Authentication**: Certificate serial + signature verification
- 🛡️ **Root CA Protection**: Root CA explicitly denied API access
- ✅ **Get Certificate**: Retrieve certificates by common name (non-revoked only)
- 🔍 **Verify Certificate**: Check certificate validity and revocation status
- 🔒 **Response Integrity**: SHA-256 hash encrypted with requester's public key
- 📋 **Revocation Checks**: All API requests verify certificate is not revoked
- 📚 **Complete Documentation**: API_README.md with Python and cURL examples

### Logging & Monitoring
- 📝 **Tracing Framework**: Structured logging with tracing-subscriber
- 🔄 **Daily Log Rotation**: Automatic rotation via tracing-appender
- 📊 **Dual Output**: Console + file logging (logs/webserver.log)
- 🚫 **No Panics**: All errors caught, logged, and handled gracefully
- 🔍 **Error Context**: Detailed error information for debugging


## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# 2. Generate master encryption key (REQUIRED for first run)
./generate_app_keypair.sh

# 3. Generate TLS certificates for HTTPS server
./generate-webserver-certs.sh

# 4. Build the application
cargo build --release

# 5. Start the web server
./target/release/pki-chain

# 6. Access the web interface
# Open browser: https://127.0.0.1:3000
```

### First-Time Setup Workflow

1. **Initialize** - Create Root CA with password (web form)
2. **Create Admin** - First admin user + intermediate CA (auto-downloads certificate + key)
3. **Login** - Upload certificate + private key + enter Root CA password
4. **Authenticated** - Access admin dashboard to manage certificates

## Web Interface

Access the web application at **https://127.0.0.1:3000**

### Available Routes

**Web Interface (Admin Only):**
- **`/`** - State-driven landing page (shows appropriate form based on system state)
- **`/initialize`** - Create Root CA with password
- **`/create-admin`** - Create first administrator account
- **`/login`** - X.509 certificate authentication with challenge-response
- **`/admin/dashboard`** - Admin control panel
- **`/admin/create-user`** - Create user certificates
- **`/admin/create-intermediate`** - Create intermediate CAs
- **`/admin/revoke`** - Revoke certificates (view revocation table)
- **`/admin/status`** - View system statistics
- **`/logout`** - End authenticated session

**REST API (Certificate-Based Auth):**
- **`POST /api/get-certificate`** - Retrieve certificate by common name (JSON)
- **`POST /api/verify-certificate`** - Verify certificate validity by serial number (JSON)

See [API_README.md](API_README.md) for complete API documentation with examples.

### Authentication Flow

```
1. Upload X.509 Certificate (.crt file)
2. Upload Private Key (.key file)
3. Enter Root CA Password
4. Server verifies:
   ✓ Certificate exists in PKI system
   ✓ Private key matches certificate public key
   ✓ Root CA password is correct
   ✓ Challenge-response signature valid
   ✓ Certificate has admin privileges (OU field ends with " Admin")
5. Access granted to admin dashboard
```

**Note**: Only users with admin certificates (OU field ending in " Admin") can access the web UI. This suffix is automatically added during admin user creation.

**Security Note**: Browser will show security warning for self-signed TLS certificate (expected for local development).

## Architecture

### Component Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Browser (HTTPS)                      │
│              https://127.0.0.1:3000                         │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  Axum Web Server                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  State Machine: NoExist → Initialized →              │  │
│  │  CreateAdmin → Ready → Authenticated                 │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Maud Templates (templates.rs)                       │  │
│  │  - State-driven HTML rendering                       │  │
│  │  - Custom styling (rgb(46,15,92))                    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Tracing Framework                                   │  │
│  │  - Daily rotating logs (logs/webserver.log)          │  │
│  │  - Error/Warn/Info levels                            │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Storage Layer (storage.rs)                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Type-State Pattern:                                 │  │
│  │  Storage<NoExist> → Storage<Initialized> →          │  │
│  │  Storage<Ready>                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Certificate Index (HashMap<String, u64>)            │  │
│  │  - Subject CN → Blockchain Height                    │  │
│  │  - O(1) certificate lookups                          │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│          Three Blockchain Storage (libblockchain)           │
│  ┌──────────────────┬──────────────────┬─────────────────┐  │
│  │ Certificate      │ Private Key      │ CRL             │  │
│  │ Blockchain       │ Blockchain       │ Blockchain      │  │
│  │                  │                  │                 │  │
│  │ Height 0:        │ Height 0:        │ (Empty until    │  │
│  │   Root CA (DER)  │   Root Key Hash  │  revocations)   │  │
│  │ Height 1+:       │ Height 1+:       │                 │  │
│  │   User Certs     │   Key Hashes     │                 │  │
│  │                  │                  │                 │  │
│  │ ▲ Encrypted with │ ▲ Encrypted with │ ▲ Encrypted     │  │
│  │   app.crt key    │   Root CA key    │   with app.crt  │  │
│  └──────────────────┴──────────────────┴─────────────────┘  │
│                    RocksDB Backend                          │
└─────────────────────────────────────────────────────────────┘
```

### Key Modules

- **[main.rs](src/main.rs)** (96 lines): Entry point, launches webserver
- **[webserver.rs](src/webserver.rs)** (1657 lines): Axum HTTPS server with state machine and REST API
  - CA server states: NoExist, Initialized, CreateAdmin, Ready, Authenticated
  - Admin-only authentication via certificate OU field verification
  - REST API endpoints: `/api/get-certificate`, `/api/verify-certificate`
  - Cryptographic authentication: serial number + signature verification
  - Root CA restriction: Self-signed certificates denied API access
  - Response integrity: SHA-256 hash encrypted with requester's public key
  - Certificate revocation UI with revoked certificates table
  - Tracing initialization with daily rotation
  - All panics replaced with graceful error handling
- **[templates.rs](src/templates.rs)** (619 lines): Maud HTML templates
  - State-driven page rendering
  - Custom CSS with plum purple theme
  - Certificate/key download pages
  - User certificate creation form with intermediate CA dropdown
  - Intermediate CA creation form
- **[storage.rs](src/storage.rs)** (1364 lines): Type-state blockchain storage
  - Three separate blockchains (certificates, keys, CRL)
  - In-memory subject name index for fast lookups
  - Certificate lookup by serial number for API operations
  - Certificate revocation with CRL blockchain storage
  - Real-time revocation checks (login and API authentication)
  - Get revoked certificates list with metadata
  - Transactional operations with rollback
  - User certificate creation without Root CA password
  - Intermediate CA detection by issuer (issued by Root CA)
- **[pki_generator.rs](src/pki_generator.rs)** (251 lines): Certificate generation
  - Unified generation for all certificate types
  - 4096-bit RSA keys, SHA-256 signatures
  - Proper issuer DN field generation
- **[encryption.rs](src/encryption.rs)** (211 lines): Hybrid RSA + AES-GCM-256
- **[configs.rs](src/configs.rs)** (149 lines): TOML configuration management

### PKI Hierarchy

```
Root CA (self-signed, pathlen=1)
  └── Intermediate CA (signed by Root, pathlen=0)
      └── User Certificate (signed by Intermediate, CA=false)
```

### Storage Architecture

**Blockchain Layer** (RocksDB):
- **Certificate Chain**: X.509 certificates in DER format (encrypted with app.key)
- **Private Key Chain**: Private keys encrypted, SHA-512 hashes + signatures
  - Root CA: PKCS#8 PEM with password protection
  - All others: Encrypted with app.key (RSA-OAEP + AES-GCM-256)
- **CRL Chain**: Certificate Revocation Lists (encrypted with app.key)

**In-Memory**:
- Application key loaded from `key/app.key` (decrypts all blockchains and non-Root CA keys)
- Certificate index: `HashMap<String, u64>` for O(1) lookups
- Secure memory handling with zeroize on drop

**Key Benefits**:
- Root CA password only required for creating intermediate CAs
- User certificates can be created without exposing Root CA password
- All operations except intermediate CA signing use app.key (in-memory)

## Installation

### Prerequisites

- **Rust 1.70+** (tested with 1.85)
- **OpenSSL development libraries** (`libssl-dev` or `openssl-devel`)
- **Linux/Unix system** (for file permissions and TLS)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jessethepro/pki-chain.git
cd pki-chain

# Generate application encryption key (FIRST RUN ONLY)
./generate_app_keypair.sh
# Output: Creates key/app.key and certificate/app.crt

# Generate TLS certificates for web server (FIRST RUN ONLY)
./generate-certs.sh
# Output: Creates web_certs/server/chain.pem and server.key

# Build the project
cargo build --release

# Run the web server
./target/release/pki-chain
```

**🔒 Security Note**: `key/app.key` is the master encryption key loaded into memory. **Keep this file secure and backed up**. Loss of the app key means permanent loss of access to blockchain data.

## Usage

### Web Interface

Access the web application at **https://127.0.0.1:3000**

```bash
# Start the server
./target/release/pki-chain

# Server output:
# 🔒 PKI Chain Certificate Authority
#    HTTPS: https://127.0.0.1:3000
#    TLS Cert: web_certs/server/chain.pem
#    TLS Key: web_certs/server/server.key
#    Web Root: web_root/
#    Log Directory: logs/
# ✅ Server ready!
```

### First-Time Setup Workflow

1. **Initialize System** (creates Root CA):
   - Navigate to https://127.0.0.1:3000
   - Enter Root CA password (stored in encrypted PKCS#8 format)
   - Click "Initialize" button

2. **Create Admin User** (auto-downloads certificate + key):
   - Fill out Distinguished Name fields (CN, O, OU, L, ST, C)
   - Enter Root CA password (required to sign admin's intermediate CA)
   - System creates admin intermediate CA + admin user certificate
   - OU field automatically appended with " Admin" suffix
   - Browser auto-downloads `<username>.crt` and `<username>.key`

3. **Login** (X.509 certificate authentication):
   - Upload `.crt` file (certificate)
   - Upload `.key` file (private key)
   - Enter Root CA password
   - Challenge-response verification authenticates you
   - System verifies admin status (OU field must end with " Admin")

4. **Admin Dashboard** (certificate management):
   - **Create Intermediate CAs**: Requires Root CA password
   - **Create User Certificates**: No Root CA password needed (uses app.key)
   - **Revoke Certificates**: Permanently revoke certificates (immutable CRL)
   - **View System Status**: Blockchain statistics and validation
   - **Logout**: End authenticated session

### REST API Usage

The REST API allows programmatic access to certificate operations. **Only non-Root CA certificates** can make API requests.

**Authentication**: All API requests require:
1. Requester's certificate serial number (hex string)
2. Cryptographic signature of request data (base64-encoded)
3. Certificate must exist in the PKI system and not be revoked
4. Certificate must NOT be the Root CA (self-signed certificates denied)

**Example: Get Certificate by Common Name**

```python
import json
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load certificate and private key
with open('user.crt', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read())
with open('user.key', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Get requester serial number
requester_serial = format(cert.serial_number, 'X')

# Sign target CN
target_cn = "target.user@example.com"
signature = private_key.sign(
    target_cn.encode('utf-8'),
    padding.PKCS1v15(),
    hashes.SHA256()
)
signature_b64 = base64.b64encode(signature).decode('ascii')

# Make API request
response = requests.post(
    'https://127.0.0.1:3000/api/get-certificate',
    json={
        'requester_serial': requester_serial,
        'target_cn': target_cn,
        'signature': signature_b64
    },
    verify=False  # Self-signed cert
)

result = response.json()
if result['success']:
    print(f"Certificate: {result['certificate_pem']}")
    print(f"Serial: {result['serial_number']}")
    # Verify response integrity
    encrypted_hash = result['encrypted_hash']
    # Decrypt with private key and verify SHA-256
else:
    print(f"Error: {result['error']}")
```

**Example: Verify Certificate by Serial Number**

```bash
# Extract serial from certificate
SERIAL=$(openssl x509 -in user.crt -noout -serial | cut -d'=' -f2)
REQUESTER_SERIAL=$(openssl x509 -in requester.crt -noout -serial | cut -d'=' -f2)

# Sign the target serial
SIGNATURE=$(echo -n "$SERIAL" | openssl dgst -sha256 -sign requester.key | base64 -w 0)

# Make API request
curl -k -X POST https://127.0.0.1:3000/api/verify-certificate \
  -H "Content-Type: application/json" \
  -d "{
    \"requester_serial\": \"$REQUESTER_SERIAL\",
    \"target_serial\": \"$SERIAL\",
    \"signature\": \"$SIGNATURE\"
  }" | jq
```

**Response Fields:**
- `success`: Boolean indicating if request succeeded
- `certificate_pem`: Certificate in PEM format (get-certificate only)
- `valid`: Boolean indicating certificate validity (verify-certificate only)
- `revoked`: Boolean indicating revocation status (verify-certificate only)
- `serial_number`: Certificate serial number (hex string)
- `subject_cn`: Subject common name
- `issuer_cn`: Issuer common name
- `not_before`: Validity start date
- `not_after`: Validity end date
- `encrypted_hash`: SHA-256 hash of response data, encrypted with requester's public key
- `error`: Error message if request failed

**API Restrictions:**
- ✅ User certificates can make API requests
- ✅ Intermediate CA certificates can make API requests
- ❌ Root CA certificates **cannot** make API requests
- ❌ Revoked certificates **cannot** make API requests

See [API_README.md](API_README.md) for complete documentation, error codes, and Python test client.

### Certificate Revocation

PKI Chain includes a permanent, immutable certificate revocation system:

**Revocation Process:**
1. Navigate to `/admin/revoke` in the web interface
2. Select certificate from dropdown (all certificates except Root CA)
3. Optionally enter revocation reason
4. Confirm revocation (checkbox required)
5. Certificate permanently added to CRL blockchain

**Revoked Certificates Table:**
- Displays all revoked certificates with metadata
- Columns: Common Name, Serial Number, Revocation Date, Reason, Certificate Height
- Timestamps shown in UTC format
- Real-time updates when new certificates are revoked

**Revocation Enforcement:**
- Login attempts with revoked certificates are **automatically denied**
- API requests from revoked certificates are **rejected**
- Get Certificate API returns **only non-revoked certificates**
- Verify Certificate API reports revocation status

**Important Notes:**
- ⚠️ Revocation is **permanent and irreversible** (immutable blockchain)
- ⚠️ Revoked certificates **cannot be un-revoked**
- ℹ️ To restore user access, create a **new certificate** with different serial number
- ℹ️ Root CA **cannot be revoked** (system protection)

### Logging

All webserver activity logged to `logs/webserver.log` with daily rotation:

```
2026-01-21T10:30:45.123Z INFO pki_chain::webserver: Starting PKI Chain web server
2026-01-21T10:30:45.456Z INFO pki_chain::webserver: Storage state: NoExist (fresh installation)
2026-01-21T10:31:12.789Z INFO pki_chain::webserver: Received admin creation request for CN: jesse.johnson
2026-01-21T10:31:15.234Z INFO pki_chain::webserver: Admin user created successfully: jesse.johnson
2026-01-21T10:32:03.567Z INFO pki_chain::webserver: Received login request
2026-01-21T10:32:04.890Z INFO pki_chain::webserver: User authenticated successfully: jesse.johnson
```

**Log Levels**: INFO (normal operations), WARN (recoverable issues), ERROR (failures)

## Configuration

All settings configured via `config.toml` in the project root:

```toml
[blockchains]
certificate_path = "data/certificates"   # Certificate blockchain (RocksDB)
private_key_path = "data/private_keys"   # Private key blockchain (RocksDB)
crl_path = "data/crl"                    # CRL blockchain (RocksDB)

[key_exports]
app_key_path = "key/app.key"             # Master encryption key
app_cert_path = "certificate/app.crt"    # Application certificate (public key)
root_key_name = "0.key.enc"              # Root CA private key filename
key_export_directory_path = "exports/keystore"  # Encrypted key storage

[server]
host = "127.0.0.1"                       # Web server bind address
port = 3000                              # Web server port
web_root = "web_root"                    # Static file directory
tls_cert_path = "web_certs/server/chain.pem"   # TLS certificate
tls_key_path = "web_certs/server/server.key"   # TLS private key

[root_ca_defaults]
root_ca_common_name = "MenaceLabs Root CA"
root_ca_organization = "MenaceLabs"
root_ca_organizational_unit = "CY"
root_ca_locality = "Sao Jose dos Campos"
root_ca_state = "SP"
root_ca_country = "BR"
root_ca_validity_days = 3650             # 10 years
```

All paths are relative to the project root. Adjust as needed for your deployment.

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

On first run, the web interface guides you through initialization:

### Height 0: Root CA (Created During Initialization)
- **Subject CN**: `MenaceLabs Root CA` (configurable in config.toml)
- **Type**: Self-signed Root Certificate Authority
- **Constraints**: CA=true, pathlen=1 (can sign one level of CAs)
- **Validity**: 10 years (3650 days, configurable)
- **Usage**: Signs Intermediate CAs
- **Storage**: Private key stored as password-protected PKCS#8 PEM in blockchain

### Heights 1-2: First Admin (Created During Setup)
- **Height 1**: Admin Intermediate CA (CN="Admin User Intermediate", pathlen=0, signed by Root)
- **Height 2**: Admin User Certificate (OU ends with " Admin", signed by Admin Intermediate)
- **Private Keys**: Encrypted with app.key (hybrid RSA + AES-GCM-256)

### Heights 3+: User-Created Certificates
All subsequent certificates created via admin dashboard:
- **Intermediate CAs**: pathlen=0, configurable validity, requires Root CA password
- **User Certificates**: CA=false, configurable validity, no Root CA password needed
- **Encryption**: All private keys (except Root CA) encrypted with app.key

## Certificate Parameters

- **RSA Key Size**: 4096 bits
- **Signature Algorithm**: SHA-256 with RSA
- **Root CA**: pathlen=1, validity 10 years (default)
- **Intermediate CA**: pathlen=0, validity 5 years (default), requires Root CA password to create
- **User Certificates**: CA=false, validity 1 year (default), no Root CA password needed
- **Admin Certificates**: OU field ends with " Admin" suffix (automatically added)
- **Encryption**:
  - Root CA: PKCS#8 PEM with password protection (only needed for signing intermediate CAs)
  - All others: Hybrid RSA-OAEP + AES-256-GCM encrypted with app.key from memory

## Development

### Project Structure

```
pki-chain/
├── src/
│   ├── lib.rs                       # Library interface
│   ├── main.rs                      # Application entry point (96 lines)
│   ├── webserver.rs                 # HTTPS web server (Axum + state machine + API, 1657 lines)
│   ├── templates.rs                 # Maud HTML templates (619 lines)
│   ├── storage.rs                   # Type-state blockchain storage (1364 lines)
│   ├── pki_generator.rs             # Unified certificate generation (251 lines)
│   ├── encryption.rs                # Hybrid RSA + AES-GCM-256 encryption (211 lines)
│   ├── key_archive.rs               # Tar-based key backup/restore (139 lines)
│   └── configs.rs                   # TOML configuration parsing (149 lines)
├── .github/
│   └── copilot-instructions.md      # AI coding assistant instructions
├── API_README.md                    # REST API documentation (~400 lines)
├── API_IMPLEMENTATION_SUMMARY.md    # API architecture overview (~350 lines)
├── test_api_client.py               # Python API test client (~340 lines)
├── test_api_quick.sh                # Bash API testing script (~80 lines)
├── config.toml                      # Configuration file
├── generate_app_keypair.sh          # Application key generator
├── generate-certs.sh                # TLS certificate generator
├── test_keypair_generation.sh       # End-to-end test suite
├── web_root/                        # Static web files (HTML/CSS/JS)
├── web_certs/                       # TLS certificates (generated)
├── logs/                            # Daily rotating webserver logs
├── data/                            # Blockchain databases (RocksDB)
│   ├── certificates/                # Certificate blockchain (encrypted DER)
│   ├── private_keys/                # Private key hashes + signatures
│   └── crl/                         # Certificate Revocation List blockchain
└── exports/keystore/                # Encrypted private key storage
```

### Building Documentation

Generate and view the API documentation:

```bash
cargo doc --open
```

### Dependencies

Key dependencies and their purposes:
- [`libblockchain`](https://github.com/jessethepro/libblockchain) - Custom blockchain storage engine with RocksDB backend
- `openssl` (0.10) - RSA-4096 key generation, X.509 certificate operations, SHA-256/SHA-512 hashing
- `axum` (0.8) - Web framework for HTTPS server and REST API
- `tokio` (1.48) - Async runtime for web server
- `axum-server` (0.8) - TLS/HTTPS support
- `keyutils` (0.4) - Linux kernel keyring integration for secure key management
- `anyhow` (1.0) - Ergonomic error handling with context chains
- `serde`/`serde_json` (1.0) - Data serialization
- `rpassword` (7.3) - Secure password input without echo
- `toml` (0.9) - TOML configuration file parsing
- `zeroize` (1.8) - Secure memory clearing for cryptographic keys

### Development Dependencies
- Standard Rust toolchain (1.70+)
- System OpenSSL development libraries (`libssl-dev` on Debian/Ubuntu)
- Linux kernel keyring support

## Security Considerations

### Best Practices

1. **Protect the Application Key**: The `key/pki-chain-app.key` file is loaded into memory and zeroized on drop. Store the file securely and back it up.

2. **Root CA Private Key**: The Root CA private key is stored as password-protected PKCS#8 in `exports/keystore/root_private_key.pkcs8`. This password is required on every startup. Store the password securely (e.g., password manager).

3. **Certificate Validation**: Always validate certificates using `openssl verify` before deployment.

4. **Blockchain Integrity**: Regularly validate blockchain integrity using the "Validate Blockchain" menu option.

5. **Keyring Security**: The Linux kernel keyring stores keys in memory. Ensure your system is properly secured and use full-disk encryption.

### Security Considerations

PKI Chain implements multiple layers of security:

**Authentication & Access Control:**
- X.509 certificate-based authentication (no passwords)
- Challenge-response signature verification
- Root CA password protection for key operations
- Session-based access control (authenticated vs unauthenticated)
- REST API: Certificate serial + cryptographic signature verification
- Root CA protection: Self-signed certificates denied API access
- Real-time revocation checks for login and API authentication
- Immutable CRL blockchain for permanent revocation records

**Encryption at Rest:**
- Root CA private key: PKCS#8 PEM with password protection
- Other private keys: Hybrid RSA-OAEP + AES-256-GCM encryption
- Blockchain data: Encrypted with application public key
- All keys zeroized in memory on drop

**Data Integrity:**
- Blockchain storage provides tamper detection
- SHA-512 hashing for private key verification
- Transaction-based operations with rollback
- Cross-chain validation (certificates ↔ key hashes)

**Logging & Monitoring:**
- Daily rotating logs in `logs/webserver.log`
- Authentication attempts logged with username
- All errors logged before displaying to user
- Graceful error handling (no panics)

**Network Security:**
- HTTPS only (TLS 1.3)
- Self-signed certificates for local development
- Localhost binding by default (127.0.0.1:3000)

## Troubleshooting

### Common Issues

**"Failed to initialize storage"**
- Ensure `key/app.key` exists (run `./generate_app_keypair.sh`)
- Check file permissions on `data/` directories
- Verify application certificate exists at `certificate/app.crt`

**"Certificate not found in PKI system" (Login Error)**
- Ensure you uploaded the correct certificate file
- Certificate must have been created through the admin dashboard
- Check logs/webserver.log for details

**"Invalid Root CA password"**
- Verify you're using the password set during initialization
- Root CA password is case-sensitive
- Check for extra spaces or special characters

**"Blockchain validation failed"**
- Possible data corruption detected
- Check blockchain integrity
- If starting fresh, run initialization again (deletes existing data)

**"Failed to open certificate blockchain"**
- RocksDB files may be locked by another process
- Check that only one instance of pki-chain is running
- Verify permissions on `data/` directory

**Browser Shows Security Warning**
- Expected for self-signed TLS certificates
- Click "Advanced" → "Proceed to localhost" (safe for local development)
- For production, use properly signed certificates

**Log Files Growing Large**
- Logs rotate daily automatically (logs/webserver.log.YYYY-MM-DD)
- Old logs must be manually archived or deleted
- Consider setting up log rotation policy

**API Request Fails with "Authentication failed"**
- Verify certificate serial number is correct (hex format)
- Ensure signature is base64-encoded and uses SHA-256
- Check that certificate exists in PKI system and is not revoked
- Root CA certificates **cannot** make API requests (security restriction)
- Review API_README.md for signature generation examples

**"Certificate has been revoked" Error**
- Certificate was permanently revoked via admin dashboard
- Revocation is **immutable** and cannot be reversed
- Create a new certificate for the user with different serial number
- Check revoked certificates table at `/admin/revoke`

**Cannot Revoke Certificate**
- Root CA (height 0) cannot be revoked (system protection)
- Ensure you're authenticated as an administrator
- Certificate must exist in PKI system
- Check logs/webserver.log for detailed error messages

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
- Axum web framework for async HTTPS server
- Maud templating for server-side HTML rendering
- Tracing framework for comprehensive logging

## Contact

- GitHub: [@jessethepro](https://github.com/jessethepro)
- Repository: [pki-chain](https://github.com/jessethepro/pki-chain)

---

**Note**: This is a demonstration project. For production use, conduct a thorough security audit and implement additional access controls, monitoring, and hardening as required by your security policies.
