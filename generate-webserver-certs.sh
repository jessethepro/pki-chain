#!/bin/bash

# Certificate Generation Script for Local Development
# Generates: Root CA → Intermediate CA → Server Certificate for localhost

set -e  # Exit on error

# Set OpenSSL config path (Arch Linux location)
export OPENSSL_CONF=/etc/ssl/openssl.cnf

# Configuration
CERT_DIR="./web_certs"
ROOT_NAME="LocalRootCA"
INTERMEDIATE_NAME="LocalIntermediateCA"
SERVER_NAME="localhost"
DAYS_ROOT=7300        # 20 years
DAYS_INTERMEDIATE=3650 # 10 years
DAYS_SERVER=825       # ~2 years (browser limit)

echo "🔐 Certificate Chain Generation Script"
echo "======================================"
echo ""

# Create directory structure
mkdir -p "$CERT_DIR"/{root,intermediate,server}
cd "$CERT_DIR"

# ==============================================================================
# Step 1: Generate Root CA
# ==============================================================================
echo "📜 Step 1: Generating Root CA..."

# Root CA private key
openssl genrsa -out root/root-ca.key 4096
chmod 400 root/root-ca.key  # Read-only by owner

# Root CA certificate
openssl req -x509 -new -nodes \
  -key root/root-ca.key \
  -sha256 \
  -days $DAYS_ROOT \
  -out root/root-ca.crt \
  -subj "/C=US/ST=Local/L=Local/O=Local Development/OU=Root CA/CN=$ROOT_NAME"

chmod 644 root/root-ca.crt  # Readable by all

echo "✓ Root CA generated"
echo "  - Private Key: root/root-ca.key"
echo "  - Certificate: root/root-ca.crt"
echo ""

# ==============================================================================
# Step 2: Generate Intermediate CA
# ==============================================================================
echo "📜 Step 2: Generating Intermediate CA..."

# Intermediate CA private key
openssl genrsa -out intermediate/intermediate-ca.key 4096
chmod 400 intermediate/intermediate-ca.key  # Read-only by owner

# Intermediate CA CSR (Certificate Signing Request)
openssl req -new \
  -key intermediate/intermediate-ca.key \
  -out intermediate/intermediate-ca.csr \
  -subj "/C=US/ST=Local/L=Local/O=Local Development/OU=Intermediate CA/CN=$INTERMEDIATE_NAME"

# Create OpenSSL config for intermediate CA
cat > intermediate/intermediate-ca.cnf << EOF
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

# Sign intermediate certificate with root CA
openssl x509 -req \
  -in intermediate/intermediate-ca.csr \
  -CA root/root-ca.crt \
  -CAkey root/root-ca.key \
  -CAcreateserial \
  -out intermediate/intermediate-ca.crt \
  -days $DAYS_INTERMEDIATE \
  -sha256 \
  -extfile intermediate/intermediate-ca.cnf \
  -extensions v3_intermediate_ca

chmod 644 intermediate/intermediate-ca.crt  # Readable by all

echo "✓ Intermediate CA generated"
echo "  - Private Key: intermediate/intermediate-ca.key"
echo "  - Certificate: intermediate/intermediate-ca.crt"
echo ""

# ==============================================================================
# Step 3: Generate Server Certificate for localhost
# ==============================================================================
echo "📜 Step 3: Generating Server Certificate for localhost..."

# Server private key
openssl genrsa -out server/server.key 2048
chmod 400 server/server.key  # Read-only by owner - CRITICAL!

# Server CSR
openssl req -new \
  -key server/server.key \
  -out server/server.csr \
  -subj "/C=US/ST=Local/L=Local/O=Local Development/OU=Web Server/CN=localhost"

# Create OpenSSL config for server certificate with SAN
cat > server/server.cnf << EOF
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
req_extensions = req_ext

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
stateOrProvinceName = State or Province Name
localityName = Locality Name
organizationName = Organization Name
commonName = Common Name

[ req_ext ]
subjectAltName = @alt_names

[ v3_server ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = 127.0.0.1
DNS.4 = services.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with intermediate CA
openssl x509 -req \
  -in server/server.csr \
  -CA intermediate/intermediate-ca.crt \
  -CAkey intermediate/intermediate-ca.key \
  -CAcreateserial \
  -out server/server.crt \
  -days $DAYS_SERVER \
  -sha256 \
  -extfile server/server.cnf \
  -extensions v3_server

chmod 644 server/server.crt  # Readable by all

echo "✓ Server certificate generated"
echo "  - Private Key: server/server.key"
echo "  - Certificate: server/server.crt"
echo ""

# ==============================================================================
# Step 4: Create Certificate Chain Bundle
# ==============================================================================
echo "📜 Step 4: Creating certificate chain bundle..."

# Full chain (includes root for local trust tooling)
cat server/server.crt intermediate/intermediate-ca.crt root/root-ca.crt > server/fullchain.pem
chmod 644 server/fullchain.pem

# Chain without root (common for web servers)
cat server/server.crt intermediate/intermediate-ca.crt > server/chain.pem
chmod 644 server/chain.pem

echo "✓ Certificate chain bundles created"
echo "  - Full chain: server/fullchain.pem"
echo "  - Chain (no root): server/chain.pem"
echo ""

# ==============================================================================
# Step 5: Verify and Display Permissions
# ==============================================================================
echo "🔒 File Permissions Security Check"
echo "======================================"
echo ""
echo "Private Keys (should be 400 or 600):"
ls -lh root/root-ca.key intermediate/intermediate-ca.key server/server.key | awk '{print "  " $1, $9}'
echo ""
echo "Certificates (can be 644):"
ls -lh root/root-ca.crt intermediate/intermediate-ca.crt server/server.crt server/chain.pem | awk '{print "  " $1, $9}'
echo ""

# ==============================================================================
# Step 6: Display Certificate Information
# ==============================================================================
echo "📋 Certificate Chain Summary"
echo "======================================"
echo ""

echo "Root CA:"
openssl x509 -in root/root-ca.crt -noout -subject -issuer -dates
echo ""

echo "Intermediate CA:"
openssl x509 -in intermediate/intermediate-ca.crt -noout -subject -issuer -dates
echo ""

echo "Server Certificate:"
openssl x509 -in server/server.crt -noout -subject -issuer -dates -ext subjectAltName
echo ""

# ==============================================================================
# Step 6: Instructions
# ==============================================================================
echo "✅ Certificate generation complete!"
echo ""

# ==============================================================================
# Step 7: Auto-install on Arch Linux (optional)
# ==============================================================================

if [ -f /etc/arch-release ]; then
    echo "🐧 Arch Linux detected!"
    echo ""
    read -p "Do you want to install the Root CA to system trust store? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📦 Installing Root CA to system trust store..."
        
        # Create certificate directory if it doesn't exist
        sudo mkdir -p /etc/ca-certificates/trust-source/anchors/
        
        # Copy root CA certificate
        sudo cp root/root-ca.crt /etc/ca-certificates/trust-source/anchors/local-development-root-ca.crt
        
        # Update CA certificates
        sudo trust extract-compat
        
        echo "✓ Root CA installed to system trust store"
        echo "✓ System CA certificates updated"
        echo ""
        echo "🌐 The certificate is now trusted by:"
        echo "   - curl"
        echo "   - wget"
        echo "   - git"
        echo "   - Node.js"
        echo "   - Python requests"
        echo "   - Most system applications"
        echo ""
        echo "⚠️  Note: You may still need to import to Firefox separately:"
        echo "   Firefox → Settings → Privacy & Security → Certificates"
        echo "   → View Certificates → Authorities → Import"
        echo "   → Select: root/root-ca.crt"
        echo ""
    else
        echo "⏭️  Skipped system installation"
        echo ""
    fi
fi

# ==============================================================================
# Step 8: Firefox Certificate Installation Instructions
# ==============================================================================

echo "🦊 Firefox Certificate Installation"
echo "======================================"
echo ""
echo "Firefox uses its own certificate store and needs manual import."
echo ""
echo "📋 Step-by-step instructions:"
echo ""
echo "1. Open Firefox and navigate to:"
echo "   about:preferences#privacy"
echo ""
echo "2. Scroll down to 'Certificates' section"
echo ""
echo "3. Click 'View Certificates' button"
echo ""
echo "4. Go to the 'Authorities' tab"
echo ""
echo "5. Click 'Import' button"
echo ""
echo "6. Navigate to and select:"
echo "   $(pwd)/root/root-ca.crt"
echo ""
echo "7. Check the box:"
echo "   ☑ Trust this CA to identify websites"
echo ""
echo "8. Click 'OK'"
echo ""
echo "9. You should see 'Local Development' → '$ROOT_NAME' in the list"
echo ""
echo "10. Restart Firefox (recommended)"
echo ""
echo "✓ After installation, https://localhost will show a green lock 🔒"
echo ""

echo "📝 Next Steps:"
echo "======================================"
echo ""
echo "1. Install Root CA in your browser (if not done above):"
echo "   - Arch/Linux: sudo cp root/root-ca.crt /etc/ca-certificates/trust-source/anchors/"
echo "                 sudo trust extract-compat"
echo "   - Ubuntu/Debian: sudo cp root/root-ca.crt /usr/local/share/ca-certificates/"
echo "                    sudo update-ca-certificates"
echo "   - macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root/root-ca.crt"
echo "   - Windows: Import root/root-ca.crt to 'Trusted Root Certification Authorities'"
echo "   - Firefox: Preferences → Privacy & Security → Certificates → View Certificates → Import"
echo ""
echo "2. Configure your server with:"
echo "   - Certificate: server/server.crt or server/chain.pem"
echo "   - Private Key: server/server.key"
echo ""
echo "3. For Axum/Rust, update your main.rs:"
echo "   - Use axum-server with tls or rustls"
echo "   - Load: server/chain.pem and server/server.key"
echo ""
echo "4. Access your app at: https://localhost:3000"
echo ""
echo "⚠️  Security Notice:"
echo "   - These certificates are for LOCAL DEVELOPMENT ONLY"
echo "   - Never use in production"
echo "   - Keep private keys secure"
echo "   - Root CA key has absolute trust - protect it!"
echo ""
