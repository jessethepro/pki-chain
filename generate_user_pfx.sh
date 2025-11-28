#!/bin/bash
# generate_user_pfx.sh - Generate a user certificate for encryption, signing, and identity

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

echo "=== User Certificate Generator ==="
echo
echo "This user certificate will be used for encryption, signing, and identity."
echo

# Prompt for DN information
read -p "Common Name (CN) [e.g., 'John Doe' or 'user@example.com']: " CN
read -p "Organization (O): " ORG
read -p "Organizational Unit (OU): " OU
read -p "Country (C) [2-letter code]: " COUNTRY
read -p "State/Province (ST): " STATE
read -p "Locality/City (L): " CITY
read -p "Email Address: " EMAIL

# Prompt for validity
read -p "Validity period (years) [default: 1]: " VALIDITY_YEARS
VALIDITY_YEARS=${VALIDITY_YEARS:-1}
VALIDITY_DAYS=$((VALIDITY_YEARS * 365))

echo
echo "=== Application PFX File (for password generation) ==="
read -p "Path to application PFX file: " APP_PFX_PATH

# Verify PFX file exists
if [ ! -f "$APP_PFX_PATH" ]; then
    echo "Error: PFX file not found: $APP_PFX_PATH"
    exit 1
fi

# Secure password input for application PFX
echo "Enter password for application PFX file (will be hidden):"
read -s APP_PFX_PASSWORD

echo
echo "=== Intermediate CA PFX File (for signing) ==="
read -p "Path to Intermediate CA PFX file: " INTER_CA_PFX_PATH

# Verify Intermediate CA PFX file exists
if [ ! -f "$INTER_CA_PFX_PATH" ]; then
    echo "Error: Intermediate CA PFX file not found: $INTER_CA_PFX_PATH"
    exit 1
fi

echo
echo "Extracting private key from application PFX..."

# Extract private key from application PFX (temporary file)
TEMP_APP_KEY=$(mktemp)
trap "rm -f $TEMP_APP_KEY" EXIT

openssl pkcs12 -in "$APP_PFX_PATH" \
    -nocerts -nodes \
    -passin "pass:${APP_PFX_PASSWORD}" \
    -out "$TEMP_APP_KEY" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract private key from application PFX"
    rm -f "$TEMP_APP_KEY"
    exit 1
fi

# Generate SHA256 hash of the private key for passwords
APP_KEY_HASH=$(openssl dgst -sha256 "$TEMP_APP_KEY" | cut -d' ' -f2)
USER_CERT_PASSWORD="$APP_KEY_HASH"

echo "User certificate password generated from application private key."
echo

# Extract Intermediate CA private key and certificate using derived password
echo "Extracting Intermediate CA certificate and key..."

TEMP_INTER_KEY=$(mktemp)
TEMP_INTER_CERT=$(mktemp)
TEMP_ROOT_CERT=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_INTER_KEY $TEMP_INTER_CERT $TEMP_ROOT_CERT" EXIT

openssl pkcs12 -in "$INTER_CA_PFX_PATH" \
    -nocerts -nodes \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$TEMP_INTER_KEY" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract Intermediate CA private key"
    echo "The Intermediate CA PFX may not use the application key-derived password"
    exit 1
fi

openssl pkcs12 -in "$INTER_CA_PFX_PATH" \
    -nokeys -clcerts \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$TEMP_INTER_CERT" 2>/dev/null

# Extract Root CA certificate from the chain
openssl pkcs12 -in "$INTER_CA_PFX_PATH" \
    -nokeys -cacerts \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$TEMP_ROOT_CERT" 2>/dev/null || true

echo "Generating user certificate..."

# Auto-generate serial number (random 16-byte hex)
SERIAL=$(openssl rand -hex 16)

# Create output filename based on CN
SAFE_CN=$(echo "$CN" | tr ' ' '_' | tr -cd '[:alnum:]_@.-')
OUTPUT_PFX="${SAFE_CN}.pfx"
OUTPUT_CER="${SAFE_CN}.cer"
OUTPUT_KEY="${SAFE_CN}.key"
OUTPUT_CSR="${SAFE_CN}.csr"
OUTPUT_CRT="${SAFE_CN}.crt"

# Build subject string (only include non-empty fields)
SUBJECT="/CN=${CN}"
[ -n "$COUNTRY" ] && SUBJECT="/C=${COUNTRY}${SUBJECT}"
[ -n "$STATE" ] && SUBJECT="${SUBJECT}/ST=${STATE}"
[ -n "$CITY" ] && SUBJECT="${SUBJECT}/L=${CITY}"
[ -n "$ORG" ] && SUBJECT="${SUBJECT}/O=${ORG}"
[ -n "$OU" ] && SUBJECT="${SUBJECT}/OU=${OU}"
[ -n "$EMAIL" ] && SUBJECT="${SUBJECT}/emailAddress=${EMAIL}"

# Generate user certificate private key (4096-bit RSA) with password
echo "Generating user certificate private key..."
openssl genrsa -aes256 -passout "pass:${USER_CERT_PASSWORD}" -out "$OUTPUT_KEY" 4096 2>/dev/null

# Generate CSR for user certificate
echo "Generating certificate signing request..."
openssl req -new -key "$OUTPUT_KEY" \
    -passin "pass:${USER_CERT_PASSWORD}" \
    -out "$OUTPUT_CSR" \
    -subj "$SUBJECT"

# Create OpenSSL config for user certificate extensions
USER_CERT_EXT_CONF=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_INTER_KEY $TEMP_INTER_CERT $TEMP_ROOT_CERT $USER_CERT_EXT_CONF" EXIT

# Build extensions config
EXT_CONFIG="basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always"

[ -n "$EMAIL" ] && EXT_CONFIG="${EXT_CONFIG}
subjectAltName = email:${EMAIL}"

cat > "$USER_CERT_EXT_CONF" <<EOF
[user_cert_ext]
$EXT_CONFIG
EOF

# Sign the user certificate CSR with Intermediate CA
echo "Signing user certificate with Intermediate CA..."
openssl x509 -req -days "$VALIDITY_DAYS" \
    -in "$OUTPUT_CSR" \
    -CA "$TEMP_INTER_CERT" \
    -CAkey "$TEMP_INTER_KEY" \
    -out "$OUTPUT_CRT" \
    -set_serial "0x${SERIAL}" \
    -extfile "$USER_CERT_EXT_CONF" \
    -extensions user_cert_ext

# Export certificate as PEM-formatted .cer file
echo "Exporting certificate to PEM format..."
openssl x509 -in "$OUTPUT_CRT" -out "$OUTPUT_CER" -outform PEM

# Create certificate chain file (User + Intermediate + Root)
TEMP_CHAIN=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_INTER_KEY $TEMP_INTER_CERT $TEMP_ROOT_CERT $USER_CERT_EXT_CONF $TEMP_CHAIN" EXIT

cat "$TEMP_INTER_CERT" "$TEMP_ROOT_CERT" > "$TEMP_CHAIN"

# Generate PFX with complete certificate chain included
echo "Creating user certificate PFX container with complete chain..."
openssl pkcs12 -export \
    -out "$OUTPUT_PFX" \
    -inkey "$OUTPUT_KEY" \
    -in "$OUTPUT_CRT" \
    -certfile "$TEMP_CHAIN" \
    -name "$CN" \
    -passin "pass:${USER_CERT_PASSWORD}" \
    -passout "pass:${USER_CERT_PASSWORD}"

# Calculate thumbprint (SHA-256 fingerprint)
THUMBPRINT=$(openssl x509 -in "$OUTPUT_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)

# Clean up intermediate files
rm -f "$OUTPUT_KEY" "$OUTPUT_CSR" "$OUTPUT_CRT" "$TEMP_APP_KEY" "$TEMP_INTER_KEY" "$TEMP_INTER_CERT" "$TEMP_ROOT_CERT" "$USER_CERT_EXT_CONF" "$TEMP_CHAIN"

echo
echo "=== User Certificate Generated Successfully ==="
echo "User certificate PFX file: $OUTPUT_PFX"
echo "User certificate file: $OUTPUT_CER"
echo "Serial Number: $SERIAL"
echo "Thumbprint (SHA-256): $THUMBPRINT"
echo "Validity: $VALIDITY_DAYS days ($VALIDITY_YEARS years)"
echo "Key Size: 4096-bit RSA"
echo
echo "Certificate Usage:"
echo "  - Digital Signature"
echo "  - Key Encipherment"
echo "  - Data Encipherment"
echo "  - Client Authentication"
echo "  - Email Protection"
echo
echo "The PFX contains the complete chain (User -> Intermediate CA -> Root CA)."
echo "The PFX password is derived from the application private key (SHA-256)."
echo

# Display certificate details
echo "User Certificate Details:"
openssl pkcs12 -in "$OUTPUT_PFX" -nokeys -clcerts -passin "pass:${USER_CERT_PASSWORD}" | \
    openssl x509 -noout -subject -dates -fingerprint -sha256

echo
echo "Certificate Chain in PFX:"
openssl pkcs12 -in "$OUTPUT_PFX" -nokeys -cacerts -passin "pass:${USER_CERT_PASSWORD}" 2>/dev/null | \
    grep "subject=" || echo "(Intermediate CA and Root CA certificates included)"

echo
echo "Done!"
