#!/bin/bash
# generate_intermediate_ca.sh - Generate an Intermediate CA for signing user certificates

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

echo "=== Intermediate CA Generator ==="
echo
echo "This Intermediate CA will be used ONLY for signing user certificates."
echo

# Prompt for DN information
read -p "Common Name (CN) [e.g., 'MyOrg Intermediate CA']: " CN
read -p "Organization (O): " ORG
read -p "Organizational Unit (OU): " OU
read -p "Country (C) [2-letter code]: " COUNTRY
read -p "State/Province (ST): " STATE
read -p "Locality/City (L): " CITY

# Prompt for validity
read -p "Validity period (years) [default: 10]: " VALIDITY_YEARS
VALIDITY_YEARS=${VALIDITY_YEARS:-10}
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
echo "=== Root CA PFX File (for signing) ==="
read -p "Path to Root CA PFX file: " ROOT_CA_PFX_PATH

# Verify Root CA PFX file exists
if [ ! -f "$ROOT_CA_PFX_PATH" ]; then
    echo "Error: Root CA PFX file not found: $ROOT_CA_PFX_PATH"
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
INTERMEDIATE_CA_PASSWORD="$APP_KEY_HASH"

echo "Intermediate CA password generated from application private key."
echo

# Extract Root CA private key and certificate using derived password
echo "Extracting Root CA certificate and key..."

TEMP_ROOT_KEY=$(mktemp)
TEMP_ROOT_CERT=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_ROOT_KEY $TEMP_ROOT_CERT" EXIT

openssl pkcs12 -in "$ROOT_CA_PFX_PATH" \
    -nocerts -nodes \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$TEMP_ROOT_KEY" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract Root CA private key"
    echo "The Root CA PFX may not use the application key-derived password"
    exit 1
fi

openssl pkcs12 -in "$ROOT_CA_PFX_PATH" \
    -nokeys -clcerts \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$TEMP_ROOT_CERT" 2>/dev/null

echo "Generating Intermediate CA..."

# Auto-generate serial number (random 16-byte hex)
SERIAL=$(openssl rand -hex 16)

# Create output filename based on CN
SAFE_CN=$(echo "$CN" | tr ' ' '_' | tr -cd '[:alnum:]_-')
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

# Generate Intermediate CA private key (4096-bit RSA) with password
echo "Generating Intermediate CA private key..."
openssl genrsa -aes256 -passout "pass:${INTERMEDIATE_CA_PASSWORD}" -out "$OUTPUT_KEY" 4096 2>/dev/null

# Generate CSR for Intermediate CA
echo "Generating certificate signing request..."
openssl req -new -key "$OUTPUT_KEY" \
    -passin "pass:${INTERMEDIATE_CA_PASSWORD}" \
    -out "$OUTPUT_CSR" \
    -subj "$SUBJECT"

# Create OpenSSL config for Intermediate CA extensions
INTER_CA_EXT_CONF=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_ROOT_KEY $TEMP_ROOT_CERT $INTER_CA_EXT_CONF" EXIT

cat > "$INTER_CA_EXT_CONF" <<EOF
[intermediate_ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# Sign the Intermediate CA CSR with Root CA
echo "Signing Intermediate CA certificate with Root CA..."
openssl x509 -req -days "$VALIDITY_DAYS" \
    -in "$OUTPUT_CSR" \
    -CA "$TEMP_ROOT_CERT" \
    -CAkey "$TEMP_ROOT_KEY" \
    -out "$OUTPUT_CRT" \
    -set_serial "0x${SERIAL}" \
    -extfile "$INTER_CA_EXT_CONF" \
    -extensions intermediate_ca_ext

# Export certificate as PEM-formatted .cer file
echo "Exporting certificate to PEM format..."
openssl x509 -in "$OUTPUT_CRT" -out "$OUTPUT_CER" -outform PEM

# Create certificate chain file (Intermediate + Root)
TEMP_CHAIN=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_ROOT_KEY $TEMP_ROOT_CERT $INTER_CA_EXT_CONF $TEMP_CHAIN" EXIT

cat "$OUTPUT_CRT" "$TEMP_ROOT_CERT" > "$TEMP_CHAIN"

# Generate PFX with certificate chain included
echo "Creating Intermediate CA PFX container with Root CA chain..."
openssl pkcs12 -export \
    -out "$OUTPUT_PFX" \
    -inkey "$OUTPUT_KEY" \
    -in "$OUTPUT_CRT" \
    -certfile "$TEMP_ROOT_CERT" \
    -name "$CN" \
    -passin "pass:${INTERMEDIATE_CA_PASSWORD}" \
    -passout "pass:${INTERMEDIATE_CA_PASSWORD}"

# Calculate thumbprint (SHA-256 fingerprint)
THUMBPRINT=$(openssl x509 -in "$OUTPUT_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)

# Clean up intermediate files
rm -f "$OUTPUT_KEY" "$OUTPUT_CSR" "$OUTPUT_CRT" "$TEMP_APP_KEY" "$TEMP_ROOT_KEY" "$TEMP_ROOT_CERT" "$INTER_CA_EXT_CONF" "$TEMP_CHAIN"

echo
echo "=== Intermediate CA Generated Successfully ==="
echo "Intermediate CA PFX file: $OUTPUT_PFX"
echo "Intermediate CA Certificate file: $OUTPUT_CER"
echo "Serial Number: $SERIAL"
echo "Thumbprint (SHA-256): $THUMBPRINT"
echo "Validity: $VALIDITY_DAYS days ($VALIDITY_YEARS years)"
echo "Key Size: 4096-bit RSA"
echo "Path Length Constraint: 0 (can only sign end-user certificates)"
echo
echo "IMPORTANT: This Intermediate CA should be used ONLY for signing user certificates."
echo "The PFX contains the complete chain including the Root CA certificate."
echo "The PFX password is derived from the application private key (SHA-256)."
echo

# Display certificate details
echo "Intermediate CA Certificate Details:"
openssl pkcs12 -in "$OUTPUT_PFX" -nokeys -passin "pass:${INTERMEDIATE_CA_PASSWORD}" | \
    openssl x509 -noout -subject -dates -fingerprint -sha256

echo
echo "Certificate Chain in PFX:"
openssl pkcs12 -in "$OUTPUT_PFX" -nokeys -cacerts -passin "pass:${INTERMEDIATE_CA_PASSWORD}" | \
    openssl x509 -noout -subject 2>/dev/null || echo "(Root CA certificate included)"

echo
echo "Done!"
