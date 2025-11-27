#!/bin/bash
# generate_root_ca.sh - Generate a Root CA for signing intermediate certificates

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

echo "=== Root CA Generator ==="
echo
echo "This Root CA will be used ONLY for signing intermediate certificates."
echo

# Prompt for DN information
read -p "Common Name (CN) [e.g., 'MyOrg Root CA']: " CN
read -p "Organization (O): " ORG
read -p "Organizational Unit (OU): " OU
read -p "Country (C) [2-letter code]: " COUNTRY
read -p "State/Province (ST): " STATE
read -p "Locality/City (L): " CITY

# Prompt for validity
read -p "Validity period (years) [default: 20]: " VALIDITY_YEARS
VALIDITY_YEARS=${VALIDITY_YEARS:-20}
VALIDITY_DAYS=$((VALIDITY_YEARS * 365))

echo
echo "=== Application PFX File (for temporary password generation) ==="
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

# Generate SHA256 hash of the private key for Root CA password
ROOT_CA_PASSWORD=$(openssl dgst -sha256 "$TEMP_APP_KEY" | cut -d' ' -f2)

echo "Root CA password generated from application private key."
echo
echo "Generating Root CA..."

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

# Generate Root CA private key (4096-bit RSA) with password
echo "Generating Root CA private key..."
openssl genrsa -aes256 -passout "pass:${ROOT_CA_PASSWORD}" -out "$OUTPUT_KEY" 4096 2>/dev/null

# Create OpenSSL config for Root CA extensions
CA_EXT_CONF=$(mktemp)
trap "rm -f $TEMP_APP_KEY $CA_EXT_CONF" EXIT

cat > "$CA_EXT_CONF" <<EOF
[root_ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# Generate self-signed Root CA certificate
echo "Generating self-signed Root CA certificate..."
openssl req -new -x509 -days "$VALIDITY_DAYS" \
    -key "$OUTPUT_KEY" \
    -passin "pass:${ROOT_CA_PASSWORD}" \
    -out "$OUTPUT_CRT" \
    -subj "$SUBJECT" \
    -set_serial "0x${SERIAL}" \
    -extensions root_ca_ext \
    -config <(cat "$OPENSSL_CONF" && cat "$CA_EXT_CONF")

# Export certificate as PEM-formatted .cer file
echo "Exporting certificate to PEM format..."
openssl x509 -in "$OUTPUT_CRT" -out "$OUTPUT_CER" -outform PEM

# Generate PFX with the same password
echo "Creating Root CA PFX container..."
openssl pkcs12 -export \
    -out "$OUTPUT_PFX" \
    -inkey "$OUTPUT_KEY" \
    -in "$OUTPUT_CRT" \
    -name "$CN" \
    -passin "pass:${ROOT_CA_PASSWORD}" \
    -passout "pass:${ROOT_CA_PASSWORD}"

# Calculate thumbprint (SHA-256 fingerprint)
THUMBPRINT=$(openssl x509 -in "$OUTPUT_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)

# Clean up intermediate files
rm -f "$OUTPUT_KEY" "$OUTPUT_CSR" "$OUTPUT_CRT" "$TEMP_APP_KEY" "$CA_EXT_CONF"

echo
echo "=== Root CA Generated Successfully ==="
echo "Root CA PFX file: $OUTPUT_PFX"
echo "Root CA Certificate file: $OUTPUT_CER"
echo "Serial Number: $SERIAL"
echo "Thumbprint (SHA-256): $THUMBPRINT"
echo "Validity: $VALIDITY_DAYS days ($VALIDITY_YEARS years)"
echo "Key Size: 4096-bit RSA"
echo
echo "IMPORTANT: This Root CA should be used ONLY for signing intermediate certificates."
echo "The PFX password is derived from the application private key (SHA-256)."
echo "You can change this password later if needed."
echo

# Display certificate details
echo "Root CA Certificate Details:"
openssl pkcs12 -in "$OUTPUT_PFX" -nokeys -passin "pass:${ROOT_CA_PASSWORD}" | \
    openssl x509 -noout -subject -dates -fingerprint -sha256

echo
echo "Done!"
