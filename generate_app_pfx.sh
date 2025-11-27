#!/bin/bash
# generate_app_pfx - Generate a key pair for encryption and signing in .pfx format

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

echo "=== PFX Certificate Generator ==="
echo

# Prompt for DN information
read -p "Common Name (CN): " CN
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

# Secure password input
echo
echo "Enter password for PFX file (will be hidden):"
read -s PASSWORD
echo "Confirm password:"
read -s PASSWORD_CONFIRM

if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
    echo "Error: Passwords do not match"
    exit 1
fi

if [ -z "$PASSWORD" ]; then
    echo "Error: Password cannot be empty"
    exit 1
fi

echo
echo "Generating certificate..."

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
[ -n "$EMAIL" ] && SUBJECT="${SUBJECT}/emailAddress=${EMAIL}"

# Generate private key (4096-bit RSA)
echo "Generating RSA private key..."
openssl genrsa -out "$OUTPUT_KEY" 4096 2>/dev/null

# Generate CSR
echo "Generating certificate signing request..."
openssl req -new -key "$OUTPUT_KEY" -out "$OUTPUT_CSR" -subj "$SUBJECT"

# Generate self-signed certificate with both signing and encryption capabilities
echo "Generating self-signed certificate..."

# Build extensions config
EXT_CONFIG="keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth, emailProtection, codeSigning"
[ -n "$EMAIL" ] && EXT_CONFIG="${EXT_CONFIG}
subjectAltName = email:${EMAIL}"

openssl x509 -req -days "$VALIDITY_DAYS" \
    -in "$OUTPUT_CSR" \
    -signkey "$OUTPUT_KEY" \
    -out "$OUTPUT_CRT" \
    -set_serial "0x${SERIAL}" \
    -extfile <(echo "$EXT_CONFIG") 2>/dev/null

# Generate PFX with password
echo "Creating PFX container..."
openssl pkcs12 -export \
    -out "$OUTPUT_PFX" \
    -inkey "$OUTPUT_KEY" \
    -in "$OUTPUT_CRT" \
    -name "$CN" \
    -password "pass:${PASSWORD}"

# Export certificate as PEM-formatted .cer file
echo "Exporting certificate to PEM format..."
openssl x509 -in "$OUTPUT_CRT" -out "$OUTPUT_CER" -outform PEM

# Calculate thumbprint (SHA-1 fingerprint)
THUMBPRINT=$(openssl x509 -in "$OUTPUT_CRT" -noout -fingerprint -sha1 | cut -d'=' -f2)

# Clean up intermediate files
rm -f "$OUTPUT_KEY" "$OUTPUT_CSR" "$OUTPUT_CRT"

echo
echo "=== Certificate Generated Successfully ==="
echo "PFX file: $OUTPUT_PFX"
echo "Certificate file: $OUTPUT_CER"
echo "Serial Number: $SERIAL"
echo "Thumbprint (SHA-1): $THUMBPRINT"
echo "Validity: $VALIDITY_DAYS days ($VALIDITY_YEARS years)"
echo "Key Size: 4096-bit RSA"
echo

# Display certificate details
echo "Certificate Details:"
openssl pkcs12 -in "$OUTPUT_PFX" -nokeys -passin "pass:${PASSWORD}" | \
    openssl x509 -noout -subject -dates -fingerprint

echo
echo "Done!"
