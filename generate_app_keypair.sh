#!/bin/bash
# generate_app_keypair.sh - Generate application keypair (unencrypted) with self-signed certificate

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

# Configuration variables
CN="${CN:-PKI Chain App}"
ORG="${ORG:-MyOrganization}"
OU="${OU:-IT}"
COUNTRY="${COUNTRY:-US}"
STATE="${STATE:-}"
CITY="${CITY:-}"
EMAIL="${EMAIL:-}"
VALIDITY_YEARS="${VALIDITY_YEARS:-10}"
PASSWORD="${PASSWORD:-}"

echo "=== Application Keypair Generator ==="
echo

# Use provided values or prompt if not set
if [ -z "$CN" ] || [ "$CN" = "PKI Chain App" ]; then
    read -p "Common Name (CN) [default: PKI Chain App]: " CN_INPUT
    CN="${CN_INPUT:-PKI Chain App}"
fi

if [ -z "$ORG" ] || [ "$ORG" = "MyOrganization" ]; then
    read -p "Organization (O) [default: MyOrganization]: " ORG_INPUT
    ORG="${ORG_INPUT:-MyOrganization}"
fi

if [ -z "$OU" ] || [ "$OU" = "IT" ]; then
    read -p "Organizational Unit (OU) [default: IT]: " OU_INPUT
    OU="${OU_INPUT:-IT}"
fi

if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "US" ]; then
    read -p "Country (C) [default: US]: " COUNTRY_INPUT
    COUNTRY="${COUNTRY_INPUT:-US}"
fi

if [ -z "$STATE" ]; then
    read -p "State/Province (ST) [optional]: " STATE
fi

if [ -z "$CITY" ]; then
    read -p "Locality/City (L) [optional]: " CITY
fi

if [ -z "$EMAIL" ]; then
    read -p "Email Address [optional]: " EMAIL
fi

if [ "$VALIDITY_YEARS" = "10" ]; then
    read -p "Validity period (years) [default: 10]: " VALIDITY_INPUT
    VALIDITY_YEARS="${VALIDITY_INPUT:-10}"
fi

VALIDITY_DAYS=$((VALIDITY_YEARS * 365))

echo
echo "Generating application keypair..."

# Auto-generate serial number (random 16-byte hex)
SERIAL=$(openssl rand -hex 16)

# Create output filenames
OUTPUT_KEY="pki-chain-app.key"
OUTPUT_CRT="pki-chain-app.crt"

# Build subject string (only include non-empty fields)
SUBJECT="/CN=${CN}"
[ -n "$COUNTRY" ] && SUBJECT="/C=${COUNTRY}${SUBJECT}"
[ -n "$STATE" ] && SUBJECT="${SUBJECT}/ST=${STATE}"
[ -n "$CITY" ] && SUBJECT="${SUBJECT}/L=${CITY}"
[ -n "$ORG" ] && SUBJECT="${SUBJECT}/O=${ORG}"
[ -n "$OU" ] && SUBJECT="${SUBJECT}/OU=${OU}"
[ -n "$EMAIL" ] && SUBJECT="${SUBJECT}/emailAddress=${EMAIL}"

# Create OpenSSL extensions config
EXT_CONF=$(mktemp)
trap "rm -f $EXT_CONF" EXIT

cat > "$EXT_CONF" <<EOF
[app_cert_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth, emailProtection, codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# Add email to SAN if provided
if [ -n "$EMAIL" ]; then
    echo "subjectAltName = email:${EMAIL}" >> "$EXT_CONF"
fi

# Generate unencrypted private key (4096-bit RSA)
echo "Generating RSA private key (4096-bit, unencrypted)..."
openssl genrsa -out "$OUTPUT_KEY" 4096 2>/dev/null

# Generate self-signed certificate
echo "Generating self-signed X.509 certificate..."
openssl req -new -x509 -days "$VALIDITY_DAYS" \
    -key "$OUTPUT_KEY" \
    -out "$OUTPUT_CRT" \
    -subj "$SUBJECT" \
    -set_serial "0x${SERIAL}" \
    -extensions app_cert_ext \
    -config <(cat "$OPENSSL_CONF" && cat "$EXT_CONF")

# Calculate thumbprint (SHA-256 fingerprint)
THUMBPRINT=$(openssl x509 -in "$OUTPUT_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)

echo
echo "=== Application Keypair Generated Successfully ==="
echo "Private key file: $OUTPUT_KEY (UNENCRYPTED - keep secure!)"
echo "Certificate file: $OUTPUT_CRT"
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
echo "  - Code Signing"
echo

# Display certificate details
echo "Certificate Details:"
openssl x509 -in "$OUTPUT_CRT" -noout -subject -dates -fingerprint -sha256

echo
echo "⚠️  WARNING: Private key is NOT password-protected!"
echo "IMPORTANT: Keep $OUTPUT_KEY secure with restrictive file permissions!"
echo "Done!"
