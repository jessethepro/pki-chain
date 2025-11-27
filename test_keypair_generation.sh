#!/bin/bash
# test_keypair_generation.sh - Test complete PKI chain generation and validation

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

echo "========================================="
echo "   PKI Chain Generation Test Suite"
echo "========================================="
echo

# Prompt for application PFX file
read -p "Path to application PFX file: " APP_PFX_PATH

# Convert to absolute path if relative
if [[ "$APP_PFX_PATH" != /* ]]; then
    APP_PFX_PATH="$(pwd)/$APP_PFX_PATH"
fi

# Verify PFX file exists
if [ ! -f "$APP_PFX_PATH" ]; then
    echo "Error: PFX file not found: $APP_PFX_PATH"
    exit 1
fi

# Secure password input for application PFX
echo "Enter password for application PFX file (will be hidden):"
read -s APP_PFX_PASSWORD

echo
echo "=== Test Configuration ==="
echo "Application PFX: $APP_PFX_PATH"
echo "Number of user certificates: 5"
echo

# Create temporary test directory
TEST_DIR=$(mktemp -d -t pki-test-XXXXXX)
echo "Test directory: $TEST_DIR"
echo

# Cleanup function
cleanup() {
    echo
    echo "=== Cleaning up test files ==="
    rm -rf "$TEST_DIR"
    echo "Test directory removed: $TEST_DIR"
}

trap cleanup EXIT

cd "$TEST_DIR"

# Extract app private key for password derivation
echo "=== Step 1: Extracting application private key ==="
TEMP_APP_KEY="app.key"
openssl pkcs12 -in "$APP_PFX_PATH" \
    -nocerts -nodes \
    -passin "pass:${APP_PFX_PASSWORD}" \
    -out "$TEMP_APP_KEY" 2>&1

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract private key from application PFX"
    echo "Please check the password and PFX file"
    exit 1
fi

APP_KEY_HASH=$(openssl dgst -sha256 "$TEMP_APP_KEY" | cut -d' ' -f2)
echo "✓ Application key extracted and hashed"
echo

# Generate Root CA
echo "=== Step 2: Generating Root CA ==="
ROOT_CA_KEY="RootCA.key"
ROOT_CA_CSR="RootCA.csr"
ROOT_CA_CRT="RootCA.crt"
ROOT_CA_PFX="RootCA.pfx"
ROOT_CA_CER="RootCA.cer"
SERIAL_ROOT=$(openssl rand -hex 16)

SUBJECT_ROOT="/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Security/CN=Test Root CA"

openssl genrsa -aes256 -passout "pass:${APP_KEY_HASH}" -out "$ROOT_CA_KEY" 4096 2>/dev/null
echo "✓ Root CA private key generated"

CA_EXT_CONF="root_ca_ext.conf"
cat > "$CA_EXT_CONF" <<EOF
[root_ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -new -x509 -days 7300 \
    -key "$ROOT_CA_KEY" \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$ROOT_CA_CRT" \
    -subj "$SUBJECT_ROOT" \
    -set_serial "0x${SERIAL_ROOT}" \
    -extensions root_ca_ext \
    -config <(cat "$OPENSSL_CONF" && cat "$CA_EXT_CONF") 2>/dev/null

echo "✓ Root CA certificate generated (20 years)"

openssl x509 -in "$ROOT_CA_CRT" -out "$ROOT_CA_CER" -outform PEM

openssl pkcs12 -export \
    -out "$ROOT_CA_PFX" \
    -inkey "$ROOT_CA_KEY" \
    -in "$ROOT_CA_CRT" \
    -name "Test Root CA" \
    -passin "pass:${APP_KEY_HASH}" \
    -passout "pass:${APP_KEY_HASH}" 2>/dev/null

echo "✓ Root CA PFX created"
ROOT_THUMBPRINT=$(openssl x509 -in "$ROOT_CA_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)
echo "  Thumbprint: $ROOT_THUMBPRINT"
echo

# Generate Intermediate CA
echo "=== Step 3: Generating Intermediate CA ==="
INTER_CA_KEY="IntermediateCA.key"
INTER_CA_CSR="IntermediateCA.csr"
INTER_CA_CRT="IntermediateCA.crt"
INTER_CA_PFX="IntermediateCA.pfx"
INTER_CA_CER="IntermediateCA.cer"
SERIAL_INTER=$(openssl rand -hex 16)

SUBJECT_INTER="/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Security/CN=Test Intermediate CA"

openssl genrsa -aes256 -passout "pass:${APP_KEY_HASH}" -out "$INTER_CA_KEY" 4096 2>/dev/null
echo "✓ Intermediate CA private key generated"

openssl req -new -key "$INTER_CA_KEY" \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$INTER_CA_CSR" \
    -subj "$SUBJECT_INTER" 2>/dev/null

INTER_CA_EXT_CONF="inter_ca_ext.conf"
cat > "$INTER_CA_EXT_CONF" <<EOF
[intermediate_ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl x509 -req -days 3650 \
    -in "$INTER_CA_CSR" \
    -CA "$ROOT_CA_CRT" \
    -CAkey "$ROOT_CA_KEY" \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$INTER_CA_CRT" \
    -set_serial "0x${SERIAL_INTER}" \
    -extfile "$INTER_CA_EXT_CONF" \
    -extensions intermediate_ca_ext 2>/dev/null

echo "✓ Intermediate CA certificate signed by Root CA (10 years)"

openssl x509 -in "$INTER_CA_CRT" -out "$INTER_CA_CER" -outform PEM

openssl pkcs12 -export \
    -out "$INTER_CA_PFX" \
    -inkey "$INTER_CA_KEY" \
    -in "$INTER_CA_CRT" \
    -certfile "$ROOT_CA_CRT" \
    -name "Test Intermediate CA" \
    -passin "pass:${APP_KEY_HASH}" \
    -passout "pass:${APP_KEY_HASH}" 2>/dev/null

echo "✓ Intermediate CA PFX created with Root CA chain"
INTER_THUMBPRINT=$(openssl x509 -in "$INTER_CA_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)
echo "  Thumbprint: $INTER_THUMBPRINT"
echo

# Generate User Certificates
echo "=== Step 4: Generating 5 User Certificates ==="

USER_NAMES=("Alice Smith" "Bob Johnson" "Carol Williams" "David Brown" "Eve Davis")
USER_EMAILS=("alice@test.com" "bob@test.com" "carol@test.com" "david@test.com" "eve@test.com")

for i in {0..4}; do
    USER_NAME="${USER_NAMES[$i]}"
    USER_EMAIL="${USER_EMAILS[$i]}"
    USER_SAFE=$(echo "$USER_NAME" | tr ' ' '_')
    
    echo "  Generating certificate for: $USER_NAME ($USER_EMAIL)"
    
    USER_KEY="${USER_SAFE}.key"
    USER_CSR="${USER_SAFE}.csr"
    USER_CRT="${USER_SAFE}.crt"
    USER_PFX="${USER_SAFE}.pfx"
    USER_CER="${USER_SAFE}.cer"
    SERIAL_USER=$(openssl rand -hex 16)
    
    SUBJECT_USER="/C=US/ST=California/L=San Francisco/O=Test Organization/OU=Users/CN=${USER_NAME}/emailAddress=${USER_EMAIL}"
    
    openssl genrsa -aes256 -passout "pass:${APP_KEY_HASH}" -out "$USER_KEY" 4096 2>/dev/null
    
    openssl req -new -key "$USER_KEY" \
        -passin "pass:${APP_KEY_HASH}" \
        -out "$USER_CSR" \
        -subj "$SUBJECT_USER" 2>/dev/null
    
    USER_EXT_CONF="${USER_SAFE}_ext.conf"
    cat > "$USER_EXT_CONF" <<EOF
[user_cert_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = email:${USER_EMAIL}
EOF
    
    openssl x509 -req -days 365 \
        -in "$USER_CSR" \
        -CA "$INTER_CA_CRT" \
        -CAkey "$INTER_CA_KEY" \
        -passin "pass:${APP_KEY_HASH}" \
        -out "$USER_CRT" \
        -set_serial "0x${SERIAL_USER}" \
        -extfile "$USER_EXT_CONF" \
        -extensions user_cert_ext 2>/dev/null
    
    openssl x509 -in "$USER_CRT" -out "$USER_CER" -outform PEM
    
    CHAIN_FILE="${USER_SAFE}_chain.pem"
    cat "$INTER_CA_CRT" "$ROOT_CA_CRT" > "$CHAIN_FILE"
    
    openssl pkcs12 -export \
        -out "$USER_PFX" \
        -inkey "$USER_KEY" \
        -in "$USER_CRT" \
        -certfile "$CHAIN_FILE" \
        -name "$USER_NAME" \
        -passin "pass:${APP_KEY_HASH}" \
        -passout "pass:${APP_KEY_HASH}" 2>/dev/null
    
    USER_THUMBPRINT=$(openssl x509 -in "$USER_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)
    echo "    ✓ ${USER_NAME}: $USER_THUMBPRINT"
done

echo

# Validate Certificates
echo "=== Step 5: Validating Certificate Chain ==="

# Validate Root CA is self-signed
echo "  Testing Root CA self-signature..."
openssl verify -CAfile "$ROOT_CA_CRT" "$ROOT_CA_CRT" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    ✓ Root CA self-signature valid"
else
    echo "    ✗ Root CA self-signature FAILED"
    exit 1
fi

# Validate Intermediate CA against Root CA
echo "  Testing Intermediate CA signature..."
openssl verify -CAfile "$ROOT_CA_CRT" "$INTER_CA_CRT" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    ✓ Intermediate CA signed by Root CA"
else
    echo "    ✗ Intermediate CA signature FAILED"
    exit 1
fi

# Create chain file for user validation
CA_CHAIN="ca_chain.pem"
cat "$INTER_CA_CRT" "$ROOT_CA_CRT" > "$CA_CHAIN"

# Validate each user certificate
for i in {0..4}; do
    USER_NAME="${USER_NAMES[$i]}"
    USER_SAFE=$(echo "$USER_NAME" | tr ' ' '_')
    USER_CRT="${USER_SAFE}.crt"
    
    openssl verify -CAfile "$CA_CHAIN" "$USER_CRT" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "    ✓ ${USER_NAME} certificate valid"
    else
        echo "    ✗ ${USER_NAME} certificate FAILED"
        exit 1
    fi
done

echo

# Test PFX password access
echo "=== Step 6: Testing PFX Password Access ==="

echo "  Testing Root CA PFX..."
openssl pkcs12 -in "$ROOT_CA_PFX" -nokeys -passin "pass:${APP_KEY_HASH}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    ✓ Root CA PFX password correct"
else
    echo "    ✗ Root CA PFX password FAILED"
    exit 1
fi

echo "  Testing Intermediate CA PFX..."
openssl pkcs12 -in "$INTER_CA_PFX" -nokeys -passin "pass:${APP_KEY_HASH}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    ✓ Intermediate CA PFX password correct"
else
    echo "    ✗ Intermediate CA PFX password FAILED"
    exit 1
fi

for i in {0..4}; do
    USER_NAME="${USER_NAMES[$i]}"
    USER_SAFE=$(echo "$USER_NAME" | tr ' ' '_')
    USER_PFX="${USER_SAFE}.pfx"
    
    openssl pkcs12 -in "$USER_PFX" -nokeys -passin "pass:${APP_KEY_HASH}" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "    ✓ ${USER_NAME} PFX password correct"
    else
        echo "    ✗ ${USER_NAME} PFX password FAILED"
        exit 1
    fi
done

echo

# Test password change functionality
echo "=== Step 7: Testing Password Change ==="

# Change password for Carol Williams (index 2)
TEST_USER="Carol Williams"
TEST_USER_SAFE=$(echo "$TEST_USER" | tr ' ' '_')
TEST_USER_PFX="${TEST_USER_SAFE}.pfx"
NEW_PASSWORD="NewSecurePassword123!"

echo "  Changing password for: $TEST_USER"

# Extract to PEM with current password
TEMP_PEM=$(mktemp)
openssl pkcs12 -in "$TEST_USER_PFX" \
    -passin "pass:${APP_KEY_HASH}" \
    -out "$TEMP_PEM" \
    -nodes 2>/dev/null

if [ $? -ne 0 ]; then
    echo "    ✗ Failed to extract PFX for password change"
    rm -f "$TEMP_PEM"
    exit 1
fi

# Re-create PFX with new password
TEMP_NEW_PFX=$(mktemp)
openssl pkcs12 -export \
    -in "$TEMP_PEM" \
    -out "$TEMP_NEW_PFX" \
    -name "$TEST_USER" \
    -passout "pass:${NEW_PASSWORD}" 2>/dev/null

if [ $? -ne 0 ]; then
    echo "    ✗ Failed to create PFX with new password"
    rm -f "$TEMP_PEM" "$TEMP_NEW_PFX"
    exit 1
fi

# Replace original with new
mv "$TEMP_NEW_PFX" "$TEST_USER_PFX"
rm -f "$TEMP_PEM"

echo "    ✓ Password changed successfully"

# Test old password fails
echo "  Verifying old password no longer works..."
set +e  # Temporarily disable exit on error
openssl pkcs12 -in "$TEST_USER_PFX" -nokeys -passin "pass:${APP_KEY_HASH}" > /dev/null 2>&1
OLD_PW_RESULT=$?
set -e  # Re-enable exit on error
if [ $OLD_PW_RESULT -eq 0 ]; then
    echo "    ✗ Old password still works (should fail)"
    exit 1
else
    echo "    ✓ Old password correctly rejected"
fi

# Test new password works
echo "  Verifying new password works..."
openssl pkcs12 -in "$TEST_USER_PFX" -nokeys -passin "pass:${NEW_PASSWORD}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "    ✓ New password accepted"
else
    echo "    ✗ New password FAILED"
    exit 1
fi

# Verify certificate content is intact
echo "  Verifying certificate integrity after password change..."
CHANGED_THUMBPRINT=$(openssl pkcs12 -in "$TEST_USER_PFX" -nokeys -passin "pass:${NEW_PASSWORD}" | \
    openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d'=' -f2)

ORIGINAL_CRT="${TEST_USER_SAFE}.crt"
ORIGINAL_THUMBPRINT=$(openssl x509 -in "$ORIGINAL_CRT" -noout -fingerprint -sha256 | cut -d'=' -f2)

if [ "$CHANGED_THUMBPRINT" == "$ORIGINAL_THUMBPRINT" ]; then
    echo "    ✓ Certificate integrity preserved"
else
    echo "    ✗ Certificate integrity compromised"
    exit 1
fi

echo

# Display summary
echo "========================================="
echo "   Test Summary"
echo "========================================="
echo
echo "✓ Root CA generated and validated"
echo "✓ Intermediate CA generated and validated"
echo "✓ 5 user certificates generated and validated"
echo "✓ All certificate chains validated"
echo "✓ All PFX passwords verified"
echo "✓ Password change tested and verified"
echo
echo "All tests PASSED!"
echo
echo "Test files location: $TEST_DIR"
echo "Files will be deleted on exit."
echo
