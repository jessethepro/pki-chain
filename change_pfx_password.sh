#!/bin/bash
# change_pfx_password.sh - Change the password of a PFX file using app PFX for authentication

set -e

# Set OpenSSL config file location
export OPENSSL_CONF=/etc/ssl/openssl.cnf

echo "=== PFX Password Changer ==="
echo

# Check if correct number of arguments provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <app_pfx_file> <target_pfx_file>"
    echo
    echo "  app_pfx_file    - Application PFX file for authentication"
    echo "  target_pfx_file - PFX file whose password will be changed"
    exit 1
fi

APP_PFX_PATH="$1"
TARGET_PFX_PATH="$2"

# Verify both PFX files exist
if [ ! -f "$APP_PFX_PATH" ]; then
    echo "Error: Application PFX file not found: $APP_PFX_PATH"
    exit 1
fi

if [ ! -f "$TARGET_PFX_PATH" ]; then
    echo "Error: Target PFX file not found: $TARGET_PFX_PATH"
    exit 1
fi

# Prompt for application PFX password
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

# Generate SHA256 hash of the app private key (current password for target PFX)
CURRENT_PASSWORD=$(openssl dgst -sha256 "$TEMP_APP_KEY" | cut -d' ' -f2)

echo "Current password derived from application private key."
echo

# Prompt for new password
echo "Enter NEW password for target PFX file (will be hidden):"
read -s NEW_PASSWORD
echo "Confirm NEW password:"
read -s NEW_PASSWORD_CONFIRM

if [ "$NEW_PASSWORD" != "$NEW_PASSWORD_CONFIRM" ]; then
    echo "Error: Passwords do not match"
    exit 1
fi

if [ -z "$NEW_PASSWORD" ]; then
    echo "Error: Password cannot be empty"
    exit 1
fi

echo
echo "Changing password for $TARGET_PFX_PATH..."

# Create temporary files for the conversion
TEMP_PEM=$(mktemp)
TEMP_NEW_PFX=$(mktemp)
trap "rm -f $TEMP_APP_KEY $TEMP_PEM $TEMP_NEW_PFX" EXIT

# Extract everything from target PFX with current password
openssl pkcs12 -in "$TARGET_PFX_PATH" \
    -passin "pass:${CURRENT_PASSWORD}" \
    -out "$TEMP_PEM" \
    -nodes 2>/dev/null

if [ $? -ne 0 ]; then
    echo "Error: Failed to decrypt target PFX with derived password"
    echo "The target PFX may not have been created with the current application key"
    exit 1
fi

# Get friendly name from original PFX (if any)
FRIENDLY_NAME=$(openssl pkcs12 -in "$TARGET_PFX_PATH" \
    -passin "pass:${CURRENT_PASSWORD}" \
    -info -nokeys -nocerts 2>/dev/null | \
    grep "friendlyName:" | sed 's/.*friendlyName: //' || echo "")

# Re-create PFX with new password
if [ -n "$FRIENDLY_NAME" ]; then
    openssl pkcs12 -export \
        -in "$TEMP_PEM" \
        -out "$TEMP_NEW_PFX" \
        -name "$FRIENDLY_NAME" \
        -passout "pass:${NEW_PASSWORD}"
else
    openssl pkcs12 -export \
        -in "$TEMP_PEM" \
        -out "$TEMP_NEW_PFX" \
        -passout "pass:${NEW_PASSWORD}"
fi

# Replace original file with new one
mv "$TEMP_NEW_PFX" "$TARGET_PFX_PATH"

echo
echo "=== Password Changed Successfully ==="
echo "PFX file: $TARGET_PFX_PATH"
echo "The password has been updated."
echo

# Verify new password works
echo "Verifying new password..."
openssl pkcs12 -in "$TARGET_PFX_PATH" -nokeys -passin "pass:${NEW_PASSWORD}" | \
    openssl x509 -noout -subject -fingerprint -sha256

echo
echo "Done!"
