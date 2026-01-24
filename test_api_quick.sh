#!/bin/bash
# Quick API Test Script
# Usage: ./test_api_quick.sh <cert.crt> <key.key>

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <certificate.crt> <private_key.key>"
    echo "Example: $0 admin@example.com.crt admin@example.com.key"
    exit 1
fi

CERT_FILE="$1"
KEY_FILE="$2"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}PKI Chain API Quick Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Extract serial number
echo -e "${GREEN}[1/4] Extracting certificate serial...${NC}"
SERIAL=$(openssl x509 -in "$CERT_FILE" -noout -serial | cut -d= -f2)
echo "Serial: $SERIAL"
echo ""

# Test 1: Get Root CA certificate
echo -e "${GREEN}[2/4] Testing Get Certificate API...${NC}"
TARGET_CN="MenaceLabs Root CA"
echo "Target: $TARGET_CN"

# Sign the target CN
SIGNATURE=$(echo -n "$TARGET_CN" | openssl dgst -sha256 -sign "$KEY_FILE" | base64 -w 0)

# Send request
RESPONSE=$(curl -k -s -X POST https://127.0.0.1:3000/api/get-certificate \
    -H "Content-Type: application/json" \
    -d "{
        \"requester_serial\": \"$SERIAL\",
        \"target_cn\": \"$TARGET_CN\",
        \"signature\": \"$SIGNATURE\"
    }")

echo "$RESPONSE" | jq .

# Extract serial from response for next test
TARGET_SERIAL=$(echo "$RESPONSE" | jq -r '.serial_number // empty')

if [ -z "$TARGET_SERIAL" ]; then
    echo -e "${RED}Failed to get certificate - check authentication${NC}"
    exit 1
fi
echo ""

# Test 2: Verify the certificate we just retrieved
echo -e "${GREEN}[3/4] Testing Verify Certificate API...${NC}"
echo "Target Serial: $TARGET_SERIAL"

# Sign the target serial
SIGNATURE=$(echo -n "$TARGET_SERIAL" | openssl dgst -sha256 -sign "$KEY_FILE" | base64 -w 0)

# Send request
curl -k -s -X POST https://127.0.0.1:3000/api/verify-certificate \
    -H "Content-Type: application/json" \
    -d "{
        \"requester_serial\": \"$SERIAL\",
        \"target_serial\": \"$TARGET_SERIAL\",
        \"signature\": \"$SIGNATURE\"
    }" | jq .

echo ""
echo -e "${GREEN}[4/4] Tests completed!${NC}"
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}API Endpoints Available:${NC}"
echo -e "${BLUE}========================================${NC}"
echo "POST /api/get-certificate"
echo "  - Get certificate by Common Name"
echo "  - Returns certificate PEM and metadata"
echo ""
echo "POST /api/verify-certificate"
echo "  - Verify certificate validity"
echo "  - Returns validity status and dates"
echo ""
echo -e "${BLUE}Authentication Required:${NC}"
echo "  - Certificate serial number (hex)"
echo "  - Cryptographic signature (base64)"
echo "  - Only non-revoked certificates allowed"
echo ""
echo -e "${BLUE}Response Integrity:${NC}"
echo "  - Encrypted hash with RSA-OAEP"
echo "  - Hash computed from response fields"
echo "  - Verify with your private key"
echo -e "${BLUE}========================================${NC}"
