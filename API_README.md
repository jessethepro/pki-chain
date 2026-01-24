# PKI Chain REST API Documentation

## Overview

The PKI Chain API provides secure access to certificate management operations. All API endpoints require authentication using X.509 certificates and cryptographic signatures.

**Base URL**: `https://127.0.0.1:3000/api`

## Authentication

All API requests must include:

1. **Requester Serial Number**: Hex string of the requester's X.509 certificate serial number
2. **Cryptographic Signature**: Base64-encoded signature of the request data, signed with the requester's private key

### Authentication Flow

1. Requester signs the target data (CN or serial number) with their private key
2. Signature is base64-encoded and included in the request
3. Server verifies:
   - Certificate exists in the blockchain
   - Certificate is not revoked
   - Signature is valid using certificate's public key
4. If authentication fails, request is rejected

### Response Integrity

Each successful response includes an `encrypted_hash` field:

- Hash is computed from response data (SHA-256)
- Hash is encrypted with requester's public key (RSA-OAEP)
- Requester can decrypt and verify the hash to ensure response authenticity

## API Endpoints

### 1. Get Certificate

Retrieve an X.509 certificate by Common Name.

**Endpoint**: `POST /api/get-certificate`

**Request Body**:
```json
{
  "requester_serial": "A1B2C3D4E5F6",
  "target_cn": "example.com",
  "signature": "base64_encoded_signature_of_target_cn"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "serial_number": "1234567890ABCDEF",
  "subject_cn": "example.com",
  "issuer_cn": "Intermediate CA",
  "not_before": "Jan 24 00:00:00 2026 GMT",
  "not_after": "Jan 24 00:00:00 2027 GMT",
  "encrypted_hash": "base64_encrypted_hash",
  "error": null
}
```

**Error Response** (200 OK with error):
```json
{
  "success": false,
  "certificate_pem": null,
  "serial_number": null,
  "subject_cn": null,
  "issuer_cn": null,
  "not_before": null,
  "not_after": null,
  "encrypted_hash": null,
  "error": "Certificate not found"
}
```

**Response Hash Format**:
```
{serial_number}|{subject_cn}|{issuer_cn}|{not_before}|{not_after}
```

**Error Conditions**:
- `Authentication failed: Certificate not found` - Requester certificate not in blockchain
- `Authentication failed: Certificate has been revoked` - Requester certificate is revoked
- `Authentication failed: Invalid signature` - Signature verification failed
- `Certificate not found` - Target certificate does not exist
- `Certificate has been revoked` - Target certificate is revoked (cannot be retrieved)

### 2. Verify Certificate

Verify the validity status of a certificate by serial number.

**Endpoint**: `POST /api/verify-certificate`

**Request Body**:
```json
{
  "requester_serial": "A1B2C3D4E5F6",
  "target_serial": "1234567890ABCDEF",
  "signature": "base64_encoded_signature_of_target_serial"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "valid": true,
  "serial_number": "1234567890ABCDEF",
  "subject_cn": "example.com",
  "not_before": "Jan 24 00:00:00 2026 GMT",
  "not_after": "Jan 24 00:00:00 2027 GMT",
  "revoked": false,
  "encrypted_hash": "base64_encrypted_hash",
  "error": null
}
```

**Error Response** (200 OK with error):
```json
{
  "success": false,
  "valid": false,
  "serial_number": "1234567890ABCDEF",
  "subject_cn": null,
  "not_before": null,
  "not_after": null,
  "revoked": null,
  "encrypted_hash": null,
  "error": "Certificate not found"
}
```

**Response Hash Format**:
```
{serial_number}|{subject_cn}|{not_before}|{not_after}|{valid}|{revoked}
```

**Validity Logic**:
- `valid = true`: Certificate exists, not expired, and not revoked
- `valid = false`: Certificate expired, revoked, or does not exist

**Error Conditions**:
- Same authentication errors as Get Certificate endpoint
- `Certificate not found` - Target certificate does not exist (valid=false)

## Usage Examples

### Python Client

See `test_api_client.py` for a complete Python implementation.

**Installation**:
```bash
pip install cryptography requests
```

**Basic Usage**:
```python
from pki_client import PKIClient

# Initialize with your certificate and private key
client = PKIClient('my_cert.crt', 'my_key.key')

# Get certificate by CN
result = client.get_certificate('example.com')
print(result)

# Verify certificate by serial
result = client.verify_certificate('1234567890ABCDEF')
print(result)
```

### cURL Example

**Get Certificate**:
```bash
#!/bin/bash

# Your certificate details
CERT_FILE="my_cert.crt"
KEY_FILE="my_key.key"
TARGET_CN="MenaceLabs Root CA"

# Extract serial number from certificate (hex format)
SERIAL=$(openssl x509 -in "$CERT_FILE" -noout -serial | cut -d= -f2)

# Sign the target CN
SIGNATURE=$(echo -n "$TARGET_CN" | \
    openssl dgst -sha256 -sign "$KEY_FILE" | \
    base64 -w 0)

# Send API request
curl -k -X POST https://127.0.0.1:3000/api/get-certificate \
    -H "Content-Type: application/json" \
    -d "{
        \"requester_serial\": \"$SERIAL\",
        \"target_cn\": \"$TARGET_CN\",
        \"signature\": \"$SIGNATURE\"
    }" | jq
```

**Verify Certificate**:
```bash
#!/bin/bash

# Your certificate details
CERT_FILE="my_cert.crt"
KEY_FILE="my_key.key"
TARGET_SERIAL="1234567890ABCDEF"

# Extract serial number from certificate
SERIAL=$(openssl x509 -in "$CERT_FILE" -noout -serial | cut -d= -f2)

# Sign the target serial
SIGNATURE=$(echo -n "$TARGET_SERIAL" | \
    openssl dgst -sha256 -sign "$KEY_FILE" | \
    base64 -w 0)

# Send API request
curl -k -X POST https://127.0.0.1:3000/api/verify-certificate \
    -H "Content-Type: application/json" \
    -d "{
        \"requester_serial\": \"$SERIAL\",
        \"target_serial\": \"$TARGET_SERIAL\",
        \"signature\": \"$SIGNATURE\"
    }" | jq
```

## Security Considerations

### Certificate-Based Authentication

- Only users with valid certificates in the blockchain can make requests
- Revoked certificates are immediately denied access
- Signature verification ensures requester owns the private key

### Response Integrity

- Encrypted hash prevents response tampering
- Hash is encrypted with requester's public key (only requester can decrypt)
- Verify hash after receiving response to ensure authenticity

### Revoked Certificates

- Get Certificate API will NOT return revoked certificates
- Verify Certificate API will report `revoked: true` for revoked certificates
- Revocation status is permanent and immutable

### TLS Security

- All API requests must use HTTPS (TLS)
- Self-signed certificates require `-k` flag in curl or `verify=False` in Python
- Production deployments should use trusted CA certificates

## Error Handling

All API responses use HTTP 200 OK status code. Check the `success` field in the JSON response to determine if the operation succeeded.

**Common Error Messages**:

| Error | Cause | Solution |
|-------|-------|----------|
| `Authentication failed: Certificate not found` | Requester certificate not in blockchain | Ensure certificate was created by the PKI system |
| `Authentication failed: Certificate has been revoked` | Requester certificate is revoked | Use a non-revoked certificate |
| `Authentication failed: Invalid signature` | Signature verification failed | Check signature generation process |
| `Certificate not found` | Target certificate doesn't exist | Verify Common Name or serial number |
| `Certificate has been revoked` | Target certificate is revoked | Certificate cannot be retrieved |
| `Internal server error` | Server-side error | Check server logs |

## Testing

Run the Python test client:

```bash
# Test with admin certificate
python test_api_client.py admin@example.com.crt admin@example.com.key

# Follow prompts to test both endpoints
```

## Logging

API requests are logged to `logs/webserver.log` with:
- Request timestamp
- Requester serial number
- Target CN/serial
- Authentication result
- Response status

**Example log entry**:
```
2026-01-24T12:34:56.789Z INFO API get-certificate request from serial: A1B2C3D4, target CN: example.com
2026-01-24T12:34:56.890Z INFO API get-certificate successful: returned certificate for example.com
```

## Rate Limiting

Currently no rate limiting is implemented. Consider adding rate limiting in production deployments.

## Future Enhancements

Potential future API features:
- Certificate search by multiple criteria
- Batch certificate verification
- CRL download endpoint
- Certificate chain validation
- API key authentication (in addition to certificate-based auth)
