#!/usr/bin/env python3
"""
PKI Chain API Client Test Script

This script demonstrates how to use the PKI Chain API endpoints:
1. Get Certificate by CN (Common Name)
2. Verify Certificate by Serial Number

Requirements:
- Python 3.7+
- cryptography library: pip install cryptography requests

Authentication:
- Each request must include the requester's certificate serial number
- Each request must be signed with the requester's private key
- Only non-revoked certificates can make API requests
"""

import base64
import json
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import requests

# Configuration
API_BASE_URL = "https://127.0.0.1:3000/api"
VERIFY_SSL = False  # Set to True if using trusted certificate


class PKIClient:
    """Client for interacting with PKI Chain API"""
    
    def __init__(self, cert_path: str, key_path: str):
        """
        Initialize PKI API client
        
        Args:
            cert_path: Path to requester's X.509 certificate (.crt file)
            key_path: Path to requester's private key (.key file)
        """
        # Load certificate
        with open(cert_path, 'rb') as f:
            self.cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Load private key
        with open(key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Get requester's serial number (hex format)
        self.serial_number = format(self.cert.serial_number, 'X')
        print(f"Loaded certificate: {self.get_cn()}")
        print(f"Serial Number: {self.serial_number}")
    
    def get_cn(self) -> str:
        """Get Common Name from certificate"""
        for attr in self.cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                return attr.value
        return "Unknown"
    
    def sign_data(self, data: str) -> str:
        """
        Sign data with private key and return base64-encoded signature
        
        Args:
            data: String data to sign
            
        Returns:
            Base64-encoded signature
        """
        signature = self.private_key.sign(
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def decrypt_hash(self, encrypted_hash_b64: str) -> bytes:
        """
        Decrypt response hash with private key
        
        Args:
            encrypted_hash_b64: Base64-encoded encrypted hash
            
        Returns:
            Decrypted hash bytes
        """
        encrypted_hash = base64.b64decode(encrypted_hash_b64)
        decrypted_hash = self.private_key.decrypt(
            encrypted_hash,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_hash
    
    def verify_response_hash(self, response_data: str, encrypted_hash_b64: str) -> bool:
        """
        Verify response authenticity by decrypting and comparing hash
        
        Args:
            response_data: Pipe-separated response data
            encrypted_hash_b64: Base64-encoded encrypted hash from response
            
        Returns:
            True if hash matches, False otherwise
        """
        try:
            # Decrypt hash from response
            decrypted_hash = self.decrypt_hash(encrypted_hash_b64)
            
            # Compute hash of response data
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(response_data.encode('utf-8'))
            computed_hash = digest.finalize()
            
            # Compare hashes
            return decrypted_hash == computed_hash
        except Exception as e:
            print(f"Error verifying response hash: {e}")
            return False
    
    def get_certificate(self, target_cn: str) -> dict:
        """
        Get certificate by Common Name
        
        Args:
            target_cn: Common Name of certificate to retrieve
            
        Returns:
            Response dictionary with certificate data or error
        """
        # Sign the target CN
        signature = self.sign_data(target_cn)
        
        # Prepare request
        request_data = {
            "requester_serial": self.serial_number,
            "target_cn": target_cn,
            "signature": signature
        }
        
        # Send request
        url = f"{API_BASE_URL}/get-certificate"
        print(f"\n🔍 Requesting certificate for CN: {target_cn}")
        
        try:
            response = requests.post(
                url,
                json=request_data,
                verify=VERIFY_SSL
            )
            response.raise_for_status()
            result = response.json()
            
            # Verify response if successful
            if result.get('success') and result.get('encrypted_hash'):
                response_data = f"{result['serial_number']}|{result['subject_cn']}|{result['issuer_cn']}|{result['not_before']}|{result['not_after']}"
                
                if self.verify_response_hash(response_data, result['encrypted_hash']):
                    print("✅ Response hash verified - authentic response from server")
                else:
                    print("⚠️  Response hash verification failed - possible tampering")
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {e}"}
    
    def verify_certificate(self, target_serial: str) -> dict:
        """
        Verify certificate by serial number
        
        Args:
            target_serial: Serial number (hex) of certificate to verify
            
        Returns:
            Response dictionary with validation status or error
        """
        # Sign the target serial
        signature = self.sign_data(target_serial)
        
        # Prepare request
        request_data = {
            "requester_serial": self.serial_number,
            "target_serial": target_serial,
            "signature": signature
        }
        
        # Send request
        url = f"{API_BASE_URL}/verify-certificate"
        print(f"\n🔍 Verifying certificate with serial: {target_serial}")
        
        try:
            response = requests.post(
                url,
                json=request_data,
                verify=VERIFY_SSL
            )
            response.raise_for_status()
            result = response.json()
            
            # Verify response if successful
            if result.get('success') and result.get('encrypted_hash'):
                response_data = f"{result['serial_number']}|{result['subject_cn']}|{result['not_before']}|{result['not_after']}|{result['valid']}|{result['revoked']}"
                
                if self.verify_response_hash(response_data, result['encrypted_hash']):
                    print("✅ Response hash verified - authentic response from server")
                else:
                    print("⚠️  Response hash verification failed - possible tampering")
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request failed: {e}"}


def main():
    """Main test function"""
    if len(sys.argv) < 3:
        print("Usage: python test_api_client.py <cert_path> <key_path>")
        print("\nExample:")
        print("  python test_api_client.py admin@example.com.crt admin@example.com.key")
        sys.exit(1)
    
    cert_path = sys.argv[1]
    key_path = sys.argv[2]
    
    # Verify files exist
    if not Path(cert_path).exists():
        print(f"Error: Certificate file not found: {cert_path}")
        sys.exit(1)
    
    if not Path(key_path).exists():
        print(f"Error: Private key file not found: {key_path}")
        sys.exit(1)
    
    # Disable SSL warnings for self-signed certificates
    if not VERIFY_SSL:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Initialize client
    print("=" * 60)
    print("PKI Chain API Test Client")
    print("=" * 60)
    
    client = PKIClient(cert_path, key_path)
    
    # Test 1: Get Certificate by CN
    print("\n" + "=" * 60)
    print("TEST 1: Get Certificate")
    print("=" * 60)
    
    target_cn = input("\nEnter target Common Name (or press Enter for 'MenaceLabs Root CA'): ").strip()
    if not target_cn:
        target_cn = "MenaceLabs Root CA"
    
    result = client.get_certificate(target_cn)
    print("\nResponse:")
    print(json.dumps(result, indent=2))
    
    # Test 2: Verify Certificate by Serial
    print("\n" + "=" * 60)
    print("TEST 2: Verify Certificate")
    print("=" * 60)
    
    if result.get('success') and result.get('serial_number'):
        # Use serial from previous response
        target_serial = result['serial_number']
        print(f"\nUsing serial from previous response: {target_serial}")
    else:
        target_serial = input("\nEnter target serial number (hex): ").strip()
        if not target_serial:
            print("Skipping verify test - no serial number provided")
            return
    
    result = client.verify_certificate(target_serial)
    print("\nResponse:")
    print(json.dumps(result, indent=2))
    
    print("\n" + "=" * 60)
    print("Tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
