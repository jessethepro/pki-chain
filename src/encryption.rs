use anyhow::{anyhow, Result};
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::symm::Cipher;

/// Size of AES key length field in serialized format (u32 = 4 bytes)
pub const AES_KEY_LEN_SIZE: usize = 4; // u32 for AES key length
/// Size of AES-256 key (256 bits = 32 bytes)
pub const AES_GCM_256_KEY_SIZE: usize = 32; // 256 bits
/// Size of AES-GCM nonce (96 bits = 12 bytes)
pub const AES_GCM_NONCE_SIZE: usize = 12; // 96 bits
/// Size of AES-GCM authentication tag (128 bits = 16 bytes)
pub const AES_GCM_TAG_SIZE: usize = 16; // 128 bits
/// Size of data length field in serialized format (u32 = 4 bytes)
pub const DATA_LEN_SIZE: usize = 4; // u32 for block length
pub struct EncryptedData {
    iv: Vec<u8>,
    tag: Vec<u8>,
    nonce: Vec<u8>,
    encrypted_aes_key: Vec<u8>,
    encrypted_data: Vec<u8>,
}

impl EncryptedData {
    pub fn encrypt_data(
        data: Vec<u8>,
        public_key: PKey<openssl::pkey::Public>,
    ) -> Result<EncryptedData> {
        // Generate random AES-256 key (32 bytes)
        let mut aes_key = [0u8; AES_GCM_256_KEY_SIZE];
        openssl::rand::rand_bytes(&mut aes_key)
            .map_err(|e| anyhow!("Failed to generate random AES key: {}", e))?;

        // Generate random 12-byte nonce
        let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
        openssl::rand::rand_bytes(&mut nonce)
            .map_err(|e| anyhow!("Failed to generate random nonce: {}", e))?;

        let cipher = Cipher::aes_256_gcm();
        let mut tag = [0u8; AES_GCM_TAG_SIZE];

        let encrypted_data =
            openssl::symm::encrypt_aead(cipher, &aes_key, Some(&nonce), &[], &data, &mut tag)
                .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

        // Encrypt AES key with RSA-OAEP
        let encrypted_aes_key = (|| -> Result<Vec<u8>> {
            let rsa = public_key
                .rsa()
                .map_err(|e| anyhow!("Failed to get RSA public key: {}", e))?;
            let mut ciphertext = vec![0u8; rsa.size() as usize];
            let len = rsa
                .public_encrypt(&aes_key, &mut ciphertext, Padding::PKCS1_OAEP)
                .map_err(|e| anyhow!("RSA encryption failed: {}", e))?;

            ciphertext.truncate(len);
            Ok(ciphertext)
        })()?;
        Ok(EncryptedData {
            iv: vec![],
            encrypted_aes_key,
            tag: tag.to_vec(),
            nonce: nonce.to_vec(),
            encrypted_data,
        })
    }

    pub fn serialize_encrypted_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let aes_key_len = self.encrypted_aes_key.len() as u32;
        data.extend_from_slice(&aes_key_len.to_le_bytes());
        data.extend_from_slice(&self.encrypted_aes_key);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.tag);
        let data_len = self.encrypted_data.len() as u32;
        data.extend_from_slice(&data_len.to_le_bytes());
        data.extend_from_slice(&self.encrypted_data);
        data
    }

    pub fn decrypt_data(&self, private_key: PKey<openssl::pkey::Private>) -> Result<Vec<u8>> {
        // Decrypt AES key with RSA-OAEP
        let aes_key = (|| -> Result<Vec<u8>> {
            let rsa = private_key
                .rsa()
                .map_err(|e| anyhow!("Failed to get RSA private key: {}", e))?;
            let mut decrypted_key = vec![0u8; rsa.size() as usize];
            let len = rsa
                .private_decrypt(
                    &self.encrypted_aes_key,
                    &mut decrypted_key,
                    Padding::PKCS1_OAEP,
                )
                .map_err(|e| anyhow!("RSA decryption failed: {}", e))?;

            decrypted_key.truncate(len);
            Ok(decrypted_key)
        })()?;

        let cipher = Cipher::aes_256_gcm();
        let decrypted_data = openssl::symm::decrypt_aead(
            cipher,
            &aes_key,
            Some(&self.nonce),
            &[],
            &self.encrypted_data,
            &self.tag,
        )
        .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?;

        Ok(decrypted_data)
    }
}

pub fn deserialize_encrypted_data(serialized_data: &[u8]) -> Result<EncryptedData> {
    let mut offset = 0;

    if serialized_data.len() < AES_KEY_LEN_SIZE {
        return Err(anyhow!(
            "Serialized data too short to contain AES key length"
        ));
    }

    let aes_key_len = u32::from_le_bytes(
        serialized_data[offset..offset + AES_KEY_LEN_SIZE]
            .try_into()
            .unwrap(),
    ) as usize;
    offset += AES_KEY_LEN_SIZE;

    if serialized_data.len() < offset + aes_key_len + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
        return Err(anyhow!(
            "Serialized data too short to contain encrypted AES key, nonce, and tag"
        ));
    }

    let encrypted_aes_key = serialized_data[offset..offset + aes_key_len].to_vec();
    offset += aes_key_len;

    let nonce = serialized_data[offset..offset + AES_GCM_NONCE_SIZE].to_vec();
    offset += AES_GCM_NONCE_SIZE;

    let tag = serialized_data[offset..offset + AES_GCM_TAG_SIZE].to_vec();
    offset += AES_GCM_TAG_SIZE;

    if serialized_data.len() < offset + DATA_LEN_SIZE {
        return Err(anyhow!("Serialized data too short to contain data length"));
    }

    let data_len = u32::from_le_bytes(
        serialized_data[offset..offset + DATA_LEN_SIZE]
            .try_into()
            .unwrap(),
    ) as usize;
    offset += DATA_LEN_SIZE;

    if serialized_data.len() < offset + data_len {
        return Err(anyhow!(
            "Serialized data too short to contain encrypted data"
        ));
    }

    let encrypted_data = serialized_data[offset..offset + data_len].to_vec();

    Ok(EncryptedData {
        iv: vec![],
        encrypted_aes_key,
        nonce,
        tag,
        encrypted_data,
    })
}
