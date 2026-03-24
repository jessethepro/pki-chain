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

pub fn encrypt_data(data: &[u8], public_key: PKey<openssl::pkey::Public>) -> Result<Vec<u8>> {
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

    let encrypted_data = openssl::symm::encrypt_aead(
        cipher,
        &aes_key,
        Some(&nonce),
        &[], // AAD
        data,
        &mut tag,
    )
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

    // Serialize:
    // [4 bytes encrypted_aes_key_len LE]
    // [encrypted_aes_key]
    // [12 bytes nonce]
    // [16 bytes tag]
    // [4 bytes encrypted_data_len LE]
    // [encrypted_data]
    let mut out = Vec::with_capacity(
        AES_KEY_LEN_SIZE
            + encrypted_aes_key.len()
            + AES_GCM_NONCE_SIZE
            + AES_GCM_TAG_SIZE
            + DATA_LEN_SIZE
            + encrypted_data.len(),
    );

    let encrypted_aes_key_len = encrypted_aes_key.len() as u32;
    out.extend_from_slice(&encrypted_aes_key_len.to_le_bytes());
    out.extend_from_slice(&encrypted_aes_key);

    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);

    let encrypted_data_len = encrypted_data.len() as u32;
    out.extend_from_slice(&encrypted_data_len.to_le_bytes());
    out.extend_from_slice(&encrypted_data);

    Ok(out)
}

pub fn decrypt_data(
    serialized_data: &[u8],
    private_key: PKey<openssl::pkey::Private>,
) -> Result<Vec<u8>> {
    let mut offset = 0usize;

    // Helper: safely take n bytes without panicking
    fn take<'a>(buf: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(n)
            .ok_or_else(|| anyhow!("Offset overflow while parsing encrypted payload"))?;
        if end > buf.len() {
            return Err(anyhow!(
                "Malformed encrypted payload: need {} bytes at offset {}, total {}",
                n,
                *offset,
                buf.len()
            ));
        }
        let out = &buf[*offset..end];
        *offset = end;
        Ok(out)
    }

    let aes_key_len = {
        let raw = take(serialized_data, &mut offset, AES_KEY_LEN_SIZE)?;
        u32::from_le_bytes(
            raw.try_into()
                .map_err(|_| anyhow!("Invalid AES key length field"))?,
        ) as usize
    };

    // Optional sanity limit to prevent absurd allocations/parsing
    if aes_key_len == 0 || aes_key_len > 4096 {
        return Err(anyhow!("Invalid encrypted AES key length: {}", aes_key_len));
    }

    let encrypted_aes_key = take(serialized_data, &mut offset, aes_key_len)?;
    let nonce = take(serialized_data, &mut offset, AES_GCM_NONCE_SIZE)?;
    let tag = take(serialized_data, &mut offset, AES_GCM_TAG_SIZE)?;

    let data_len = {
        let raw = take(serialized_data, &mut offset, DATA_LEN_SIZE)?;
        u32::from_le_bytes(
            raw.try_into()
                .map_err(|_| anyhow!("Invalid data length field"))?,
        ) as usize
    };

    let encrypted_data = take(serialized_data, &mut offset, data_len)?;

    // Optional: reject trailing bytes if format expects exact match
    if offset != serialized_data.len() {
        return Err(anyhow!(
            "Unexpected trailing bytes in payload: {}",
            serialized_data.len() - offset
        ));
    }

    // RSA-OAEP unwrap
    let aes_key = {
        let rsa = private_key
            .rsa()
            .map_err(|e| anyhow!("Failed to get RSA private key: {}", e))?;
        let mut decrypted_key = vec![0u8; rsa.size() as usize];
        let len = rsa
            .private_decrypt(encrypted_aes_key, &mut decrypted_key, Padding::PKCS1_OAEP)
            .map_err(|e| anyhow!("RSA decryption failed: {}", e))?;
        decrypted_key.truncate(len);
        decrypted_key
    };

    // Enforce expected AES-256 key size
    if aes_key.len() != 32 {
        return Err(anyhow!(
            "Invalid AES-256 key size after RSA unwrap: {} bytes",
            aes_key.len()
        ));
    }

    let decrypted_data = openssl::symm::decrypt_aead(
        Cipher::aes_256_gcm(),
        &aes_key,
        Some(nonce),
        &[], // AAD
        encrypted_data,
        tag,
    )
    .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?;

    Ok(decrypted_data)
}
