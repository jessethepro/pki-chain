use anyhow::{anyhow, Result};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{Signer, Verifier};
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509PurposeId, X509StoreContext};

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

pub fn sign_data(data: &[u8], private_key: PKey<openssl::pkey::Private>) -> Result<Vec<u8>> {
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
        .map_err(|e| anyhow!("Failed to create signer: {}", e))?;
    signer
        .update(data)
        .map_err(|e| anyhow!("Failed to update signer with data: {}", e))?;
    signer
        .sign_to_vec()
        .map_err(|e| anyhow!("Failed to generate signature: {}", e))
}

pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    public_key: PKey<openssl::pkey::Public>,
) -> Result<bool> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
        .map_err(|e| anyhow!("Failed to create verifier: {}", e))?;
    verifier
        .update(data)
        .map_err(|e| anyhow!("Failed to update verifier with data: {}", e))?;
    verifier
        .verify(signature)
        .map_err(|e| anyhow!("Failed to verify signature: {}", e))
}

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

pub fn encrypt_and_sign_data(
    data: &[u8],
    app_public_key: PKey<openssl::pkey::Public>,
    cert_private_key: PKey<openssl::pkey::Private>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let encrypted_data = encrypt_data(data, app_public_key)?;
    let signature = sign_data(&encrypted_data, cert_private_key)?;
    Ok((encrypted_data, signature))
}

pub fn verify_and_decrypt_cert(
    encrypted_data: &[u8],
    signature: &[u8],
    app_private_key: PKey<openssl::pkey::Private>,
) -> (Result<openssl::x509::X509>, Result<bool>) {
    let decrypted_data = match decrypt_data(encrypted_data, app_private_key) {
        Ok(data) => data,
        Err(e) => {
            // If decryption fails, we can't verify the signature, but we can still report the error
            return (Err(anyhow!("Decryption failed: {}", e)), Ok(false));
        }
    };
    let cert = match openssl::x509::X509::from_der(&decrypted_data) {
        Ok(cert) => cert,
        Err(e) => {
            return (
                Err(anyhow!(
                    "Failed to parse decrypted data as X509 certificate: {}",
                    e
                )),
                Ok(false),
            );
        }
    };
    let public_key = match cert.public_key() {
        Ok(key) => key,
        Err(e) => {
            return (
                Err(anyhow!(
                    "Failed to extract public key from certificate: {}",
                    e
                )),
                Ok(false),
            );
        }
    };
    let verified = match verify_signature(encrypted_data, signature, public_key) {
        Ok(valid) => valid,
        Err(e) => {
            return (
                Ok(cert), // We can still return the cert even if signature verification fails
                Err(anyhow!("Signature verification failed: {}", e)),
            );
        }
    };
    (Ok(cert), Ok(verified))
}

pub fn verify_priv_key_signature_with_cert(
    data: &[u8],
    signature: &[u8],
    cert: &openssl::x509::X509,
) -> Result<bool> {
    let public_key = cert
        .public_key()
        .map_err(|e| anyhow!("Failed to extract public key from certificate: {}", e))?;
    verify_signature(data, signature, public_key)
}

pub fn verify_and_decrypt_priv_key(
    encrypted_data: &[u8],
    signature: &[u8],
    cert: &openssl::x509::X509,
    app_private_key: PKey<openssl::pkey::Private>,
) -> (
    Result<openssl::pkey::PKey<openssl::pkey::Private>>,
    Result<bool>,
) {
    let decrypted_data = match decrypt_data(encrypted_data, app_private_key) {
        Ok(data) => data,
        Err(e) => {
            // If decryption fails, we can't verify the signature, but we can still report the error
            return (Err(anyhow!("Decryption failed: {}", e)), Ok(false));
        }
    };

    let verified = match verify_priv_key_signature_with_cert(encrypted_data, signature, cert) {
        Ok(valid) => valid,
        Err(e) => {
            return (
                Err(anyhow!("Signature verification failed: {}", e)),
                Ok(false),
            );
        }
    };
    if !verified {
        return (Err(anyhow!("Signature verification failed")), Ok(false));
    }

    let private_key = match openssl::pkey::PKey::private_key_from_der(&decrypted_data) {
        Ok(key) => key,
        Err(e) => {
            return (
                Err(anyhow!(
                    "Failed to parse decrypted data as private key: {}",
                    e
                )),
                Ok(verified),
            );
        }
    };
    (Ok(private_key), Ok(verified))
}

pub fn create_app_cert_and_key_pair() -> Result<(openssl::x509::X509, PKey<openssl::pkey::Private>)>
{
    let rsa = openssl::rsa::Rsa::generate(4096)
        .map_err(|e| anyhow!("Failed to generate RSA key pair: {}", e))?;
    let private_key = PKey::from_rsa(rsa)
        .map_err(|e| anyhow!("Failed to create PKey from RSA key pair: {}", e))?;

    let mut builder = openssl::x509::X509Builder::new()
        .map_err(|e| anyhow!("Failed to create X509 builder: {}", e))?;
    builder
        .set_version(2)
        .map_err(|e| anyhow!("Failed to set certificate version: {}", e))?;

    let subject_name = openssl::x509::X509NameBuilder::new()
        .and_then(|mut b| {
            b.append_entry_by_text("CN", "App Certificate")
                .map(|_| b.build())
        })
        .map_err(|e| anyhow!("Failed to build subject name: {}", e))?;

    let issuer_name = openssl::x509::X509NameBuilder::new()
        .and_then(|mut b| {
            b.append_entry_by_text("CN", "App Certificate")
                .map(|_| b.build())
        })
        .map_err(|e| anyhow!("Failed to build issuer name: {}", e))?;

    builder
        .set_subject_name(&subject_name)
        .map_err(|e| anyhow!("Failed to set subject name: {}", e))?;
    builder
        .set_issuer_name(&issuer_name)
        .map_err(|e| anyhow!("Failed to set issuer name: {}", e))?;
    builder
        .set_pubkey(&private_key)
        .map_err(|e| anyhow!("Failed to set public key in certificate: {}", e))?;
    builder
        .sign(&private_key, MessageDigest::sha256())
        .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;

    Ok((builder.build(), private_key))
}

pub fn get_app_public_key(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Public>> {
    let public_key_pem = std::fs::read(&app_config.key_exports.app_cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to read public key PEM file: {}", e))?;
    let public_key = openssl::pkey::PKey::public_key_from_pem(public_key_pem.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to load public key from PEM: {}", e))?;
    Ok(public_key)
}

pub fn get_app_private_key(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    let private_key_pem = std::fs::read(&app_config.key_exports.app_key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read private key PEM file: {}", e))?;
    let private_key = openssl::pkey::PKey::private_key_from_pem(private_key_pem.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to load private key from PEM: {}", e))?;
    Ok(private_key)
}

pub fn verify_certificate_signature(
    user_cert: &openssl::x509::X509,
    ca_cert: &openssl::x509::X509,
) -> anyhow::Result<bool> {
    let ca_public_key = ca_cert
        .public_key()
        .map_err(|e| anyhow::anyhow!("Failed to extract public key from CA certificate: {}", e))?;

    verify_signature(
        user_cert
            .to_der()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to serialize user certificate for signature verification: {}",
                    e
                )
            })?
            .as_slice(),
        user_cert.signature().as_slice(),
        ca_public_key,
    )
    .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
}

pub fn verify_client_auth_cert_chain(
    store: &X509Store,
    chain: &Stack<openssl::x509::X509>,
    user_cert: &openssl::x509::X509,
) -> bool {
    let mut store_ctx = match X509StoreContext::new() {
        Ok(ctx) => ctx,
        Err(_) => return false,
    };

    store_ctx
        .init(store, user_cert, chain, |ctx| ctx.verify_cert())
        .unwrap_or(false)
}

pub fn add_intermediate_ca_to_stack(
    intermediate_cert: &openssl::x509::X509,
    mut chain: Stack<openssl::x509::X509>,
) -> anyhow::Result<Stack<openssl::x509::X509>> {
    chain
        .push(intermediate_cert.to_owned())
        .map_err(|e| anyhow!("Failed to add intermediate certificate to chain: {}", e))?;
    Ok(chain)
}

pub fn build_client_auth_store_from_root_ca(
    root_cert: &openssl::x509::X509,
) -> anyhow::Result<X509Store> {
    let mut store_builder = X509StoreBuilder::new()
        .map_err(|e| anyhow!("Failed to create X509 store builder: {}", e))?;
    store_builder
        .set_purpose(X509PurposeId::SSL_CLIENT)
        .map_err(|e| {
            anyhow!(
                "Failed to set certificate validation purpose to SSL client: {}",
                e
            )
        })?;
    store_builder
        .add_cert(root_cert.to_owned())
        .map_err(|e| anyhow!("Failed to add root certificate to trust store: {}", e))?;

    Ok(store_builder.build())
}
