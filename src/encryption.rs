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

pub fn sign_data(
    data: &[u8],
    private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<Vec<u8>> {
    let mut signer =
        match openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &private_key) {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "sign_data -> Failed to create signer: {}",
                    e
                ))
            }
        };
    match signer.update(data) {
        Ok(_) => (),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "sign_data -> Failed to update signer with data: {}",
                e
            ))
        }
    }
    match signer.sign_to_vec() {
        Ok(sig) => Ok(sig),
        Err(e) => Err(anyhow::anyhow!(
            "sign_data -> Failed to generate signature: {}",
            e
        )),
    }
}

pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    public_key: openssl::pkey::PKey<openssl::pkey::Public>,
) -> anyhow::Result<bool> {
    let mut verifier =
        match openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key) {
            Ok(v) => v,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "verify_signature -> Failed to create verifier: {}",
                    e
                ))
            }
        };
    match verifier.update(data) {
        Ok(_) => (),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "verify_signature -> Failed to update verifier with data: {}",
                e
            ))
        }
    }
    match verifier.verify(signature) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(anyhow::anyhow!(
            "verify_signature -> Failed to verify signature: {}",
            e
        )),
    }
}

pub fn encrypt_data(
    data: &[u8],
    public_key: &openssl::pkey::PKey<openssl::pkey::Public>,
) -> anyhow::Result<Vec<u8>> {
    // Generate random AES-256 key (32 bytes)
    let mut aes_key = [0u8; AES_GCM_256_KEY_SIZE];
    match openssl::rand::rand_bytes(&mut aes_key) {
        Ok(_) => (),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "encrypt_data -> Failed to generate random AES key: {}",
                e
            ))
        }
    }

    // Generate random 12-byte nonce
    let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
    match openssl::rand::rand_bytes(&mut nonce) {
        Ok(_) => (),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "encrypt_data -> Failed to generate random nonce: {}",
                e
            ))
        }
    }

    let cipher = openssl::symm::Cipher::aes_256_gcm();
    let mut tag = [0u8; AES_GCM_TAG_SIZE];

    let encrypted_data = match openssl::symm::encrypt_aead(
        cipher,
        &aes_key,
        Some(&nonce),
        &[], // AAD
        data,
        &mut tag,
    ) {
        Ok(ed) => ed,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "encrypt_data -> AES-GCM encryption failed: {}",
                e
            ))
        }
    };

    // Encrypt AES key with RSA-OAEP
    let encrypted_aes_key = (|| -> anyhow::Result<Vec<u8>> {
        let rsa = match public_key.rsa() {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "encrypt_data -> Failed to get RSA public key: {}",
                    e
                ))
            }
        };

        let mut ciphertext = vec![0u8; rsa.size() as usize];
        let len = match rsa.public_encrypt(
            &aes_key,
            &mut ciphertext,
            openssl::rsa::Padding::PKCS1_OAEP,
        ) {
            Ok(len) => len,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "encrypt_data -> RSA encryption failed: {}",
                    e
                ))
            }
        };

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
    private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<Vec<u8>> {
    let mut offset = 0usize;

    // Helper: safely take n bytes without panicking
    fn take<'a>(buf: &'a [u8], offset: &mut usize, n: usize) -> anyhow::Result<&'a [u8]> {
        let end = offset.checked_add(n).ok_or_else(|| {
            anyhow::anyhow!("decrypt_data -> Offset overflow while parsing encrypted payload")
        })?;
        if end > buf.len() {
            return Err(anyhow::anyhow!(
                "decrypt_data -> Malformed encrypted payload: need {} bytes at offset {}, total {}",
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
                .map_err(|_| anyhow::anyhow!("decrypt_data -> Invalid AES key length field"))?,
        ) as usize
    };

    // Optional sanity limit to prevent absurd allocations/parsing
    if aes_key_len == 0 || aes_key_len > 4096 {
        return Err(anyhow::anyhow!(
            "decrypt_data -> Invalid encrypted AES key length: {}",
            aes_key_len
        ));
    }

    let encrypted_aes_key = take(serialized_data, &mut offset, aes_key_len)?;
    let nonce = take(serialized_data, &mut offset, AES_GCM_NONCE_SIZE)?;
    let tag = take(serialized_data, &mut offset, AES_GCM_TAG_SIZE)?;

    let data_len = {
        let raw = take(serialized_data, &mut offset, DATA_LEN_SIZE)?;
        u32::from_le_bytes(
            raw.try_into()
                .map_err(|_| anyhow::anyhow!("decrypt_data -> Invalid data length field"))?,
        ) as usize
    };

    let encrypted_data = take(serialized_data, &mut offset, data_len)?;

    // Optional: reject trailing bytes if format expects exact match
    if offset != serialized_data.len() {
        return Err(anyhow::anyhow!(
            "decrypt_data -> Unexpected trailing bytes in payload: {}",
            serialized_data.len() - offset
        ));
    }

    // RSA-OAEP unwrap
    let aes_key = {
        let rsa = private_key
            .rsa()
            .map_err(|e| anyhow::anyhow!("decrypt_data -> Failed to get RSA private key: {}", e))?;
        let mut decrypted_key = vec![0u8; rsa.size() as usize];
        let len = rsa
            .private_decrypt(
                encrypted_aes_key,
                &mut decrypted_key,
                openssl::rsa::Padding::PKCS1_OAEP,
            )
            .map_err(|e| anyhow::anyhow!("decrypt_data -> RSA decryption failed: {}", e))?;
        decrypted_key.truncate(len);
        decrypted_key
    };

    // Enforce expected AES-256 key size
    if aes_key.len() != 32 {
        return Err(anyhow::anyhow!(
            "decrypt_data -> Invalid AES-256 key size after RSA unwrap: {} bytes",
            aes_key.len()
        ));
    }

    let decrypted_data = openssl::symm::decrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        &aes_key,
        Some(nonce),
        &[], // AAD
        encrypted_data,
        tag,
    )
    .map_err(|e| anyhow::anyhow!("decrypt_data -> AES-GCM decryption failed: {}", e))?;

    Ok(decrypted_data)
}

pub fn encrypt_and_sign_data(
    data: &[u8],
    app_public_key: &openssl::pkey::PKey<openssl::pkey::Public>,
    cert_private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let encrypted_data = encrypt_data(data, app_public_key)?;
    let signature = sign_data(&encrypted_data, cert_private_key)?;
    Ok((encrypted_data, signature))
}

pub fn create_app_cert_and_key_pair() -> anyhow::Result<(
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
)> {
    let rsa = openssl::rsa::Rsa::generate(4096).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to generate RSA key pair: {}",
            e
        )
    })?;
    let private_key = openssl::pkey::PKey::from_rsa(rsa).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to create PKey from RSA key pair: {}",
            e
        )
    })?;

    let mut builder = openssl::x509::X509Builder::new().map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to create X509 builder: {}",
            e
        )
    })?;
    builder.set_version(2).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set certificate version: {}",
            e
        )
    })?;

    let serial_bn = openssl::bn::BigNum::from_u32(1).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to generate certificate serial number: {}",
            e
        )
    })?;
    let serial = serial_bn
        .to_asn1_integer()
        .map_err(|e| anyhow::anyhow!("create_app_cert_and_key_pair -> Failed to convert certificate serial number to ASN1: {}", e))?;
    builder.set_serial_number(&serial).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set certificate serial number: {}",
            e
        )
    })?;

    let not_before = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set certificate not_before timestamp: {}",
            e
        )
    })?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365 * 5).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set certificate not_after timestamp: {}",
            e
        )
    })?;
    builder.set_not_before(&not_before).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to apply certificate not_before timestamp: {}",
            e
        )
    })?;
    builder.set_not_after(&not_after).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to apply certificate not_after timestamp: {}",
            e
        )
    })?;

    let subject_name = openssl::x509::X509NameBuilder::new()
        .and_then(|mut b| {
            b.append_entry_by_text("CN", "App Certificate")
                .map(|_| b.build())
        })
        .map_err(|e| {
            anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to build subject name: {}",
                e
            )
        })?;

    let issuer_name = openssl::x509::X509NameBuilder::new()
        .and_then(|mut b| {
            b.append_entry_by_text("CN", "App Certificate")
                .map(|_| b.build())
        })
        .map_err(|e| {
            anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to build issuer name: {}",
                e
            )
        })?;

    builder.set_subject_name(&subject_name).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set subject name: {}",
            e
        )
    })?;
    builder.set_issuer_name(&issuer_name).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set issuer name: {}",
            e
        )
    })?;
    builder.set_pubkey(&private_key).map_err(|e| {
        anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set public key in certificate: {}",
            e
        )
    })?;
    builder
        .sign(&private_key, openssl::hash::MessageDigest::sha256())
        .map_err(|e| {
            anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to sign certificate: {}",
                e
            )
        })?;

    Ok((builder.build(), private_key))
}

pub fn get_app_public_key(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Public>> {
    let app_cert_pem = std::fs::read(&app_config.key_exports.app_cert_path).map_err(|e| {
        anyhow::anyhow!(
            "get_app_public_key -> Failed to read app certificate PEM file: {}",
            e
        )
    })?;
    let app_cert = openssl::x509::X509::from_pem(&app_cert_pem).map_err(|e| {
        anyhow::anyhow!(
            "get_app_public_key -> Failed to parse app certificate PEM file: {}",
            e
        )
    })?;
    let public_key_pem = app_cert.public_key()?.public_key_to_pem().map_err(|e| {
        anyhow::anyhow!(
            "get_app_public_key -> Failed to serialize app public key to PEM format: {}",
            e
        )
    })?;
    let public_key =
        openssl::pkey::PKey::public_key_from_pem(public_key_pem.as_slice()).map_err(|e| {
            anyhow::anyhow!(
                "get_app_public_key -> Failed to load public key from PEM: {}",
                e
            )
        })?;
    Ok(public_key)
}

pub fn get_app_private_key(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    let private_key_pem = std::fs::read(&app_config.key_exports.app_key_path).map_err(|e| {
        anyhow::anyhow!(
            "get_app_private_key -> Failed to read private key PEM file: {}",
            e
        )
    })?;
    let private_key = openssl::pkey::PKey::private_key_from_pem(private_key_pem.as_slice())
        .map_err(|e| {
            anyhow::anyhow!(
                "get_app_private_key -> Failed to load private key from PEM: {}",
                e
            )
        })?;
    Ok(private_key)
}

pub fn verify_client_auth_cert_chain(
    store: &openssl::x509::store::X509Store,
    chain: &openssl::stack::Stack<openssl::x509::X509>,
    user_cert: &openssl::x509::X509,
) -> anyhow::Result<bool> {
    let mut store_ctx = match openssl::x509::X509StoreContext::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to create X509 store context: {}",
                e
            ))
        }
    };

    let verified = store_ctx
        .init(store, user_cert, chain, |ctx| ctx.verify_cert())
        .map_err(|e| anyhow::anyhow!("Failed to verify client auth certificate chain: {}", e))?;

    if !verified || store_ctx.error() != openssl::x509::X509VerifyResult::OK {
        let error = store_ctx.error();
        let depth = store_ctx.error_depth();
        let current_subject = store_ctx
            .current_cert()
            .and_then(|cert| {
                cert.subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| "<unknown>".to_string());

        return Err(anyhow::anyhow!(
            "Client auth certificate chain verification failed: error={:?}, depth={}, current_subject={}",
            error,
            depth,
            current_subject
        ));
    }

    Ok(true)
}

pub fn build_client_auth_store_from_root_ca(
    root_cert: &openssl::x509::X509,
) -> anyhow::Result<openssl::x509::store::X509Store> {
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()
        .map_err(|e| anyhow::anyhow!("Failed to create X509 store builder: {}", e))?;
    store_builder
        .set_purpose(openssl::x509::X509PurposeId::SSL_CLIENT)
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to set certificate validation purpose to SSL client: {}",
                e
            )
        })?;
    store_builder
        .add_cert(root_cert.to_owned())
        .map_err(|e| anyhow::anyhow!("Failed to add root certificate to trust store: {}", e))?;

    Ok(store_builder.build())
}

pub fn validate_self_signed_root_pair(
    cert: &openssl::x509::X509,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<bool> {
    // 1) Pair consistency: cert public key corresponds to provided private key
    let cert_pub = cert
        .public_key()
        .map_err(|e| anyhow::anyhow!("failed to extract cert public key: {e}"))?;
    if !cert_pub.public_eq(&key) {
        return Err(anyhow::anyhow!(
            "certificate public key does not match private key"
        ));
    }

    // 2) Self-signed shape check: issuer == subject
    if cert.issuer_name().try_cmp(cert.subject_name())? != std::cmp::Ordering::Equal {
        return Err(anyhow::anyhow!(
            "certificate is not self-issued (issuer != subject)"
        ));
    }

    // 3) Signature verification: cert verifies with its own public key
    let sig_ok = cert
        .verify(&cert_pub)
        .map_err(|e| anyhow::anyhow!("failed to verify cert signature: {e}"))?;
    if !sig_ok {
        return Err(anyhow::anyhow!("self-signature verification failed"));
    }

    // 4) Time validity
    let now = openssl::asn1::Asn1Time::days_from_now(0)?;
    if cert.not_before().compare(&now)? == std::cmp::Ordering::Greater {
        return Err(anyhow::anyhow!("certificate not yet valid"));
    }
    if cert.not_after().compare(&now)? == std::cmp::Ordering::Less {
        return Err(anyhow::anyhow!("certificate expired"));
    }

    // 5) Optional but recommended: full OpenSSL path verification with self as trust anchor
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
    store_builder.add_cert(cert.clone())?;
    let store = store_builder.build();

    let mut ctx = openssl::x509::X509StoreContext::new()?;
    let chain = openssl::stack::Stack::new()?; // no intermediates for self-signed root
    let verified = ctx.init(&store, &cert, &chain, |c| c.verify_cert())?;
    if !verified || ctx.error() != openssl::x509::X509VerifyResult::OK {
        return Err(anyhow::anyhow!(
            "X509 verification failed: {:?}",
            ctx.error()
        ));
    }

    Ok(true)
}

pub fn validate_intermediate_cert_chain(
    intermediate_cert: &openssl::x509::X509,
    cert_store: &openssl::x509::store::X509Store,
) -> anyhow::Result<bool> {
    let chain = match openssl::stack::Stack::new() {
        Ok(c) => c,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "validate_intermediate_cert_chain -> Failed to create certificate chain stack: {}",
                e
            ))
        }
    };
    let valid = verify_client_auth_cert_chain(cert_store, &chain, intermediate_cert)?;
    if !valid {
        return Err(anyhow::anyhow!("validate_intermediate_cert_chain -> Intermediate certificate failed validation against root CA"));
    }
    Ok(true)
}
