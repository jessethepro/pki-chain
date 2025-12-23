use anyhow::Context;
use anyhow::Result;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::symm::Cipher;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

pub const KEYSTORE_DIR: &str = "exports/keystore";

/// A securely stored private key that implements Zeroize
#[derive(Clone)]
struct SecureKey {
    key_pem: Vec<u8>,
}

impl Zeroize for SecureKey {
    fn zeroize(&mut self) {
        self.key_pem.zeroize();
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurePrivateKey")
            .field("der_bytes", &"<redacted>")
            .finish()
    }
}

pub struct EncryptedKeyStore {
    directory: PathBuf,
    master_key: SecureKey,
}

impl EncryptedKeyStore {
    /// Create new encrypted key store, deriving encryption key from app private key
    pub fn new(app_key: PKey<Private>) -> Result<Self> {
        // Derive a 32-byte AES key using SHA-256 with domain separation
        let mut domain_data = b"pki-chain-keystore-v1".to_vec();
        domain_data.extend_from_slice(&app_key.private_key_to_der()?);
        let derived_key = hash(MessageDigest::sha256(), &domain_data)
            .context("Failed to derive encryption key")?
            .to_vec();

        // Create directory
        fs::create_dir_all(KEYSTORE_DIR).context("Failed to create key store directory")?;

        Ok(Self {
            directory: PathBuf::from(KEYSTORE_DIR),
            master_key: SecureKey {
                key_pem: derived_key,
            },
        })
    }

    /// Store a private key with AES-256-GCM encryption
    pub fn store_key(&self, key_height: u64, pkey: PKey<Private>) -> Result<PathBuf> {
        let key_pem_as_bytes = pkey.private_key_to_pem_pkcs8()?;
        let cipher = Cipher::aes_256_gcm();

        // Generate random 12-byte nonce (IV)
        let mut nonce = vec![0u8; 12];
        rand_bytes(&mut nonce).context("Failed to generate random nonce")?;

        // Encrypt with AES-256-GCM
        let mut tag = [0u8; 16]; // 16-byte authentication tag buffer
        let ciphertext = openssl::symm::encrypt_aead(
            cipher,
            &self.master_key.key_pem,
            Some(&nonce),
            &[], // No additional authenticated data
            key_pem_as_bytes.as_slice(),
            &mut tag,
        )
        .context("Encryption failed")?;

        // Format: [nonce (12 bytes)][tag (16 bytes)][ciphertext]
        let mut data = nonce.clone();
        data.extend_from_slice(&tag);
        data.extend_from_slice(&ciphertext);

        // Write to file (remove existing file first to avoid permission issues)
        let filename = format!(
            "{}.key.enc",
            key_height.to_string().replace("/", "_").replace(" ", "_")
        );
        let path = self.directory.join(&filename);

        // Remove existing file if it exists
        if path.exists() {
            fs::remove_file(&path).context("Failed to remove existing encrypted key file")?;
        }

        fs::write(&path, data).context("Failed to write encrypted key")?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(path)
    }

    /// Retrieve and decrypt a private key
    /// Retrurn the decrypted key PEM bytes
    pub fn retrieve_key(&self, key_height: u64) -> Result<PKey<Private>> {
        let cipher = Cipher::aes_256_gcm();
        let filename = format!(
            "{}.key.enc",
            key_height.to_string().replace("/", "_").replace(" ", "_")
        );
        let path = self.directory.join(&filename);

        let data = fs::read(&path).context("Failed to read encrypted key")?;

        if data.len() < 28 {
            return Err(anyhow::anyhow!("Invalid encrypted key file: too short (expected at least 28 bytes for nonce + tag)"));
        }

        // Extract fixed-position nonce and tag, then variable-length ciphertext
        // Format: [nonce (12 bytes)][tag (16 bytes)][ciphertext]
        let nonce = &data[0..12];
        let tag = &data[12..28];
        let ciphertext = &data[28..];

        // Decrypt with AES-256-GCM
        let mut tag_array = [0u8; 16];
        tag_array.copy_from_slice(tag);
        let plaintext = openssl::symm::decrypt_aead(
            cipher,
            &self.master_key.key_pem,
            Some(nonce),
            &[], // No additional authenticated data
            ciphertext,
            &mut tag_array,
        )
        .context("Decryption failed - key may be corrupted or tampered")?;

        Ok(PKey::private_key_from_pem(&plaintext)
            .context("Failed to parse decrypted private key PEM")?)
    }

    /// Delete a key from the store
    pub fn delete_key(&self, key_height: u64) -> Result<()> {
        let filename = format!(
            "{}.key.enc",
            key_height.to_string().replace("/", "_").replace(" ", "_")
        );
        let path = self.directory.join(&filename);
        fs::remove_file(&path).context("Failed to delete key")?;
        Ok(())
    }

    /// List all encrypted keys in the store
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(name) = path.file_name() {
                if let Some(name_str) = name.to_str() {
                    if name_str.ends_with(".key.enc") {
                        let key_name = name_str.trim_end_matches(".key.enc").to_string();
                        keys.push(key_name);
                    }
                }
            }
        }
        Ok(keys)
    }
}
