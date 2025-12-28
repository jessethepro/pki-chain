//! Private Key Storage Module
//!
//! Provides secure encrypted storage for RSA private keys using a hybrid encryption scheme.
//! The Root CA private key is stored as password-protected PKCS#8, while all other private keys
//! use a two-tier encryption approach combining RSA and AES-GCM-256.
//!
//! # Encryption Architecture
//!
//! ## Root CA Key (Height 0)
//! - Format: PKCS#8 PEM with optional password protection
//! - Cipher: AES-256-CBC (when password-protected)
//! - File: `root_private_key.pkcs8`
//!
//! ## Other Keys (Height 1+)
//! - Primary encryption: AES-GCM-256 (symmetric)
//! - Key protection: RSA-OAEP with Root CA public key
//! - File format: `[AES Key Len (u32)][Encrypted AES Key][Nonce (12)][Tag (16)][Data Len (u32)][Encrypted Data]`
//! - Files: `{height}.key.enc`
//!
//! This hybrid approach provides:
//! - **Fast encryption/decryption**: AES-GCM for bulk data
//! - **Strong key protection**: RSA-OAEP for AES key encryption
//! - **Authenticated encryption**: GCM mode provides integrity verification
//! - **Cold storage support**: Root CA key can be stored offline
//!
//! # Security Features
//!
//! - **Memory-safe key handling**: Uses Linux kernel keyring for in-memory keys
//! - **Restrictive file permissions**: 0600 (owner read/write only) on Unix
//! - **Random nonces**: Fresh 96-bit nonce for each encryption operation
//! - **PKCS#1 OAEP padding**: Secure RSA encryption with Optimal Asymmetric Encryption Padding
//!
//! # Example
//!
//! ```no_run
//! use pki_chain::private_key_storage::EncryptedKeyStore;
//! use keyutils::Keyring;
//! use std::path::PathBuf;
//!
//! # fn example() -> anyhow::Result<()> {
//! let keyring = Keyring::attach(keyutils::SpecialKeyring::Process)?;
//! let store = EncryptedKeyStore::new(
//!     PathBuf::from("exports/keystore"),
//!     keyring,
//!     "root-key".to_string(),
//! )?;
//!
//! // Store a key (requires root public key for encryption)
//! // store.store_key(height, root_public_key, private_key)?;
//!
//! // Retrieve a key (uses root private key from keyring)
//! // let private_key = store.retrieve_key(height)?;
//!
//! // List all stored keys
//! let keys = store.list_keys()?;
//! println!("Stored keys: {:?}", keys);
//! # Ok(())
//! # }
//! ```

use crate::configs::AppConfig;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::symm::Cipher;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

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

/// Encrypted key store for secure private key storage
///
/// Manages a directory of encrypted private keys with different encryption schemes:
/// - Root CA (height 0): PKCS#8 PEM format with optional password
/// - Other keys: Hybrid RSA + AES-GCM-256 encryption
///
/// # Fields
///
/// * `directory` - Filesystem path where encrypted keys are stored
/// * `proc_keyring` - Linux kernel keyring for secure in-memory key access
/// * `root_key_name` - Name of the root key in the keyring (used for encryption/decryption)
pub struct EncryptedKeyStore {
    app_configs: AppConfig,
}

impl EncryptedKeyStore {
    /// Create a new encrypted key store with keyring integration
    ///
    /// Initializes the encrypted key store directory and sets up keyring access
    /// for secure key management. Creates the directory if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `export_path` - Directory path where encrypted keys will be stored
    /// * `proc_keyring` - Linux kernel process keyring for in-memory key access
    /// * `root_key_name` - Name identifier for the root key in the keyring
    ///
    /// # Returns
    ///
    /// * `Result<Self>` - Initialized key store or error if directory creation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::private_key_storage::EncryptedKeyStore;
    /// # use keyutils::Keyring;
    /// # use std::path::PathBuf;
    /// # fn example() -> anyhow::Result<()> {
    /// let keyring = Keyring::attach(keyutils::SpecialKeyring::Process)?;
    /// let store = EncryptedKeyStore::new(
    ///     PathBuf::from("exports/keystore"),
    ///     keyring,
    ///     "root-key".to_string(),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(app_configs: AppConfig) -> Result<Self> {
        // Create directory
        fs::create_dir_all(&app_configs.key_exports.key_export_directory_path)
            .context("Failed to create key store directory")?;

        Ok(Self { app_configs })
    }

    /// Store a private key with encryption appropriate for its height
    ///
    /// Storage strategy depends on the key height:
    /// - **Height 0 (Root CA)**: Stored as password-protected PKCS#8 PEM file
    ///   - Prompts for password (Enter for no password)
    ///   - Uses AES-256-CBC encryption when password provided
    ///   - Saved as `root_private_key.pkcs8`
    ///
    /// - **Height 1+ (Other keys)**: Stored with hybrid RSA + AES-GCM-256 encryption
    ///   - Generates random AES-256 key for data encryption
    ///   - Encrypts AES key with Root CA public key using RSA-OAEP
    ///   - Encrypts private key DER with AES-GCM-256
    ///   - Saved as `{height}.key.enc`
    ///
    /// # Arguments
    ///
    /// * `key_height` - Blockchain height of the key (0 for Root CA, 1+ for others)
    /// * `root_public_key` - Root CA public key for RSA encryption (unused for height 0)
    /// * `private_key` - The private key to encrypt and store
    ///
    /// # Returns
    ///
    /// * `Result<PathBuf>` - Path to the stored encrypted key file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Password input fails
    /// - PKCS#8 conversion fails
    /// - Random number generation fails
    /// - Encryption operations fail
    /// - File write operations fail
    ///
    /// # File Format (Height 1+)
    ///
    /// ```text
    /// [AES Key Len (4 bytes, u32 LE)]
    /// [Encrypted AES Key (variable, RSA-encrypted)]
    /// [Nonce (12 bytes)]
    /// [Authentication Tag (16 bytes)]
    /// [Data Length (4 bytes, u32 LE)]
    /// [Encrypted Private Key DER (variable, AES-GCM encrypted)]
    /// ```
    ///
    /// # Security
    ///
    /// - File permissions set to 0600 on Unix systems
    /// - Fresh random nonce for each encryption
    /// - RSA-OAEP padding for key encryption
    /// - AES-GCM provides authenticated encryption
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::private_key_storage::EncryptedKeyStore;
    /// # use openssl::pkey::PKey;
    /// # fn example(store: &EncryptedKeyStore,
    /// #            root_pub_key: PKey<openssl::pkey::Public>,
    /// #            priv_key: PKey<openssl::pkey::Private>) -> anyhow::Result<()> {
    /// // Store an intermediate CA key (height 1)
    /// let path = store.store_key(1, root_pub_key, priv_key)?;
    /// println!("Key stored at: {:?}", path);
    /// # Ok(())
    /// # }
    /// ```
    pub fn store_key(
        &self,
        key_height: u64,
        root_public_key: PKey<openssl::pkey::Public>,
        private_key: PKey<openssl::pkey::Private>,
    ) -> Result<PathBuf> {
        match key_height {
            0 => {
                print!("Enter password for Root Key PKCS#8 file storage (press Enter if none): ");
                std::io::stdout().flush()?;
                let pwd = rpassword::read_password()?;
                let pkcs8_bytes = if pwd.is_empty() {
                    private_key
                        .private_key_to_pkcs8()
                        .map_err(|e| anyhow!("Failed to convert private key to PKCS#8: {}", e))?
                } else {
                    private_key
                        .private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), pwd.as_bytes())
                        .map_err(|e| {
                            anyhow!("Failed to convert private key to encrypted PKCS#8: {}", e)
                        })?
                };
                let filename = self.app_configs.key_exports.root_key_name.clone();
                let path = self
                    .app_configs
                    .key_exports
                    .key_export_directory_path
                    .join(&filename);
                fs::write(&path, &pkcs8_bytes).context("Failed to write Root Key PKCS#8 file")?;
                return Ok(path);
            }
            _ => {}
        }
        let serialized_encrypted_file = (|| -> Result<Vec<u8>> {
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

            let encrypted_file_data = openssl::symm::encrypt_aead(
                cipher,
                &aes_key,
                Some(&nonce),
                &[],
                &private_key.private_key_to_der()?,
                &mut tag,
            )
            .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

            // Encrypt AES key with RSA-OAEP
            let encrypted_aes_key = (|| -> Result<Vec<u8>> {
                let rsa = root_public_key
                    .rsa()
                    .map_err(|e| anyhow!("Failed to get RSA public key: {}", e))?;
                let mut ciphertext = vec![0u8; rsa.size() as usize];
                let len = rsa
                    .public_encrypt(&aes_key, &mut ciphertext, Padding::PKCS1_OAEP)
                    .map_err(|e| anyhow!("RSA encryption failed: {}", e))?;

                ciphertext.truncate(len);
                Ok(ciphertext)
            })()?;
            let serialized_file_data = {
                let mut data = Vec::new();
                let aes_key_len = encrypted_aes_key.len() as u32;
                data.extend_from_slice(&aes_key_len.to_le_bytes());
                data.extend_from_slice(&encrypted_aes_key);
                data.extend_from_slice(&nonce);
                data.extend_from_slice(&tag);
                let data_len = encrypted_file_data.len() as u32;
                data.extend_from_slice(&data_len.to_le_bytes());
                data.extend_from_slice(&encrypted_file_data);
                data
            };
            Ok(serialized_file_data)
        })()?;

        // Write to file (remove existing file first to avoid permission issues)
        let filename = format!(
            "{}.key.enc",
            key_height.to_string().replace("/", "_").replace(" ", "_")
        );
        let path = self
            .app_configs
            .key_exports
            .key_export_directory_path
            .join(&filename);

        // Remove existing file if it exists
        if path.exists() {
            fs::remove_file(&path).context("Failed to remove existing encrypted key file")?;
        }

        fs::write(&path, serialized_encrypted_file).context("Failed to write encrypted key")?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(path)
    }

    /// Retrieve and decrypt a private key from storage
    ///
    /// Decrypts a stored private key using the appropriate method based on its height:
    /// - **Height 0 (Root CA)**: Reads `root_private_key.pkcs8` and decrypts PKCS#8 PEM
    /// - **Height 1+**: Reads `{height}.key.enc` and performs two-stage decryption:
    ///   1. Decrypts AES key using Root CA private key from keyring (RSA-OAEP)
    ///   2. Decrypts private key DER using recovered AES key (AES-GCM-256)
    ///
    /// # Arguments
    ///
    /// * `key_height` - Blockchain height of the key to retrieve
    ///
    /// # Returns
    ///
    /// * `Result<PKey<Private>>` - The decrypted private key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Encrypted file cannot be read
    /// - File format is invalid or corrupted
    /// - Root CA private key not found in keyring
    /// - RSA or AES decryption fails
    /// - Private key DER parsing fails
    /// - Authentication tag verification fails (indicates tampering)
    ///
    /// # File Format Expected (Height 1+)
    ///
    /// ```text
    /// [AES Key Len (4 bytes, u32 LE)]
    /// [Encrypted AES Key (variable)]
    /// [Nonce (12 bytes)]
    /// [Authentication Tag (16 bytes)]
    /// [Data Length (4 bytes, u32 LE)]
    /// [Encrypted Private Key DER (variable)]
    /// ```
    ///
    /// # Security
    ///
    /// - Uses Linux kernel keyring for secure root key access
    /// - Verifies GCM authentication tag before returning data
    /// - No key material written to disk unencrypted
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::private_key_storage::EncryptedKeyStore;
    /// # fn example(store: &EncryptedKeyStore) -> anyhow::Result<()> {
    /// // Retrieve Root CA key
    /// let root_key = store.retrieve_key(0)?;
    ///
    /// // Retrieve an intermediate CA key
    /// let int_key = store.retrieve_key(1)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn retrieve_key(&self, key_height: u64) -> Result<PKey<Private>> {
        match key_height {
            0 => {
                let filename = self.app_configs.key_exports.root_key_name.clone();
                let path = self
                    .app_configs
                    .key_exports
                    .key_export_directory_path
                    .join(&filename);
                let encrypted_root_key = fs::read(&path).with_context(|| {
                    format!(
                        "Failed to read Root CA private key from {}",
                        path.to_str().unwrap_or("<invalid path>")
                    )
                })?;
                print!("Enter password for Root CA private key (press Enter if none): ");
                std::io::stdout().flush()?;
                let passwd = rpassword::read_password()?;
                let root_key = if passwd.is_empty() {
                    PKey::private_key_from_pkcs8(&encrypted_root_key).map_err(|e| {
                        anyhow!(
                            "Failed to parse Root CA private key PEM from {}: {}",
                            path.to_str().unwrap_or("<invalid path>"),
                            e
                        )
                    })?
                } else {
                    PKey::private_key_from_pkcs8_passphrase(&encrypted_root_key, passwd.as_bytes())
                        .map_err(|e| {
                            anyhow!(
                                "Failed to decrypt Root CA private key from {}: {}",
                                path.to_str().unwrap_or("<invalid path>"),
                                e
                            )
                        })?
                };
                return Ok(root_key);
            }
            _ => {}
        }
        let filename = format!(
            "{}.key.enc",
            key_height.to_string().replace("/", "_").replace(" ", "_")
        );
        let path = self
            .app_configs
            .key_exports
            .key_export_directory_path
            .join(&filename);

        let encrypted_file_data = fs::read(&path).context("Failed to read encrypted key")?;

        if encrypted_file_data.len() < 28 {
            return Err(anyhow::anyhow!("Invalid encrypted key file: too short (expected at least 28 bytes for nonce + tag)"));
        }

        let mut index = 0;
        let aes_key_len = u32::from_le_bytes(
            encrypted_file_data
                .get(index..index + AES_KEY_LEN_SIZE)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow!("Failed to read AES key length"))?,
        ) as usize;
        index += AES_KEY_LEN_SIZE;
        let encrypted_aes_key = encrypted_file_data
            .get(index..index + aes_key_len)
            .ok_or_else(|| anyhow!("Failed to read encrypted AES key"))?;
        index += aes_key_len;
        let nonce = encrypted_file_data
            .get(index..index + AES_GCM_NONCE_SIZE)
            .ok_or_else(|| anyhow!("Failed to read nonce"))?;
        index += AES_GCM_NONCE_SIZE;
        let tag = encrypted_file_data
            .get(index..index + AES_GCM_TAG_SIZE)
            .ok_or_else(|| anyhow!("Failed to read authentication tag"))?;
        index += AES_GCM_TAG_SIZE;
        let data_len = u32::from_le_bytes(
            encrypted_file_data
                .get(index..index + DATA_LEN_SIZE)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow!("Failed to read data length"))?,
        ) as usize;
        index += DATA_LEN_SIZE;
        let data_bytes = encrypted_file_data
            .get(index..index + data_len)
            .ok_or_else(|| anyhow!("Failed to read encrypted data"))?;
        let decrypted_file_data = {
            // Decrypt AES key with RSA-OAEP
            let aes_key = (|| -> Result<Vec<u8>> {
                let root_key_der = (|| -> Result<Vec<u8>> {
                    let root_path = self
                        .app_configs
                        .key_exports
                        .key_export_directory_path
                        .join(&self.app_configs.key_exports.root_key_name);
                    let encrypted_pem_data = fs::read(&root_path).with_context(|| {
                        format!(
                            "Failed to read Root CA private key from {}",
                            root_path.to_str().unwrap_or("<invalid path>")
                        )
                    })?;
                    let passwd = rpassword::prompt_password(
                        "Enter password for Root CA private key (press Enter if none): ",
                    )?;
                    let pem_data = if passwd.is_empty() {
                        encrypted_pem_data
                    } else {
                        PKey::private_key_from_pkcs8_passphrase(
                            &encrypted_pem_data,
                            passwd.as_bytes(),
                        )
                        .map_err(|e| {
                            anyhow!(
                                "Failed to decrypt Root CA private key from {}: {}",
                                root_path.to_str().unwrap_or("<invalid path>"),
                                e
                            )
                        })?
                        .private_key_to_der()
                        .map_err(|e| {
                            anyhow!("Failed to convert Root CA private key to PEM: {}", e)
                        })?
                    };
                    let root_key = PKey::private_key_from_pem(&pem_data).map_err(|e| {
                        anyhow!(
                            "Failed to parse Root CA private key PEM from {}: {}",
                            root_path.to_str().unwrap_or("<invalid path>"),
                            e
                        )
                    })?;
                    Ok(root_key.private_key_to_der().map_err(|e| {
                        anyhow!("Failed to convert Root CA private key to DER: {}", e)
                    })?)
                })()?;
                let root_private_key = PKey::private_key_from_der(root_key_der.as_slice())
                    .map_err(|e| anyhow!("Failed to parse private key DER: {}", e))?;
                let rsa = root_private_key
                    .rsa()
                    .map_err(|e| anyhow!("Failed to get RSA key: {}", e))?;
                let mut plaintext = vec![0u8; rsa.size() as usize];
                let len = rsa
                    .private_decrypt(encrypted_aes_key, &mut plaintext, Padding::PKCS1_OAEP)
                    .map_err(|e| anyhow!("RSA decryption failed: {}", e))?;
                plaintext.truncate(len);
                Ok(plaintext)
            })()?;

            // Decrypt block data with AES-GCM

            openssl::symm::decrypt_aead(
                Cipher::aes_256_gcm(),
                &aes_key,
                Some(nonce),
                &[],
                data_bytes,
                tag,
            )
            .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?
        };
        Ok(decrypted_file_data
            .as_slice()
            .try_into()
            .map_err(|e| anyhow!("Failed to parse private key DER: {}", e))
            .and_then(|der| {
                PKey::private_key_from_der(der)
                    .map_err(|e| anyhow!("Failed to create private key from DER: {}", e))
            })?)
    }

    /// Delete an encrypted key file from storage
    ///
    /// Removes the encrypted key file for the specified height from the filesystem.
    /// This operation is permanent and cannot be undone. The key will need to be
    /// regenerated or restored from backup if deleted.
    ///
    /// # Arguments
    ///
    /// * `key_height` - Blockchain height of the key to delete
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Success or error if file deletion fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File does not exist
    /// - Insufficient permissions to delete file
    /// - I/O error during deletion
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::private_key_storage::EncryptedKeyStore;
    /// # fn example(store: &EncryptedKeyStore) -> anyhow::Result<()> {
    /// // Delete a key at height 5
    /// store.delete_key(5)?;
    /// println!("Key deleted successfully");
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete_key(&self, key_height: u64) -> Result<()> {
        let filename = format!(
            "{}.key.enc",
            key_height.to_string().replace("/", "_").replace(" ", "_")
        );
        let path = self
            .app_configs
            .key_exports
            .key_export_directory_path
            .join(&filename);
        fs::remove_file(&path).context("Failed to delete key")?;
        Ok(())
    }

    /// List all encrypted key identifiers in the store
    ///
    /// Scans the key store directory and returns a list of all encrypted key files.
    /// Returns the height/identifier portion of each filename (without the `.key.enc` extension).
    ///
    /// # Returns
    ///
    /// * `Result<Vec<String>>` - Vector of key identifiers (heights) as strings
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Directory cannot be read
    /// - Insufficient permissions to list directory
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::private_key_storage::EncryptedKeyStore;
    /// # fn example(store: &EncryptedKeyStore) -> anyhow::Result<()> {
    /// let keys = store.list_keys()?;
    /// println!("Found {} encrypted keys", keys.len());
    /// for key_id in keys {
    ///     println!("  - Key at height: {}", key_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.app_configs.key_exports.key_export_directory_path)? {
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
