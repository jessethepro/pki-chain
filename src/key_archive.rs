use crate::encryption::EncryptedFileData;
use anyhow::Result;
use keyutils::Key;
use openssl::pkey::PKey;
use secrecy::{ExposeSecret, SecretBox};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::{collections::HashMap, marker::PhantomData};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;

enum ArchiveState {
    OPEN,
    CLOSED,
    TEMP,
    NOEXIST,
}

struct OpenedKeyArchive {
    archive_state: ArchiveState,
    key_archive_file: File,
    secure_password: SecretBox<Vec<u8>>,
}

struct ClosedKeyArchive {
    archive_state: ArchiveState,
    key_archive_path: PathBuf,
    secure_password: SecretBox<Vec<u8>>,
}

struct TempKeyArchive {
    archive_state: ArchiveState,
    temp_archive_path: NamedTempFile,
    secure_password: SecretBox<Vec<u8>>,
}

struct NoExistKeyArchive {}

pub struct KeyArchive<State> {
    key_archive_state: PhantomData<State>,
}

impl KeyArchive<NoExistKeyArchive> {
    pub fn get_archive_path(&self) -> PathBuf {
        let temp_archive_path = "/tmp/private_key_archive.tar".to_string();
        PathBuf::from(temp_archive_path)
    }
}

impl KeyArchive<TempKeyArchive> {
    pub fn create_temporary_archive(
        root_ca_password: String,
    ) -> Result<KeyArchive<TempKeyArchive>> {
        let temp_archive = NamedTempFile::new()?;
        Ok(KeyArchive {
            key_archive_state: PhantomData,
        })
    }
}

impl KeyArchive {
    pub fn open(key_archive_path: PathBuf, root_ca_password: String) -> Result<KeyArchive> {
        if key_archive_path.exists() {
            return Ok(KeyArchive {
                key_archive_path,
                secure_password: SecretBox::new(Box::new(root_ca_password.into_bytes())),
            });
        }

        Err(anyhow::anyhow!(
            "Key archive file does not exist at {:?}",
            key_archive_path
        ))
    }

    pub fn list_keys_in_tar(&self) -> Result<HashMap<u64, String>> {
        // Open the tar file
        let file = File::open(&self.key_archive_path)?;

        // Create archive reader
        let mut key_archive = Archive::new(file);
        let mut archived_keys: HashMap<u64, String> = HashMap::new();

        // Iterate through entries
        for entry in key_archive.entries()? {
            let entry = entry?;

            match entry.header().entry_type() {
                tar::EntryType::Regular => {
                    let file_name = entry
                        .path()?
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("")
                        .to_string();
                    if let Some(height_str) = file_name.strip_suffix(".key.enc") {
                        if let Ok(height) = height_str.parse::<u64>() {
                            archived_keys.insert(height, file_name);
                        }
                    }
                }

                _ => {
                    // Skip non-regular files
                    continue;
                }
            }
        }
        Ok(archived_keys)
    }

    pub fn add_key_to_archive(
        &self,
        height: u64,
        private_key: PKey<openssl::pkey::Private>,
    ) -> Result<PathBuf> {
        let file_data = private_key.private_key_to_pem_pkcs8()?;
        let root_public_key =
            openssl::pkey::PKey::public_key_from_pem(&self.get_root_key()?.public_key_to_pem()?)?;
        let tar_path = self.key_archive_path.clone();
        let tar_file = fs::File::open(&tar_path)
            .map_err(|e| anyhow::anyhow!("Failed to open archive file at {:?}: {}", tar_path, e))?;
        let mut tar_builder = Builder::new(&tar_file);

        let mut tar_header = tar::Header::new_gnu();
        tar_header.set_size(file_data.len() as u64);
        tar_header.set_mode(0o400); // Read-only permissions
        tar_header.set_cksum();
        let file_name = format!("{}.key.enc", height);
        let serialized_encrypted_file =
            EncryptedFileData::encrypte_file_data(&file_name, file_data, root_public_key)?
                .serialize_encrypted_file();

        tar_builder
            .append_data(
                &mut tar_header,
                file_name.as_str(),
                &serialized_encrypted_file[..],
            )
            .map_err(|e| {
                anyhow::anyhow!("Failed to append file {} to archive: {}", file_name, e)
            })?;
        tar_builder
            .finish()
            .map_err(|e| anyhow::anyhow!("Failed to finalize archive: {}", e))?;
        Ok(tar_path)
    }

    fn get_root_key(&self) -> Result<PKey<openssl::pkey::Private>> {
        let root_key_file_data = (|| -> Result<Vec<u8>> {
            let file = File::open(&self.key_archive_path)
                .map_err(|e| anyhow::anyhow!("Failed to open archive: {}", e))?;
            let mut archive = Archive::new(file);
            let default_configs = crate::configs::AppConfig::load()?;
            let root_key_name = &default_configs.key_exports.root_key_name;

            for entry in archive.entries()? {
                let mut entry = entry?;
                let entry_path = entry.path()?;
                if entry_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
                    == root_key_name
                {
                    let mut contents = Vec::new();
                    entry.read_to_end(&mut contents)?;
                    return Ok(contents);
                }
            }
            Err(anyhow::anyhow!("Root key file not found in archive"))
        })()?;

        let root_private_key = openssl::pkey::PKey::private_key_from_pem_passphrase(
            &root_key_file_data,
            self.secure_password.expose_secret(),
        )?;
        Ok(root_private_key)
    }

    pub fn get_key_from_archive(&self, height: u64) -> Result<PKey<openssl::pkey::Private>> {
        let file_name = format!("{}.key.enc", height);
        let file = File::open(&self.key_archive_path)
            .map_err(|e| anyhow::anyhow!("Failed to open archive: {}", e))?;
        let mut archive = Archive::new(file);

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?;
            if entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                == file_name
            {
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents)?;
                let encrypted_file_data =
                    EncryptedFileData::deserialize_encrypted_file(file_name.as_str(), &contents)?;
                let deserialized_unecrypted_file =
                    encrypted_file_data.decrypt_file_data(self.get_root_key()?)?;
                let private_key =
                    openssl::pkey::PKey::private_key_from_pem(&deserialized_unecrypted_file)?;
                return Ok(private_key);
            }
        }
        Err(anyhow::anyhow!(
            "Key for height {} not found in archive",
            height
        ))
    }
}
