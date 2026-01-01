use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tar::{Archive, Builder};

pub struct KeyArchive {
    archive_path: PathBuf,
    key_archive_name: String,
}

impl KeyArchive {
    pub fn new(archive_path: PathBuf, key_archive_name: String) -> Self {
        KeyArchive {
            archive_path,
            key_archive_name,
        }
    }

    pub fn extract(&self, destination: &PathBuf) -> anyhow::Result<()> {
        let file = File::open(&self.archive_path)
            .map_err(|e| anyhow::anyhow!("Failed to open archive: {}", e))?;
        let mut archive = Archive::new(file);
        archive
            .unpack(destination)
            .map_err(|e| anyhow::anyhow!("Failed to extract archive: {}", e))?;
        Ok(())
    }

    pub fn list_keys_in_tar(&self) -> Result<HashMap<u64, String>> {
        // Open the tar file
        let file = File::open(&self.archive_path)?;

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

    pub fn add_files_to_key_archive(&self) -> Result<PathBuf> {
        let tar_path = self.archive_path.join(self.key_archive_name.clone());
        let tar_file = if tar_path.exists() {
            fs::File::open(&tar_path).map_err(|e| {
                anyhow::anyhow!("Failed to open archive file at {:?}: {}", tar_path, e)
            })?
        } else {
            fs::File::create(&tar_path).map_err(|e| {
                anyhow::anyhow!("Failed to create archive file at {:?}: {}", tar_path, e)
            })?
        };
        let mut tar_builder = Builder::new(&tar_file);

        for entry in fs::read_dir(&self.archive_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.to_str().unwrap_or("").ends_with(".key.enc") {
                tar_builder
                    .append_path(&path)
                    .map_err(|e| anyhow::anyhow!("Failed to append file to archive: {}", e))?;
            }
        }

        match tar_builder
            .finish()
            .map_err(|e| anyhow::anyhow!("Failed to finalize archive: {}", e))
        {
            Ok(_) => {
                for entry in fs::read_dir(&self.archive_path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.to_str().unwrap_or("").ends_with(".key.enc") {
                        fs::remove_file(&path).map_err(|e| {
                            anyhow::anyhow!("Failed to remove original file {:?}: {}", path, e)
                        })?;
                    }
                }
                tar_file.sync_all().map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to sync archive file to disk at {:?}: {}",
                        tar_path,
                        e
                    )
                })?;
                Ok(tar_path)
            }
            Err(e) => Err(e),
        }
    }
    pub fn get_file_from_key_archive(&self, file_name: &str) -> Result<Vec<u8>> {
        let file = File::open(&self.archive_path)
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
                return Ok(contents);
            }
        }

        Err(anyhow::anyhow!("File {} not found in archive", file_name))
    }
}
