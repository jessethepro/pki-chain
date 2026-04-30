pub struct Empty {}

impl crate::storage::Storage<Empty> {
    pub fn create_storage(self) -> crate::storage::Storage<crate::storage_created::Created> {
        let certificate_chain = match libblockchain::blockchain::open_chain(
            match self.app_config.blockchains.certificate_path.to_str() {
                Some(path) => path,
                None => {
                    tracing::error!(
                        "create_storage -> Failed to parse certificate path from app_config"
                    );
                    std::process::exit(1);
                }
            },
        ) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!(error = %e, "create_storage -> Failed to open certificate chain.");
                std::process::exit(1);
            }
        };
        let private_key_chain = match libblockchain::blockchain::open_chain(
            match self.app_config.blockchains.private_key_path.to_str() {
                Some(path) => path,
                None => {
                    tracing::error!(
                        "create_storage -> Failed to parse private key path from app_config"
                    );
                    std::process::exit(1);
                }
            },
        ) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!(error = %e, "create_storage -> Failed to open private key chain.");
                std::process::exit(1);
            }
        };
        let crl_chain = match libblockchain::blockchain::open_chain(
            match self.app_config.blockchains.crl_path.to_str() {
                Some(path) => path,
                None => {
                    tracing::error!("create_storage -> Failed to parse CRL path from app_config");
                    std::process::exit(1);
                }
            },
        ) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!(error = %e, "create_storage -> Failed to open CRL chain.");
                std::process::exit(1);
            }
        };
        if !self.app_config.key_exports.app_cert_path.exists()
            && !self.app_config.key_exports.app_key_path.exists()
        {
            match self.app_config.key_exports.app_cert_path.parent() {
                Some(dir) => match std::fs::create_dir_all(dir) {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "create_storage -> Failed to create parent directory for app certificate export path.");
                        std::process::exit(1);
                    }
                },
                None => {
                    tracing::error!("create_storage -> Failed to get parent directory of app certificate export path.");
                    std::process::exit(1);
                }
            };
            match self.app_config.key_exports.app_key_path.parent() {
                Some(dir) => match std::fs::create_dir_all(dir) {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "create_storage -> Failed to create parent directory for app key export path.");
                        std::process::exit(1);
                    }
                },
                None => {
                    tracing::error!(
                        "create_storage -> Failed to get parent directory of app key export path."
                    );
                    std::process::exit(1);
                }
            };
            let (app_cert, app_key) = match crate::encryption::create_app_cert_and_key_pair() {
                Ok((cert, key)) => (cert, key),
                Err(e) => {
                    tracing::error!(error = %e, "create_storage -> Failed to create app certificate and key pair.");
                    std::process::exit(1);
                }
            };
            match app_cert.to_pem() {
                Ok(pem) => {
                    let cert_path = self.app_config.key_exports.app_cert_path.clone();
                    match std::fs::write(&cert_path, pem) {
                        Ok(_) => {
                            tracing::info!("create_storage -> Successfully exported app certificate to PEM file.");
                            let cert_perms = std::os::unix::fs::PermissionsExt::from_mode(0o400);
                            match std::fs::set_permissions(&cert_path, cert_perms) {
                                Ok(_) => (),
                                Err(e) => {
                                    tracing::error!(error = %e, "create_storage -> Failed to set permissions for app certificate PEM file.");
                                    std::process::exit(1);
                                }
                            };
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "create_storage -> Failed to write app certificate PEM file.");
                            std::process::exit(1);
                        }
                    };
                }
                Err(e) => {
                    tracing::error!(error = %e, "create_storage -> Failed to serialize app certificate to PEM.");
                    std::process::exit(1);
                }
            };
            match app_key.private_key_to_pem_pkcs8() {
                Ok(pem) => {
                    let key_path = self.app_config.key_exports.app_key_path.clone();
                    match std::fs::write(&key_path, pem) {
                        Ok(_) => {
                            tracing::info!("create_storage -> Successfully exported app private key to PEM file.");
                            let key_perms = std::os::unix::fs::PermissionsExt::from_mode(0o400);
                            match std::fs::set_permissions(&key_path, key_perms) {
                                Ok(_) => (),
                                Err(e) => {
                                    tracing::error!(error = %e, "create_storage -> Failed to set permissions for app private key PEM file.");
                                    std::process::exit(1);
                                }
                            };
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "create_storage -> Failed to write app private key PEM file.");
                            std::process::exit(1);
                        }
                    };
                }
                Err(e) => {
                    tracing::error!(error = %e, "create_storage -> Failed to serialize app private key to PEM.");
                    std::process::exit(1);
                }
            };
        };
        crate::storage::Storage {
            state: crate::storage_created::Created {
                certificate_chain,
                private_key_chain,
                crl_chain,
            },
            app_config: self.app_config.clone(),
        }
    }
}
