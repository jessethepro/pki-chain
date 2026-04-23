const ROOT_BLOCK_HEIGHT: u64 = 0;
const ADMIN_BLOCK_HEIGHT: u64 = 1; // Represents the block height where the admin intermediate certificate and intermediate key are stored in the blockchains.

pub fn get_root_private_key(
    private_key_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    let block_count = private_key_chain.block_count()?;
    if block_count == 0 {
        anyhow::bail!("get_root_private_key -> No private keys found in the chain");
    }
    let encrypted_root_key_block = match private_key_chain.get_block_by_height(ROOT_BLOCK_HEIGHT) {
        (Ok(block), Ok(_)) => block,
        _ => anyhow::bail!("get_root_private_key -> No private keys found in the chain"),
    };
    let decrypted_root_key_der = crate::encryption::decrypt_data(
        encrypted_root_key_block.block_data().as_slice(),
        app_private_key,
    )?;
    Ok(openssl::pkey::PKey::private_key_from_der(
        &decrypted_root_key_der,
    )?)
}

pub fn get_root_certificate(
    certificate_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<openssl::x509::X509> {
    let block_count = certificate_chain.block_count()?;
    if block_count == 0 {
        anyhow::bail!("get_root_certificate -> No certificates found in the chain");
    }
    let encrypted_root_cert_block = match certificate_chain.get_block_by_height(ROOT_BLOCK_HEIGHT) {
        (Ok(block), Ok(_)) => block,
        _ => anyhow::bail!("get_root_certificate -> No certificates found in the chain"),
    };
    let decrypted_root_cert_der = crate::encryption::decrypt_data(
        encrypted_root_cert_block.block_data().as_slice(),
        app_private_key,
    )?;
    let root_cert = openssl::x509::X509::from_der(&decrypted_root_cert_der)?;
    Ok(root_cert)
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct ValidationResult {
    pub cert_height: u64,
    pub key_height: u64,
    pub cert_blockchain_valid: Option<bool>,
    pub key_blockchain_valid: Option<bool>,
    pub cert_signatures_validation_results: Option<std::collections::HashMap<u64, bool>>,
    pub key_signatures_validation_results: Option<std::collections::HashMap<u64, bool>>,
    pub error_message: Option<String>,
}

fn validate_storage(app_config: &crate::configs::AppConfig) -> ValidationResult {
    let mut validation_results = ValidationResult {
        cert_height: 0,
        key_height: 0,
        cert_blockchain_valid: None,
        key_blockchain_valid: None,
        cert_signatures_validation_results: None,
        key_signatures_validation_results: None,
        error_message: None,
    };
    let cert_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.certificate_path.to_str() {
            Some(path) => path,
            None => {
                tracing::error!(
                    error = "Failed to parse certificate path from app_config",
                    "validate_storage -> Failed to parse certificate path from app_config"
                );
                validation_results.error_message =
                    Some("Failed to parse certificate path from app_config".to_string());
                return validation_results;
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to open certificate blockchain for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to open certificate blockchain for validation: {}",
                e
            ));
            return validation_results;
        }
    };
    validation_results.cert_blockchain_valid = match cert_chain.validate() {
        Ok(()) => Some(true),
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to validate certificate blockchain.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to validate certificate blockchain: {}",
                e
            ));
            return validation_results;
        }
    };
    validation_results.cert_height = match cert_chain.block_count() {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to get certificate block count.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to get certificate block count: {}",
                e
            ));
            return validation_results;
        }
    };
    let priv_key_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.private_key_path.to_str() {
            Some(path) => path,
            None => {
                tracing::error!(
                    error = "Failed to parse private key path from app_config",
                    "validate_storage -> Failed to parse private key path from app_config"
                );
                validation_results.error_message =
                    Some("Failed to parse private key path from app_config".to_string());
                return validation_results;
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to open private key blockchain for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to open private key blockchain for validation: {}",
                e
            ));
            return validation_results;
        }
    };
    validation_results.key_blockchain_valid = match priv_key_chain.validate() {
        Ok(()) => Some(true),
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to validate private key blockchain.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to validate private key blockchain: {}",
                e
            ));
            return validation_results;
        }
    };
    validation_results.key_height = match priv_key_chain.block_count() {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to get private key block count.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to get private key block count: {}",
                e
            ));
            return validation_results;
        }
    };
    if validation_results.cert_blockchain_valid == Some(false)
        || validation_results.key_blockchain_valid == Some(false)
    {
        validation_results.error_message = Some(format!(
                        "validate_storage -> Blockchain validation failed: cert_blockchain_valid={}, key_blockchain_valid={}",
                        validation_results.cert_blockchain_valid.unwrap_or(false),
                        validation_results.key_blockchain_valid.unwrap_or(false)
                    ));
        return validation_results;
    }
    if validation_results.cert_height != validation_results.key_height {
        tracing::error!(
            cert_block_count = validation_results.cert_height,
            key_block_count = validation_results.key_height,
            "validate_storage -> Certificate and private key block counts do not match."
        );
        validation_results.error_message = Some(format!(
                        "validate_storage -> Certificate and private key block counts do not match: cert_block_count={}, key_block_count={}",
                        validation_results.cert_height, validation_results.key_height
                    ));
        return validation_results;
    }
    if validation_results.cert_height == 0 || validation_results.key_height == 0 {
        tracing::info!("validate_storage -> Certificate and private key blockchains are empty.");
        return validation_results;
    }
    for i in 0..validation_results.cert_height - 1 {
        let (cert_block, cert_signature) = match cert_chain.get_block_by_height(i) {
            (Ok(block), Ok(signature)) => (block, signature),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "validate_storage -> Failed to get certificate block at height {}.", i);
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to get certificate block at height {}: {}",
                    i, e
                ));
                return validation_results;
            }
        };
        let (cert, verified) = match crate::encryption::verify_and_decrypt_cert(
            cert_block.block_data().as_slice(),
            cert_signature.as_slice(),
            match crate::encryption::get_app_private_key(&app_config.clone()) {
                Ok(key) => key,
                Err(e) => {
                    tracing::error!(error = %e, "validate_storage -> Failed to get app private key for signature verification of certificate block at height {}.", i);
                    validation_results.error_message = Some(format!(
                                    "validate_storage -> Failed to get app private key for signature verification of certificate block at height {}: {}",
                                    i, e
                                ));
                    return validation_results;
                }
            },
        ) {
            (Ok(cert), Ok(verified)) => (cert, verified),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "validate_storage -> Failed to verify and decrypt certificate block at height {}.", i);
                validation_results.error_message = Some(format!(
                                "validate_storage -> Failed to verify and decrypt certificate block at height {}: {}",
                                i, e
                            ));
                return validation_results;
            }
        };
        validation_results
            .cert_signatures_validation_results
            .as_mut()
            .unwrap()
            .insert(i, verified);
        let (key_block, key_signature) = match priv_key_chain.get_block_by_height(i) {
            (Ok(block), Ok(signature)) => (block, signature),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "validate_storage -> Failed to get private key block at height {}.", i);
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to get private key block at height {}: {}",
                    i, e
                ));
                return validation_results;
            }
        };
        let key_sig_verified = match crate::encryption::verify_priv_key_signature_with_cert(
            key_block.block_data().as_slice(),
            key_signature.as_slice(),
            &cert,
        ) {
            Ok(verified) => verified,
            Err(e) => {
                tracing::error!(error = %e, "validate_storage -> Failed to verify signature of private key block at height {}.", i);
                validation_results.error_message = Some(format!(
                                "validate_storage -> Failed to verify signature of private key block at height {}: {}",
                                i, e
                            ));
                return validation_results;
            }
        };
        validation_results
            .key_signatures_validation_results
            .as_mut()
            .unwrap()
            .insert(i, key_sig_verified);
    }
    validation_results
}

pub struct Storage<State> {
    pub state: State,
    pub app_config: crate::configs::AppConfig,
}

#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum StorageState {
    Empty,
    Created,
    Initialized,
    Ready,
    Inconsistent,
}
#[derive(serde::Serialize, Debug, Clone)]
pub struct StorageStatusResults {
    pub app_cert_exists: Option<bool>,
    pub app_key_exists: Option<bool>,
    pub app_certificate_readable: Option<bool>,
    pub app_key_readable: Option<bool>,
    pub app_certificate_valid: Option<bool>,
    pub cert_path_exists: Option<bool>,
    pub key_path_exists: Option<bool>,
    pub crl_path_exists: Option<bool>,
    pub cert_chain_openable: Option<bool>,
    pub key_chain_openable: Option<bool>,
    pub crl_chain_openable: Option<bool>,
    pub validation_result: Option<ValidationResult>,
    pub storage_state: StorageState,
    pub error_message: Option<String>,
}

fn check_storage_paths_exist(app_config: &crate::configs::AppConfig) -> StorageStatusResults {
    StorageStatusResults {
        app_cert_exists: Some(app_config.key_exports.app_cert_path.exists()),
        app_key_exists: Some(app_config.key_exports.app_key_path.exists()),
        app_certificate_readable: None,
        app_key_readable: None,
        app_certificate_valid: None,
        cert_path_exists: Some(app_config.blockchains.certificate_path.exists()),
        key_path_exists: Some(app_config.blockchains.private_key_path.exists()),
        crl_path_exists: Some(app_config.blockchains.crl_path.exists()),
        cert_chain_openable: None,
        key_chain_openable: None,
        crl_chain_openable: None,
        validation_result: None,
        storage_state: StorageState::Inconsistent,
        error_message: None,
    }
}

fn check_app_certificate_and_key_readable(
    storage_status: &mut StorageStatusResults,
    app_config: &crate::configs::AppConfig,
) {
    if storage_status.app_cert_exists.unwrap_or(false) {
        match std::fs::read(&app_config.key_exports.app_cert_path) {
            Ok(_) => {
                tracing::info!(
                    "check_app_certificate_and_key_readable -> App certificate file is readable at path: {:?}",
                    app_config.key_exports.app_cert_path
                );
                storage_status.app_certificate_readable = Some(true);
            }
            Err(e) => {
                tracing::error!(error = %e, "check_app_certificate_and_key_readable -> App certificate file is not readable at path: {:?}", app_config.key_exports.app_cert_path);
                storage_status.app_certificate_readable = Some(false);
                storage_status.error_message = Some(format!(
                    "check_app_certificate_and_key_readable -> App certificate file is not readable at path: {:?}",
                    app_config.key_exports.app_cert_path
                ));
            }
        }
    } else {
        storage_status.app_certificate_readable = Some(false);
    }
    if storage_status.app_key_exists.unwrap_or(false) {
        match std::fs::read(&app_config.key_exports.app_key_path) {
            Ok(_) => {
                tracing::info!(
                    "check_app_certificate_and_key_readable -> App private key file is readable at path: {:?}",
                    app_config.key_exports.app_key_path
                );
                storage_status.app_key_readable = Some(true);
            }
            Err(e) => {
                tracing::error!(error = %e, "check_app_certificate_and_key_readable -> App private key file is not readable at path: {:?}", app_config.key_exports.app_key_path);
                storage_status.app_key_readable = Some(false);
                storage_status.error_message = Some(format!(
                    "check_app_certificate_and_key_readable -> App private key file is not readable at path: {:?}",
                    app_config.key_exports.app_key_path
                ));
            }
        }
    } else {
        storage_status.app_key_readable = Some(false);
    }
}

fn check_app_certificate_is_valid(
    storage_status: &mut StorageStatusResults,
    app_config: &crate::configs::AppConfig,
) {
    if !storage_status.app_certificate_readable.unwrap_or(false)
        || !storage_status.app_key_readable.unwrap_or(false)
    {
        storage_status.app_certificate_valid = Some(false);
        return;
    }
    let certificate_data = match std::fs::read(&app_config.key_exports.app_cert_path) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!(error = %e, "check_app_certificate_is_valid -> Failed to read app certificate file for validity check at path: {:?}", app_config.key_exports.app_cert_path);
            storage_status.app_certificate_valid = Some(false);
            storage_status.error_message = Some(format!(
                "check_app_certificate_is_valid -> Failed to read app certificate file for validity check at path: {:?}",
                app_config.key_exports.app_cert_path
            ));
            return;
        }
    };

    let certificate = match openssl::x509::X509::from_pem(&certificate_data)
        .or_else(|_| openssl::x509::X509::from_der(&certificate_data))
    {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "check_app_certificate_is_valid -> App certificate file is not a valid X.509 certificate at path: {:?}", app_config.key_exports.app_cert_path);
            storage_status.app_certificate_valid = Some(false);
            storage_status.error_message = Some(format!(
                "check_app_certificate_is_valid -> App certificate file is not a valid X.509 certificate at path: {:?}",
                app_config.key_exports.app_cert_path
            ));
            return;
        }
    };

    let private_key_data = match std::fs::read(&app_config.key_exports.app_key_path) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!(error = %e, "check_app_certificate_is_valid -> Failed to read app private key file for key-pair validation at path: {:?}", app_config.key_exports.app_key_path);
            storage_status.app_certificate_valid = Some(false);
            storage_status.error_message = Some(format!(
                "check_app_certificate_is_valid -> Failed to read app private key file for key-pair validation at path: {:?}",
                app_config.key_exports.app_key_path
            ));
            return;
        }
    };

    let private_key = match openssl::pkey::PKey::private_key_from_pem(&private_key_data) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "check_app_certificate_is_valid -> Failed to parse app private key PEM for key-pair validation at path: {:?}", app_config.key_exports.app_key_path);
            storage_status.app_certificate_valid = Some(false);
            storage_status.error_message = Some(format!(
                "check_app_certificate_is_valid -> Failed to parse app private key PEM for key-pair validation at path: {:?}",
                app_config.key_exports.app_key_path
            ));
            return;
        }
    };

    let certificate_public_key = match certificate.public_key() {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "check_app_certificate_is_valid -> Failed to extract public key from app certificate at path: {:?}", app_config.key_exports.app_cert_path);
            storage_status.app_certificate_valid = Some(false);
            storage_status.error_message = Some(format!(
                "check_app_certificate_is_valid -> Failed to extract public key from app certificate at path: {:?}",
                app_config.key_exports.app_cert_path
            ));
            return;
        }
    };

    if certificate_public_key.public_eq(&private_key) {
        tracing::info!(
            "check_app_certificate_is_valid -> App certificate is valid and matches app private key at paths: cert={:?}, key={:?}",
            app_config.key_exports.app_cert_path,
            app_config.key_exports.app_key_path
        );
        storage_status.app_certificate_valid = Some(true);
    } else {
        tracing::error!(
            "check_app_certificate_is_valid -> App certificate public key does not match app private key at paths: cert={:?}, key={:?}",
            app_config.key_exports.app_cert_path,
            app_config.key_exports.app_key_path
        );
        storage_status.error_message = Some(format!(
            "check_app_certificate_is_valid -> App certificate public key does not match app private key at paths: cert={:?}, key={:?}",
            app_config.key_exports.app_cert_path,
            app_config.key_exports.app_key_path
        ));
        storage_status.app_certificate_valid = Some(false);
    }
}

fn check_blockchains_are_openable(
    storage_status: &mut StorageStatusResults,
    app_config: &crate::configs::AppConfig,
) {
    if storage_status.cert_path_exists.unwrap_or(false) {
        match libblockchain::blockchain::open_chain(
            match app_config.blockchains.certificate_path.to_str() {
                Some(path) => path,
                None => {
                    tracing::error!(
                        error = "Failed to parse certificate path from app_config",
                        "check_blockchains_are_openable -> Failed to parse certificate path from app_config"
                    );
                    storage_status.error_message =
                        Some("Failed to parse certificate path from app_config".to_string());
                    storage_status.cert_chain_openable = Some(false);
                    return;
                }
            },
        ) {
            Ok(_) => {
                tracing::info!(
                    "check_blockchains_are_openable -> Certificate blockchain is openable at path: {:?}",
                    app_config.blockchains.certificate_path
                );
                storage_status.cert_chain_openable = Some(true);
            }
            Err(e) => {
                tracing::error!(error = %e, "check_blockchains_are_openable -> Certificate blockchain is not openable at path: {:?}", app_config.blockchains.certificate_path);
                storage_status.cert_chain_openable = Some(false);
                storage_status.error_message = Some(format!(
                    "check_blockchains_are_openable -> Certificate blockchain is not openable at path: {:?}",
                    app_config.blockchains.certificate_path
                ));
            }
        }
    } else {
        storage_status.cert_chain_openable = Some(false);
    }
    if storage_status.key_path_exists.unwrap_or(false) {
        match libblockchain::blockchain::open_chain(
            match app_config.blockchains.private_key_path.to_str() {
                Some(path) => path,
                None => {
                    tracing::error!(
                        error = "Failed to parse private key path from app_config",
                        "check_blockchains_are_openable -> Failed to parse private key path from app_config"
                    );
                    storage_status.error_message =
                        Some("Failed to parse private key path from app_config".to_string());
                    storage_status.key_chain_openable = Some(false);
                    return;
                }
            },
        ) {
            Ok(_) => {
                tracing::info!(
                    "check_blockchains_are_openable -> Private key blockchain is openable at path: {:?}",
                    app_config.blockchains.private_key_path
                );
                storage_status.key_chain_openable = Some(true);
            }
            Err(e) => {
                tracing::error!(error = %e, "check_blockchains_are_openable -> Private key blockchain is not openable at path: {:?}", app_config.blockchains.private_key_path);
                storage_status.key_chain_openable = Some(false);
                storage_status.error_message = Some(format!(
                    "check_blockchains_are_openable -> Private key blockchain is not openable at path: {:?}",
                    app_config.blockchains.private_key_path
                ));
            }
        }
    } else {
        storage_status.key_chain_openable = Some(false);
    }
}

fn validate_blockchains(
    storage_status: &mut StorageStatusResults,
    app_config: &crate::configs::AppConfig,
) {
    if storage_status.cert_chain_openable == Some(true)
        && storage_status.key_chain_openable == Some(true)
    {
        storage_status.validation_result = Some(validate_storage(app_config));
    }
}

pub fn get_state(app_config: &crate::configs::AppConfig) -> StorageStatusResults {
    let mut storage_status = check_storage_paths_exist(app_config);
    if storage_status.error_message.is_some() {
        return storage_status;
    }
    check_app_certificate_and_key_readable(&mut storage_status, app_config);
    if storage_status.error_message.is_some() {
        return storage_status;
    }
    check_app_certificate_is_valid(&mut storage_status, app_config);
    if storage_status.error_message.is_some() {
        return storage_status;
    }
    check_blockchains_are_openable(&mut storage_status, app_config);
    if storage_status.error_message.is_some() {
        return storage_status;
    }
    validate_blockchains(&mut storage_status, app_config);
    if storage_status.validation_result.is_some()
        && storage_status
            .validation_result
            .as_ref()
            .unwrap()
            .error_message
            .is_some()
    {
        return storage_status;
    }

    // If we reach this point, it means the storage is in the Created state and doesn't contain any key information.
    storage_status
}

pub fn get_api_storage(
    storage: Storage<crate::storage_ready::Ready>,
) -> anyhow::Result<Storage<crate::storage_api::API>> {
    let cert_store =
        match crate::encryption::build_client_auth_store_from_root_ca(&get_root_certificate(
            &storage.state.certificate_chain,
            crate::encryption::get_app_private_key(&storage.app_config)?,
        )?) {
            Ok(store) => store,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "get_api_storage -> Failed to build client auth store: {}",
                    e
                ))
            }
        };
    Ok(Storage {
        state: crate::storage_api::API {
            certificate_chain: storage.state.certificate_chain,
            private_key_chain: storage.state.private_key_chain,
            crl_chain: storage.state.crl_chain,
            cert_store,
            cert_user_intermediate_stack: openssl::stack::Stack::new()?,
            cert_admin_intermediate_stack: openssl::stack::Stack::new()?,
        },
        app_config: storage.app_config.clone(),
    })
}

pub fn get_admin_storage(
    storage: Storage<crate::storage_ready::Ready>,
) -> anyhow::Result<Storage<crate::storage_admin::Admin>> {
    Ok(Storage {
        state: crate::storage_admin::Admin {
            certificate_chain: storage.state.certificate_chain,
            private_key_chain: storage.state.private_key_chain,
            crl_chain: storage.state.crl_chain,
        },
        app_config: storage.app_config.clone(),
    })
}

pub fn get_initialized_storage(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<Storage<crate::storage_initialized::Initialized>> {
    let certificate_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.certificate_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_initialized_storage -> Failed to parse certificate path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to open certificate blockchain.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to open certificate blockchain: {}",
                e
            ));
        }
    };
    let private_key_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.private_key_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_initialized_storage -> Failed to parse private key path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to open private key blockchain.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to open private key blockchain: {}",
                e
            ));
        }
    };
    let crl_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.crl_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_initialized_storage -> Failed to parse CRL path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to open CRL blockchain.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to open CRL blockchain: {}",
                e
            ));
        }
    };
    Ok(Storage {
        state: crate::storage_initialized::Initialized {
            certificate_chain,
            private_key_chain,
            crl_chain,
        },
        app_config: app_config.clone(),
    })
}

pub fn get_created_storage(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<Storage<crate::storage_created::Created>> {
    let certificate_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.certificate_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_created_storage -> Failed to parse certificate path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open certificate blockchain.");
            return Err(anyhow::anyhow!(
                "Failed to open certificate blockchain: {}",
                e
            ));
        }
    };
    let private_key_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.private_key_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "Failed to parse private key path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_created_storage -> Failed to open private key blockchain.");
            return Err(anyhow::anyhow!(
                "get_created_storage -> Failed to open private key blockchain: {}",
                e
            ));
        }
    };
    let crl_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.crl_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_created_storage -> Failed to parse CRL path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_created_storage -> Failed to open CRL blockchain.");
            return Err(anyhow::anyhow!(
                "get_created_storage -> Failed to open CRL blockchain: {}",
                e
            ));
        }
    };
    Ok(Storage {
        state: crate::storage_created::Created {
            certificate_chain,
            private_key_chain,
            crl_chain,
        },
        app_config: app_config.clone(),
    })
}

pub fn get_empty_storage(
    app_config: &crate::configs::AppConfig,
) -> Storage<crate::storage_empty::Empty> {
    Storage {
        state: crate::storage_empty::Empty {},
        app_config: app_config.clone(),
    }
}

pub fn get_ready_storage(
    app_config: &crate::configs::AppConfig,
) -> anyhow::Result<Storage<crate::storage_ready::Ready>> {
    let certificate_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.certificate_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_ready_storage -> Failed to parse certificate path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to open certificate blockchain.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to open certificate blockchain: {}",
                e
            ));
        }
    };
    let private_key_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.private_key_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_ready_storage ->  Failed to parse private key path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to open private key blockchain.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to open private key blockchain: {}",
                e
            ));
        }
    };
    let crl_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.crl_path.to_str() {
            Some(path) => path,
            None => {
                return Err(anyhow::anyhow!(
                    "get_ready_storage -> Failed to parse CRL path from app_config"
                ))
            }
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to open CRL blockchain.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to open CRL blockchain: {}",
                e
            ));
        }
    };
    Ok(Storage {
        state: crate::storage_ready::Ready {
            certificate_chain,
            private_key_chain,
            crl_chain,
        },
        app_config: app_config.clone(),
    })
}
