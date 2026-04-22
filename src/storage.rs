pub fn get_root_private_key(
    private_key_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    let block_count = private_key_chain.block_count()?;
    if block_count == 0 {
        anyhow::bail!("get_root_private_key -> No private keys found in the chain");
    }
    let encrypted_root_key_block = match private_key_chain.get_block_by_height(0) {
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
    let encrypted_root_cert_block = match certificate_chain.get_block_by_height(0) {
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
macro_rules! validate_storage {
    ($state: ty) => {
        impl Storage<$state> {
            pub fn validate_storage(&self) -> ValidationResult {
                let cert_block_count = match self.state.certificate_chain.block_count() {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to get certificate block count.");
                        return ValidationResult {
                            cert_height: 0,
                            key_height: 0,
                            cert_blockchain_valid: None,
                            key_blockchain_valid: None,
                            cert_signatures_validation_results: None,
                            key_signatures_validation_results: None,
                            error_message: Some(format!("validate_storage -> Failed to get certificate block count: {}", e)),
                        };
                    }
                };
                let key_block_count = match self.state.private_key_chain.block_count() {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to get private key block count.");
                        return ValidationResult {
                            cert_height: 0,
                            key_height: 0,
                            cert_blockchain_valid: None,
                            key_blockchain_valid: None,
                            cert_signatures_validation_results: None,
                            key_signatures_validation_results: None,
                            error_message: Some(format!("validate_storage -> Failed to get private key block count: {}", e)),
                        };
                    }
                };
                let mut validation_result = ValidationResult {
                    cert_height: 0,
                    key_height: 0,
                    cert_blockchain_valid: None,
                    key_blockchain_valid: None,
                    cert_signatures_validation_results: Some(std::collections::HashMap::new()),
                    key_signatures_validation_results: Some(std::collections::HashMap::new()),
                    error_message: None,
                };
                if cert_block_count == 0 && key_block_count == 0 {
                    return ValidationResult {
                        cert_height: 0,
                        key_height: 0,
                        cert_blockchain_valid: Some(true),
                        key_blockchain_valid: Some(true),
                        cert_signatures_validation_results: None,
                        key_signatures_validation_results: None,
                        error_message: None,
                    };
                }
                validation_result.cert_blockchain_valid = match self.state.certificate_chain.validate() {
                    Ok(()) => Some(true),
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to validate certificate blockchain.");
                        validation_result.error_message =
                            Some(format!("validate_storage -> Failed to validate certificate blockchain: {}", e));
                        Some(false)
                    }
                };
                validation_result.key_blockchain_valid = match self.state.private_key_chain.validate() {
                    Ok(()) => Some(true),
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to validate private key blockchain.");
                        validation_result.error_message =
                            Some(format!("validate_storage -> Failed to validate private key blockchain: {}", e));
                        Some(false)
                    }
                };
                if validation_result.cert_blockchain_valid == Some(false)
                    || validation_result.key_blockchain_valid == Some(false)
                {
                    validation_result.error_message = Some(format!(
                        "validate_storage -> Blockchain validation failed: cert_blockchain_valid={}, key_blockchain_valid={}",
                        validation_result.cert_blockchain_valid.unwrap_or(false),
                        validation_result.key_blockchain_valid.unwrap_or(false)
                    ));
                    return validation_result;
                }
                if cert_block_count != key_block_count {
                    tracing::error!(
                        cert_block_count,
                        key_block_count,
                        "validate_storage -> Certificate and private key block counts do not match."
                    );
                    validation_result.error_message = Some(format!(
                        "validate_storage -> Certificate and private key block counts do not match: cert_block_count={}, key_block_count={}",
                        cert_block_count, key_block_count
                    ));
                    return validation_result;
                }
                for i in 1..cert_block_count - 1 {
                    validation_result.cert_height = i;
                    validation_result.key_height = i;
                    let (cert_block, cert_signature) = match self
                        .state
                        .certificate_chain
                        .get_block_by_height(i)
                    {
                        (Ok(block), Ok(signature)) => (block, signature),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(error = %e, "validate_storage -> Failed to get certificate block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "validate_storage -> Failed to get certificate block at height {}: {}",
                                i, e
                            ));
                            return validation_result;
                        }
                    };
                    let (cert, verified) = match crate::encryption::verify_and_decrypt_cert(
                        cert_block.block_data().as_slice(),
                        cert_signature.as_slice(),
                        match crate::encryption::get_app_private_key(&self.app_config.clone()) {
                            Ok(key) => key,
                            Err(e) => {
                                tracing::error!(error = %e, "validate_storage -> Failed to get app private key for signature verification of certificate block at height {}.", i);
                                validation_result.error_message = Some(format!(
                                    "validate_storage -> Failed to get app private key for signature verification of certificate block at height {}: {}",
                                    i, e
                                ));
                                return validation_result;
                            }
                        },
                    ) {
                        (Ok(cert), Ok(verified)) => (cert, verified),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(error = %e, "validate_storage -> Failed to verify and decrypt certificate block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "validate_storage -> Failed to verify and decrypt certificate block at height {}: {}",
                                i, e
                            ));
                            return validation_result;
                        }
                    };
                    validation_result
                        .cert_signatures_validation_results
                        .as_mut()
                        .unwrap()
                        .insert(i, verified);
                    let (key_block, key_signature) = match self
                        .state
                        .private_key_chain
                        .get_block_by_height(i)
                    {
                        (Ok(block), Ok(signature)) => (block, signature),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(error = %e, "validate_storage -> Failed to get private key block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "validate_storage -> Failed to get private key block at height {}: {}",
                                i, e
                            ));
                            return validation_result;
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
                            validation_result.error_message = Some(format!(
                                "validate_storage -> Failed to verify signature of private key block at height {}: {}",
                                i, e
                            ));
                            return validation_result;
                        }
                    };
                    validation_result
                        .key_signatures_validation_results
                        .as_mut()
                        .unwrap()
                        .insert(i, key_sig_verified);
                }
                return validation_result;
            }
        }
    };
}

validate_storage!(crate::storage_created::Created);
validate_storage!(crate::storage_admin::Admin);

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

pub fn get_state(app_config: &crate::configs::AppConfig) -> StorageStatusResults {
    let mut storage_status = StorageStatusResults {
        app_cert_exists: None,
        app_key_exists: None,
        cert_path_exists: None,
        key_path_exists: None,
        crl_path_exists: None,
        cert_chain_openable: None,
        key_chain_openable: None,
        crl_chain_openable: None,
        validation_result: None,
        storage_state: StorageState::Inconsistent,
        error_message: None,
    };
    match app_config.key_exports.app_cert_path.exists() {
        true => {
            tracing::info!(
                "get_state -> App certificate file exists at path: {:?}",
                app_config.key_exports.app_cert_path
            );
            match std::fs::read(&app_config.key_exports.app_cert_path) {
                Ok(_) => {
                    tracing::info!(
                        "get_state -> App certificate file is readable at path: {:?}",
                        app_config.key_exports.app_cert_path
                    );
                    storage_status.app_cert_exists = Some(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "get_state -> App certificate file is not readable at path: {:?}", app_config.key_exports.app_cert_path);
                    storage_status.app_cert_exists = Some(false);
                }
            }
        }
        false => {
            tracing::info!(
                "get_state -> App certificate file does not exist at path: {:?}",
                app_config.key_exports.app_cert_path
            );
            storage_status.app_cert_exists = Some(false);
        }
    };
    match app_config.key_exports.app_key_path.exists() {
        true => {
            tracing::info!(
                "get_state -> App private key file exists at path: {:?}",
                app_config.key_exports.app_key_path
            );
            match std::fs::read(&app_config.key_exports.app_key_path) {
                Ok(_) => {
                    tracing::info!(
                        "get_state -> App private key file is readable at path: {:?}",
                        app_config.key_exports.app_key_path
                    );
                    storage_status.app_key_exists = Some(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "get_state -> App private key file is not readable at path: {:?}", app_config.key_exports.app_key_path);
                    storage_status.app_key_exists = Some(false);
                }
            }
        }
        false => {
            tracing::info!(
                "get_state -> App private key file does not exist at path: {:?}",
                app_config.key_exports.app_key_path
            );
            storage_status.app_key_exists = Some(false);
        }
    };
    match app_config.blockchains.certificate_path.exists() {
        true => {
            tracing::info!(
                "get_state -> Certificate blockchain path exists: {:?}",
                app_config.blockchains.certificate_path
            );
            storage_status.cert_path_exists = Some(true);
            match libblockchain::blockchain::open_chain(
                match app_config.blockchains.certificate_path.to_str() {
                    Some(path) => path,
                    None => {
                        tracing::error!(
                            error = "Failed to parse certificate path from app_config",
                            "get_state -> Failed to parse certificate path from app_config"
                        );
                        storage_status.error_message =
                            Some("Failed to parse certificate path from app_config".to_string());
                        return storage_status;
                    }
                },
            ) {
                Ok(_) => {
                    tracing::info!(
                        "get_state -> Certificate blockchain is openable at path: {:?}",
                        app_config.blockchains.certificate_path
                    );
                    storage_status.cert_chain_openable = Some(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "get_state -> Certificate blockchain is not openable at path: {:?}", app_config.blockchains.certificate_path);
                    storage_status.cert_chain_openable = Some(false);
                }
            }
        }
        false => {
            tracing::info!(
                "get_state -> Certificate blockchain path does not exist: {:?}",
                app_config.blockchains.certificate_path
            );
            storage_status.cert_path_exists = Some(false);
        }
    };
    match app_config.blockchains.private_key_path.exists() {
        true => {
            tracing::info!(
                "get_state -> Private key blockchain path exists: {:?}",
                app_config.blockchains.private_key_path
            );
            match libblockchain::blockchain::open_chain(
                match app_config.blockchains.private_key_path.to_str() {
                    Some(path) => path,
                    None => {
                        tracing::error!(
                            error = "Failed to parse private key path from app_config",
                            "get_state -> Failed to parse private key path from app_config"
                        );
                        storage_status.error_message =
                            Some("Failed to parse private key path from app_config".to_string());
                        return storage_status;
                    }
                },
            ) {
                Ok(_) => {
                    tracing::info!(
                        "get_state -> Private key blockchain is openable at path: {:?}",
                        app_config.blockchains.private_key_path
                    );
                    storage_status.key_chain_openable = Some(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "get_state -> Private key blockchain is not openable at path: {:?}", app_config.blockchains.private_key_path);
                    storage_status.key_chain_openable = Some(false);
                }
            }
        }
        false => {
            tracing::info!(
                "get_state -> Private key blockchain path does not exist: {:?}",
                app_config.blockchains.private_key_path
            );
            storage_status.key_path_exists = Some(false);
        }
    };
    match app_config.blockchains.crl_path.exists() {
        true => {
            tracing::info!(
                "get_state -> CRL blockchain path exists: {:?}",
                app_config.blockchains.crl_path
            );
            match libblockchain::blockchain::open_chain(
                match app_config.blockchains.crl_path.to_str() {
                    Some(path) => path,
                    None => {
                        tracing::error!(
                            error = "Failed to parse CRL path from app_config",
                            "get_state -> Failed to parse CRL path from app_config"
                        );
                        storage_status.error_message =
                            Some("Failed to parse CRL path from app_config".to_string());
                        return storage_status;
                    }
                },
            ) {
                Ok(_) => {
                    tracing::info!(
                        "get_state -> CRL blockchain is openable at path: {:?}",
                        app_config.blockchains.crl_path
                    );
                    storage_status.crl_chain_openable = Some(true);
                }
                Err(e) => {
                    tracing::error!(error = %e, "get_state -> CRL blockchain is not openable at path: {:?}", app_config.blockchains.crl_path);
                    storage_status.crl_chain_openable = Some(false);
                }
            }
        }
        false => {
            tracing::info!(
                "get_state -> CRL blockchain path does not exist: {:?}",
                app_config.blockchains.crl_path
            );
            storage_status.crl_path_exists = Some(false);
        }
    };
    if !storage_status.app_cert_exists.unwrap_or(false)
        || !storage_status.app_key_exists.unwrap_or(false)
        || !storage_status.cert_chain_openable.unwrap_or(false)
        || !storage_status.key_chain_openable.unwrap_or(false)
        || !storage_status.crl_chain_openable.unwrap_or(false)
    {
        storage_status.storage_state = StorageState::Inconsistent;
        storage_status.error_message = Some(
            "validate_storage -> Storage is in an inconsistent state: some files exist while others do not."
                .to_string(),
        );
        return storage_status;
    }
    if !storage_status.app_cert_exists.unwrap_or(false)
        && !storage_status.app_key_exists.unwrap_or(false)
        && !storage_status.cert_path_exists.unwrap_or(false)
        && !storage_status.key_path_exists.unwrap_or(false)
        && !storage_status.crl_path_exists.unwrap_or(false)
    {
        storage_status.storage_state = StorageState::Empty;
        return storage_status;
    }

    if storage_status.app_cert_exists.unwrap_or(false)
        && storage_status.app_key_exists.unwrap_or(false)
        && storage_status.cert_chain_openable.unwrap_or(false)
        && storage_status.key_chain_openable.unwrap_or(false)
        && storage_status.crl_chain_openable.unwrap_or(false)
    {
        storage_status.storage_state = StorageState::Created;
        let storage = Storage::<crate::storage_created::Created> {
            state: crate::storage_created::Created {
                certificate_chain: match libblockchain::blockchain::open_chain(
                    match app_config.blockchains.certificate_path.to_str() {
                        Some(path) => path,
                        None => {
                            storage_status.error_message = Some(
                                "validate_storage -> Failed to parse certificate path from app_config".to_string(),
                            );
                            return storage_status;
                        }
                    },
                ) {
                    Ok(chain) => chain,
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to open certificate blockchain.");
                        storage_status.error_message = Some(format!(
                            "validate_storage -> Failed to open certificate blockchain: {}",
                            e
                        ));
                        return storage_status;
                    }
                },
                private_key_chain: match libblockchain::blockchain::open_chain(
                    match app_config.blockchains.private_key_path.to_str() {
                        Some(path) => path,
                        None => {
                            storage_status.error_message = Some(
                                "validate_storage -> Failed to parse private key path from app_config".to_string(),
                            );
                            return storage_status;
                        }
                    },
                ) {
                    Ok(chain) => chain,
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to open private key blockchain.");
                        storage_status.error_message = Some(format!(
                            "validate_storage -> Failed to open private key blockchain: {}",
                            e
                        ));
                        return storage_status;
                    }
                },
                crl_chain: match libblockchain::blockchain::open_chain(
                    match app_config.blockchains.crl_path.to_str() {
                        Some(path) => path,
                        None => {
                            storage_status.error_message = Some(
                                "validate_storage -> Failed to parse CRL path from app_config"
                                    .to_string(),
                            );
                            return storage_status;
                        }
                    },
                ) {
                    Ok(chain) => chain,
                    Err(e) => {
                        tracing::error!(error = %e, "validate_storage -> Failed to open CRL blockchain.");
                        storage_status.error_message = Some(format!(
                            "validate_storage -> Failed to open CRL blockchain: {}",
                            e
                        ));
                        return storage_status;
                    }
                },
            },
            app_config: app_config.clone(),
        };
        storage_status.validation_result = Some(storage.validate_storage());
        if storage_status
            .validation_result
            .as_ref()
            .unwrap()
            .error_message
            .is_some()
        {
            storage_status.storage_state = StorageState::Inconsistent;
            return storage_status;
        }
        if storage_status
            .validation_result
            .as_ref()
            .unwrap()
            .cert_height
            == 2
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_height
                == 2
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .cert_blockchain_valid
                == Some(true)
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_blockchain_valid
                == Some(true)
        {
            storage_status.storage_state = StorageState::Initialized;
            return storage_status;
        }
        if storage_status
            .validation_result
            .as_ref()
            .unwrap()
            .cert_height
            > 2
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_height
                > 2
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .cert_blockchain_valid
                == Some(true)
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_blockchain_valid
                == Some(true)
        {
            storage_status.storage_state = StorageState::Ready;
            return storage_status;
        }
        if storage_status
            .validation_result
            .as_ref()
            .unwrap()
            .cert_height
            > 2
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_height
                > 2
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .cert_blockchain_valid
                == Some(true)
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_blockchain_valid
                == Some(true)
        {
            if storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .cert_signatures_validation_results
                .as_ref()
                .unwrap()
                .values()
                .any(|&valid| !valid)
                || storage_status
                    .validation_result
                    .as_ref()
                    .unwrap()
                    .key_signatures_validation_results
                    .as_ref()
                    .unwrap()
                    .values()
                    .any(|&valid| !valid)
            {
                storage_status.storage_state = StorageState::Inconsistent;
                storage_status.error_message = Some(
                    "validate_storage -> Storage is in an inconsistent state: some blocks failed signature validation."
                        .to_string(),
                );
                return storage_status;
            } else {
                storage_status.storage_state = StorageState::Ready;
                return storage_status;
            }
        }
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
