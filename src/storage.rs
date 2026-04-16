pub fn get_root_private_key(
    private_key_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    let block_count = private_key_chain.block_count()?;
    if block_count == 0 {
        anyhow::bail!("No private keys found in the chain");
    }
    let encrypted_root_key_block = match private_key_chain.get_block_by_height(0) {
        (Ok(block), Ok(_)) => block,
        _ => anyhow::bail!("No private keys found in the chain"),
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
        anyhow::bail!("No certificates found in the chain");
    }
    let encrypted_root_cert_block = match certificate_chain.get_block_by_height(0) {
        (Ok(block), Ok(_)) => block,
        _ => anyhow::bail!("No certificates found in the chain"),
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
                        tracing::error!(error = %e, "Storage<Admin>: Failed to get certificate block count.");
                        return ValidationResult {
                            cert_height: 0,
                            key_height: 0,
                            cert_blockchain_valid: None,
                            key_blockchain_valid: None,
                            cert_signatures_validation_results: None,
                            key_signatures_validation_results: None,
                            error_message: Some(format!("Failed to get certificate block count: {}", e)),
                        };
                    }
                };
                let key_block_count = match self.state.private_key_chain.block_count() {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::error!(error = %e, "Storage<Admin>: Failed to get private key block count.");
                        return ValidationResult {
                            cert_height: 0,
                            key_height: 0,
                            cert_blockchain_valid: None,
                            key_blockchain_valid: None,
                            cert_signatures_validation_results: None,
                            key_signatures_validation_results: None,
                            error_message: Some(format!("Failed to get private key block count: {}", e)),
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
                        tracing::error!(error = %e, "Storage<Admin>: Failed to validate certificate blockchain.");
                        validation_result.error_message =
                            Some(format!("Failed to validate certificate blockchain: {}", e));
                        Some(false)
                    }
                };
                validation_result.key_blockchain_valid = match self.state.private_key_chain.validate() {
                    Ok(()) => Some(true),
                    Err(e) => {
                        tracing::error!(error = %e, "Storage<Admin>: Failed to validate private key blockchain.");
                        validation_result.error_message =
                            Some(format!("Failed to validate private key blockchain: {}", e));
                        Some(false)
                    }
                };
                if validation_result.cert_blockchain_valid == Some(false)
                    || validation_result.key_blockchain_valid == Some(false)
                {
                    validation_result.error_message = Some(format!(
                        "Blockchain validation failed: cert_blockchain_valid={}, key_blockchain_valid={}",
                        validation_result.cert_blockchain_valid.unwrap_or(false),
                        validation_result.key_blockchain_valid.unwrap_or(false)
                    ));
                    return validation_result;
                }
                if cert_block_count != key_block_count {
                    tracing::error!(
                        cert_block_count,
                        key_block_count,
                        "Storage<Admin>: Certificate and private key block counts do not match."
                    );
                    validation_result.error_message = Some(format!(
                        "Certificate and private key block counts do not match: cert_block_count={}, key_block_count={}",
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
                            tracing::error!(error = %e, "Storage<Admin>: Failed to get certificate block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "Failed to get certificate block at height {}: {}",
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
                                tracing::error!(error = %e, "Storage<Admin>: Failed to get app private key for signature verification of certificate block at height {}.", i);
                                validation_result.error_message = Some(format!(
                                    "Failed to get app private key for signature verification of certificate block at height {}: {}",
                                    i, e
                                ));
                                return validation_result;
                            }
                        },
                    ) {
                        (Ok(cert), Ok(verified)) => (cert, verified),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(error = %e, "Storage<Admin>: Failed to verify and decrypt certificate block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "Failed to verify and decrypt certificate block at height {}: {}",
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
                            tracing::error!(error = %e, "Storage<Admin>: Failed to get private key block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "Failed to get private key block at height {}: {}",
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
                            tracing::error!(error = %e, "Storage<Admin>: Failed to verify signature of private key block at height {}.", i);
                            validation_result.error_message = Some(format!(
                                "Failed to verify signature of private key block at height {}: {}",
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

pub fn get_state(
    app_config: &crate::configs::AppConfig,
    execution_count: u32,
) -> StorageStatusResults {
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
    storage_status.app_cert_exists = Some(app_config.blockchains.certificate_path.exists());
    storage_status.app_key_exists = Some(app_config.blockchains.private_key_path.exists());
    storage_status.cert_path_exists = Some(app_config.blockchains.certificate_path.exists());
    storage_status.key_path_exists = Some(app_config.blockchains.private_key_path.exists());
    storage_status.crl_path_exists = Some(app_config.blockchains.crl_path.exists());
    if storage_status.cert_path_exists == Some(true) {
        storage_status.cert_chain_openable = Some(
            match libblockchain::blockchain::open_chain(
                match app_config.blockchains.certificate_path.to_str() {
                    Some(path) => path,
                    None => {
                        storage_status.error_message =
                            Some("Failed to parse certificate path from app_config".to_string());
                        return storage_status;
                    }
                },
            ) {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open certificate blockchain.");
                    storage_status.error_message =
                        Some(format!("Failed to open certificate blockchain: {}", e));
                    false
                }
            },
        );
    }
    if storage_status.key_path_exists == Some(true) {
        storage_status.key_chain_openable = Some(
            match libblockchain::blockchain::open_chain(
                match app_config.blockchains.private_key_path.to_str() {
                    Some(path) => path,
                    None => {
                        storage_status.error_message =
                            Some("Failed to parse private key path from app_config".to_string());
                        return storage_status;
                    }
                },
            ) {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open private key blockchain.");
                    storage_status.error_message =
                        Some(format!("Failed to open private key blockchain: {}", e));
                    false
                }
            },
        );
    }
    if storage_status.crl_path_exists == Some(true) {
        storage_status.crl_chain_openable = Some(
            match libblockchain::blockchain::open_chain(
                match app_config.blockchains.crl_path.to_str() {
                    Some(path) => path,
                    None => {
                        storage_status.error_message =
                            Some("Failed to parse CRL path from app_config".to_string());
                        return storage_status;
                    }
                },
            ) {
                Ok(_) => true,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open CRL blockchain.");
                    storage_status.error_message =
                        Some(format!("Failed to open CRL blockchain: {}", e));
                    false
                }
            },
        );
    }
    if !storage_status.app_cert_exists.unwrap_or(false)
        && !storage_status.app_key_exists.unwrap_or(false)
        && !storage_status.cert_path_exists.unwrap_or(false)
        && !storage_status.key_path_exists.unwrap_or(false)
        && !storage_status.crl_path_exists.unwrap_or(false)
    {
        let (app_cert, app_key) = match crate::encryption::create_app_cert_and_key_pair() {
            Ok((cert, key)) => (cert, key),
            Err(e) => {
                tracing::error!(error = %e, "Failed to generate app certificate and key.");
                storage_status.error_message =
                    Some(format!("Failed to generate app certificate and key: {}", e));
                return storage_status;
            }
        };
        if let Some(cert_parent_dir) = app_config.key_exports.app_cert_path.parent() {
            if let Err(e) = std::fs::create_dir_all(cert_parent_dir) {
                tracing::error!(error = %e, "Failed to create parent directory for app certificate.");
                storage_status.error_message = Some(format!(
                    "Failed to create parent directory for app certificate: {}",
                    e
                ));
                return storage_status;
            }
        }
        if let Some(key_parent_dir) = app_config.key_exports.app_key_path.parent() {
            if let Err(e) = std::fs::create_dir_all(key_parent_dir) {
                tracing::error!(error = %e, "Failed to create parent directory for app private key.");
                storage_status.error_message = Some(format!(
                    "Failed to create parent directory for app private key: {}",
                    e
                ));
                return storage_status;
            }
        }
        match std::fs::write(
            &app_config.key_exports.app_cert_path,
            match app_cert.to_pem() {
                Ok(pem) => pem,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to convert app certificate to PEM.");
                    storage_status.error_message =
                        Some(format!("Failed to convert app certificate to PEM: {}", e));
                    return storage_status;
                }
            },
        ) {
            Ok(_) => (),
            Err(e) => {
                tracing::error!(error = %e, "Failed to write app certificate to file.");
                storage_status.error_message =
                    Some(format!("Failed to write app certificate to file: {}", e));
                return storage_status;
            }
        };
        match std::fs::write(
            &app_config.key_exports.app_key_path,
            match app_key.private_key_to_pem_pkcs8() {
                Ok(pem) => pem,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to convert app private key to PEM.");
                    storage_status.error_message =
                        Some(format!("Failed to convert app private key to PEM: {}", e));
                    return storage_status;
                }
            },
        ) {
            Ok(_) => (),
            Err(e) => {
                tracing::error!(error = %e, "Failed to write app private key to file.");
                storage_status.error_message =
                    Some(format!("Failed to write app private key to file: {}", e));
                return storage_status;
            }
        };
        let storage = Storage::<crate::storage_empty::Empty> {
            state: crate::storage_empty::Empty {},
            app_config: app_config.clone(),
        };
        let storage = storage.create_storage();
        storage.initialize_storage();
        if execution_count > 4 {
            storage_status.error_message = Some(format!(
                "Storage state check has been attempted {} times. Manual intervention may be required.",
                execution_count
            ));
            return storage_status;
        }
        get_state(app_config, execution_count + 1);
    }
    if !storage_status.app_cert_exists.unwrap_or(false)
        || !storage_status.app_key_exists.unwrap_or(false)
        || !storage_status.cert_path_exists.unwrap_or(false)
        || !storage_status.key_path_exists.unwrap_or(false)
        || !storage_status.crl_path_exists.unwrap_or(false)
    {
        storage_status.storage_state = StorageState::Inconsistent;
        storage_status.error_message = Some(
            "Storage is in an inconsistent state: some files exist while others do not."
                .to_string(),
        );
        return storage_status;
    }
    if storage_status.cert_chain_openable == Some(true)
        && storage_status.key_chain_openable == Some(true)
        && storage_status.crl_chain_openable == Some(true)
    {
        storage_status.storage_state = StorageState::Created;
        let storage = Storage::<crate::storage_created::Created> {
            state: crate::storage_created::Created {
                certificate_chain: match libblockchain::blockchain::open_chain(
                    match app_config.blockchains.certificate_path.to_str() {
                        Some(path) => path,
                        None => {
                            storage_status.error_message = Some(
                                "Failed to parse certificate path from app_config".to_string(),
                            );
                            return storage_status;
                        }
                    },
                ) {
                    Ok(chain) => chain,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to open certificate blockchain.");
                        storage_status.error_message =
                            Some(format!("Failed to open certificate blockchain: {}", e));
                        return storage_status;
                    }
                },
                private_key_chain: match libblockchain::blockchain::open_chain(
                    match app_config.blockchains.private_key_path.to_str() {
                        Some(path) => path,
                        None => {
                            storage_status.error_message = Some(
                                "Failed to parse private key path from app_config".to_string(),
                            );
                            return storage_status;
                        }
                    },
                ) {
                    Ok(chain) => chain,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to open private key blockchain.");
                        storage_status.error_message =
                            Some(format!("Failed to open private key blockchain: {}", e));
                        return storage_status;
                    }
                },
                crl_chain: match libblockchain::blockchain::open_chain(
                    match app_config.blockchains.crl_path.to_str() {
                        Some(path) => path,
                        None => {
                            storage_status.error_message =
                                Some("Failed to parse CRL path from app_config".to_string());
                            return storage_status;
                        }
                    },
                ) {
                    Ok(chain) => chain,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to open CRL blockchain.");
                        storage_status.error_message =
                            Some(format!("Failed to open CRL blockchain: {}", e));
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
            == 0
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_height
                == 0
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
            storage.initialize_storage();
            get_state(app_config, execution_count + 1);
        }
        if storage_status
            .validation_result
            .as_ref()
            .unwrap()
            .cert_height
            == 1
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_height
                == 1
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
            > 1
            && storage_status
                .validation_result
                .as_ref()
                .unwrap()
                .key_height
                > 1
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
                    "Storage is in an inconsistent state: some blocks failed signature validation."
                        .to_string(),
                );
                return storage_status;
            }
            storage_status.storage_state = StorageState::Ready;
            return storage_status;
        }
    }
    storage_status
}

pub fn get_api_storage(
    storage: Storage<crate::storage_ready::Ready>,
) -> anyhow::Result<Storage<crate::storage_api::API>> {
    let cert_store =
        crate::encryption::build_client_auth_store_from_root_ca(&get_root_certificate(
            &storage.state.certificate_chain,
            crate::encryption::get_app_private_key(&storage.app_config)?,
        )?)?;
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
                    "Failed to parse certificate path from app_config"
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
            tracing::error!(error = %e, "Failed to open private key blockchain.");
            return Err(anyhow::anyhow!(
                "Failed to open private key blockchain: {}",
                e
            ));
        }
    };
    let crl_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.crl_path.to_str() {
            Some(path) => path,
            None => return Err(anyhow::anyhow!("Failed to parse CRL path from app_config")),
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open CRL blockchain.");
            return Err(anyhow::anyhow!("Failed to open CRL blockchain: {}", e));
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
                    "Failed to parse certificate path from app_config"
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
            tracing::error!(error = %e, "Failed to open private key blockchain.");
            return Err(anyhow::anyhow!(
                "Failed to open private key blockchain: {}",
                e
            ));
        }
    };
    let crl_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.crl_path.to_str() {
            Some(path) => path,
            None => return Err(anyhow::anyhow!("Failed to parse CRL path from app_config")),
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open CRL blockchain.");
            return Err(anyhow::anyhow!("Failed to open CRL blockchain: {}", e));
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
                    "Failed to parse certificate path from app_config"
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
            tracing::error!(error = %e, "Failed to open private key blockchain.");
            return Err(anyhow::anyhow!(
                "Failed to open private key blockchain: {}",
                e
            ));
        }
    };
    let crl_chain = match libblockchain::blockchain::open_chain(
        match app_config.blockchains.crl_path.to_str() {
            Some(path) => path,
            None => return Err(anyhow::anyhow!("Failed to parse CRL path from app_config")),
        },
    ) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open CRL blockchain.");
            return Err(anyhow::anyhow!("Failed to open CRL blockchain: {}", e));
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
