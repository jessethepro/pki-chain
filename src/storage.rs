pub const ROOT_BLOCK_HEIGHT: u64 = 0;
pub const ADMIN_BLOCK_HEIGHT: u64 = 1; // Represents the block height where the admin intermediate certificate and intermediate key are stored in the blockchains.

pub fn get_root_private_key(
    private_key_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
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
        &app_private_key,
    )?;
    Ok(openssl::pkey::PKey::private_key_from_der(
        &decrypted_root_key_der,
    )?)
}

pub fn get_root_certificate(
    certificate_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
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
        &app_private_key,
    )?;
    let root_cert = openssl::x509::X509::from_der(&decrypted_root_cert_der)?;
    Ok(root_cert)
}

pub fn get_default_admin_intermediate_certificate(
    certificate_chain: &libblockchain::blockchain::BlockChain,
    app_private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> anyhow::Result<openssl::x509::X509> {
    let cert_block_count = certificate_chain.block_count()?;
    if cert_block_count <= ADMIN_BLOCK_HEIGHT {
        anyhow::bail!("get_default_admin_intermediate_certificate_and_key -> Not enough blocks in the chain to retrieve default admin intermediate certificate");
    }
    let encrypted_admin_cert_block = match certificate_chain.get_block_by_height(ADMIN_BLOCK_HEIGHT) {
        (Ok(block), Ok(_)) => block,
        _ => anyhow::bail!("get_default_admin_intermediate_certificate_and_key -> Failed to retrieve default admin intermediate certificate block"),
    };
    let decrypted_admin_cert_der = crate::encryption::decrypt_data(
        encrypted_admin_cert_block.block_data().as_slice(),
        &app_private_key,
    )?;
    let admin_cert = openssl::x509::X509::from_der(&decrypted_admin_cert_der)?;
    Ok(admin_cert)
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct ValidationResult {
    pub cert_height: u64,
    pub key_height: u64,
    pub cert_blockchain_valid: Option<bool>,
    pub key_blockchain_valid: Option<bool>,
    pub root_cert_valid: Option<bool>,
    pub default_admin_intermediate_cert_valid: Option<bool>,
    pub certificates_validation_results: Option<std::collections::HashMap<u64, bool>>,
    pub error_message: Option<String>,
}
pub fn cert_is_intermediate(
    cert: &openssl::x509::X509,
    app_config: &crate::configs::AppConfig,
) -> bool {
    cert.issuer_name().entries().any(|entry| {
        entry.object().nid() == openssl::nid::Nid::COMMONNAME
            && entry.data().as_utf8().map_or(false, |data| {
                data.to_string() == app_config.root_ca_defaults.root_ca_common_name
            })
    })
}
fn validate_storage(app_config: &crate::configs::AppConfig) -> ValidationResult {
    let mut validation_results = ValidationResult {
        cert_height: 0,
        key_height: 0,
        cert_blockchain_valid: None,
        key_blockchain_valid: None,
        root_cert_valid: None,
        default_admin_intermediate_cert_valid: None,
        certificates_validation_results: None,
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
    let app_private_key = match crate::encryption::get_app_private_key(&app_config) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to get app private key for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to get app private key for validation: {}",
                e
            ));
            return validation_results;
        }
    };
    let root_cert = match get_root_certificate(&cert_chain, &app_private_key) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to get root certificate for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to get root certificate for validation: {}",
                e
            ));
            return validation_results;
        }
    };

    let root_key = match get_root_private_key(&priv_key_chain, &app_private_key) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to get root private key for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to get root private key for validation: {}",
                e
            ));
            return validation_results;
        }
    };
    validation_results.root_cert_valid = match crate::encryption::validate_self_signed_root_pair(
        &root_cert, &root_key,
    ) {
        Ok(valid) => {
            if !valid {
                tracing::error!(
                    "validate_storage -> Root certificate and private key pair is not valid."
                );
                validation_results.root_cert_valid = Some(false);
                validation_results.error_message = Some(
                    "validate_storage -> Root certificate and private key pair is not valid."
                        .to_string(),
                );
                return validation_results;
            }
            Some(valid)
        }
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to validate self-signed root certificate and private key pair.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to validate self-signed root certificate and private key pair: {}",
                e
            ));
            return validation_results;
        }
    };
    // Zero out the root private key DER bytes from memory after validation
    zeroize::Zeroize::zeroize(&mut root_key.private_key_to_der().unwrap_or_default());
    drop(root_key); // Ensure the root private key is dropped from memory as soon as it's no longer needed for validation
    let auth_store = match crate::encryption::build_client_auth_store_from_root_ca(&root_cert) {
        Ok(store) => store,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to build certificate store from root certificate for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to build certificate store from root certificate for validation: {}",
                e
            ));
            return validation_results;
        }
    };
    let default_interm_cert = match get_default_admin_intermediate_certificate(
        &cert_chain,
        &app_private_key,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to get default admin intermediate certificate for validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to get default admin intermediate certificate for validation: {}",
                e
            ));
            return validation_results;
        }
    };
    validation_results.default_admin_intermediate_cert_valid =
        match crate::encryption::validate_intermediate_cert_chain(&default_interm_cert, &auth_store)
        {
            Ok(valid) => {
                if !valid {
                    tracing::error!(
                        "validate_storage -> Default admin intermediate certificate is not valid under the root certificate."
                    );
                    validation_results.default_admin_intermediate_cert_valid = Some(false);
                    validation_results.error_message = Some(
                        "validate_storage -> Default admin intermediate certificate is not valid under the root certificate."
                            .to_string(),
                    );
                    return validation_results;
                }
                Some(valid)
            }
            Err(e) => {
                tracing::error!(error = %e, "validate_storage -> Failed to validate default admin intermediate certificate under the root certificate.");
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to validate default admin intermediate certificate under the root certificate: {}",
                    e
                ));
                return validation_results;
            }
        };
    let mut auth_chain = match openssl::stack::Stack::new() {
        Ok(mut stack) => {
            stack.push(default_interm_cert).map_err(|e| {
                tracing::error!(error = %e, "validate_storage -> Failed to push default admin intermediate certificate onto stack for certificate chain validation.");
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to push default admin intermediate certificate onto stack for certificate chain validation: {}",
                    e
                ));
                e
            });
            stack
        }
        Err(e) => {
            tracing::error!(error = %e, "validate_storage -> Failed to create stack for certificate chain validation.");
            validation_results.error_message = Some(format!(
                "validate_storage -> Failed to create stack for certificate chain validation: {}",
                e
            ));
            return validation_results;
        }
    };

    for i in 2..validation_results.cert_height - 1 {
        let cert_block = match cert_chain.get_block_by_height(i) {
            (Ok(block), Ok(_)) => block,
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "validate_storage -> Failed to get certificate block at height {}.", i);
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to get certificate block at height {}: {}",
                    i, e
                ));
                return validation_results;
            }
        };
        let cert = match crate::encryption::decrypt_data(
            cert_block.block_data().as_slice(),
            &app_private_key,
        ) {
            Ok(cert) => match openssl::x509::X509::from_der(&cert) {
                Ok(cert) => cert,
                Err(e) => {
                    tracing::error!(error = %e, "validate_storage -> Failed to parse certificate block at height {}.", i);
                    validation_results.error_message = Some(format!(
                        "validate_storage -> Failed to parse certificate block at height {}: {}",
                        i, e
                    ));
                    return validation_results;
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "validate_storage -> Failed to decrypt and parse certificate block at height {}.", i);
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to decrypt and parse certificate block at height {}: {}",
                    i, e
                ));
                return validation_results;
            }
        };
        if cert_is_intermediate(&cert, &app_config) {
            auth_chain.push(cert).map_err(|e| {
                tracing::error!(error = %e, "validate_storage -> Failed to push certificate block at height {} onto stack for certificate chain validation.", i);
                validation_results.error_message = Some(format!(
                    "validate_storage -> Failed to push certificate block at height {} onto stack for certificate chain validation: {}",
                    i, e
                ));
                e
            });
        } else {
            let cert_valid =
                crate::encryption::verify_client_auth_cert_chain(&auth_store, &auth_chain, &cert);
            validation_results
                .certificates_validation_results
                .get_or_insert_with(|| std::collections::HashMap::new())
                .insert(i, cert_valid);
        }
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
    } else {
        tracing::info!(
            "get_state -> Storage paths existence check results: {:?}",
            storage_status
        );
        // Check if all storage paths do not exist, if so, we can directly set the storage state to Empty without further checks
        if storage_status.app_cert_exists == Some(false)
            && storage_status.app_key_exists == Some(false)
            && storage_status.cert_path_exists == Some(false)
            && storage_status.key_path_exists == Some(false)
            && storage_status.crl_path_exists == Some(false)
        {
            storage_status.storage_state = StorageState::Empty;
            return storage_status;
        }
        // If the app certificate and app key files exist but the blockchain paths do not exist,
        // Storage is still considered Empty.
        if storage_status.app_cert_exists == Some(true)
            && storage_status.app_key_exists == Some(true)
            && storage_status.cert_path_exists == Some(false)
            && storage_status.key_path_exists == Some(false)
            && storage_status.crl_path_exists == Some(false)
        {
            storage_status.storage_state = StorageState::Empty;
            return storage_status;
        }
        // If some of the three storage paths exist but not all, we consider the storage state to be Inconsistent
        if (storage_status.cert_path_exists == Some(true)
            || storage_status.key_path_exists == Some(true)
            || storage_status.crl_path_exists == Some(true))
            && !(storage_status.cert_path_exists == Some(true)
                && storage_status.key_path_exists == Some(true)
                && storage_status.crl_path_exists == Some(true))
        {
            storage_status.storage_state = StorageState::Inconsistent;
            return storage_status;
        }
        // If the app certificate, app key, and all three blockchain paths exist, we proceed to check readability and validity
        if storage_status.app_cert_exists == Some(true)
            && storage_status.app_key_exists == Some(true)
            && storage_status.cert_path_exists == Some(true)
            && storage_status.key_path_exists == Some(true)
            && storage_status.crl_path_exists == Some(true)
        {
            tracing::info!(
                "get_state -> All storage paths exist. Proceeding to check readability and validity."
            );
            check_app_certificate_and_key_readable(&mut storage_status, app_config);
            if storage_status.error_message.is_some() {
                return storage_status;
            }
            if storage_status.app_certificate_readable == Some(true)
                && storage_status.app_key_readable == Some(true)
            {
                tracing::info!(
                    "get_state -> App certificate and key files are readable. Proceeding to check validity."
                );
                check_app_certificate_is_valid(&mut storage_status, app_config);
                if storage_status.error_message.is_some() {
                    return storage_status;
                }
                // If the app certificate and key are readable and valid, we proceed to check if the blockchains are openable and valid
                if storage_status.app_certificate_valid == Some(true) {
                    tracing::info!(
                        "get_state -> App certificate is valid. Proceeding to check if blockchains are openable and valid."
                    );
                    check_blockchains_are_openable(&mut storage_status, app_config);
                    if storage_status.error_message.is_some() {
                        return storage_status;
                    }
                    // If the blockchains are openable, we proceed to validate the blockchains and determine the storage state based on the validation results
                    if storage_status.cert_chain_openable == Some(true)
                        && storage_status.key_chain_openable == Some(true)
                    {
                        tracing::info!(
                            "get_state -> Blockchains are openable. Proceeding to validate blockchains."
                        );
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
                        // If the blockchains are valide but contain no blocks, we consider the storage state to be Created
                        if storage_status.validation_result.is_some() {
                            let validation_result =
                                storage_status.validation_result.as_ref().unwrap();
                            if validation_result.cert_blockchain_valid == Some(true)
                                && validation_result.key_blockchain_valid == Some(true)
                                && validation_result.cert_height == 0
                                && validation_result.key_height == 0
                            {
                                storage_status.storage_state = StorageState::Created;
                                return storage_status;
                            }
                        }
                        // If the blockchains are valid but only contain the root block and default admin intermediate block,
                        // we consider the storage state to be Initialized
                        if storage_status.validation_result.is_some() {
                            let validation_result =
                                storage_status.validation_result.as_ref().unwrap();
                            if validation_result.cert_blockchain_valid == Some(true)
                                && validation_result.key_blockchain_valid == Some(true)
                                && validation_result.cert_height == 2
                                && validation_result.key_height == 2
                            {
                                storage_status.storage_state = StorageState::Initialized;
                                return storage_status;
                            }
                        }
                        // If any of the signatures for the keys are invalid, or if the certificate and key blockchains have different heights, we consider the storage state to be Inconsistent
                        if storage_status.validation_result.is_some() {
                            let validation_result =
                                storage_status.validation_result.as_ref().unwrap();
                            if validation_result.cert_blockchain_valid == Some(true)
                                && validation_result.key_blockchain_valid == Some(true)
                                && ((validation_result.cert_height != validation_result.key_height)
                                    || validation_result
                                        .certificates_validation_results
                                        .as_ref()
                                        .map_or(false, |results| {
                                            results.values().any(|&valid| !valid)
                                        }))
                            {
                                storage_status.storage_state = StorageState::Inconsistent;
                                return storage_status;
                            }
                        }
                        // If the blockchains are valid and contain more than 2 blocks, we consider the storage state to be Ready
                        if storage_status.validation_result.is_some() {
                            let validation_result =
                                storage_status.validation_result.as_ref().unwrap();
                            if validation_result.cert_blockchain_valid == Some(true)
                                && validation_result.key_blockchain_valid == Some(true)
                                && validation_result.cert_height >= 3
                                && validation_result.key_height >= 3
                            {
                                storage_status.storage_state = StorageState::Ready;
                                return storage_status;
                            }
                        }
                    } else {
                        tracing::error!(
                            "get_state -> Blockchains are not openable. Certificate chain openable: {:?}, Key chain openable: {:?}",
                            storage_status.cert_chain_openable,
                            storage_status.key_chain_openable
                        );
                        storage_status.storage_state = StorageState::Inconsistent;
                        return storage_status;
                    }
                } else {
                    tracing::error!(
                        "get_state -> App certificate is not valid. Certificate valid: {:?}",
                        storage_status.app_certificate_valid
                    );
                    storage_status.storage_state = StorageState::Inconsistent;
                    return storage_status;
                }
            } else {
                tracing::error!(
                    "get_state -> App certificate or key files are not readable. Certificate readable: {:?}, Key readable: {:?}",
                    storage_status.app_certificate_readable,
                    storage_status.app_key_readable
                );
                storage_status.storage_state = StorageState::Inconsistent;
                return storage_status;
            }
        }
    }
    storage_status
}

pub fn get_api_storage(
    storage: Storage<crate::storage_ready::Ready>,
) -> anyhow::Result<Storage<crate::storage_api::API>> {
    Ok(Storage {
        state: crate::storage_api::API {
            certificate_chain: storage.state.certificate_chain,
            crl_chain: storage.state.crl_chain,
            auth_store: storage.state.auth_store,
            auth_chain: storage.state.auth_chain,
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
            auth_store: storage.state.auth_store,
            auth_chain: storage.state.auth_chain,
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
    let root_cert = match crate::storage::get_root_certificate(
        &certificate_chain,
        &crate::encryption::get_app_private_key(app_config)?,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to get root certificate from certificate blockchain.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to get root certificate from certificate blockchain: {}",
                e
            ));
        }
    };
    let root_key = match crate::storage::get_root_private_key(
        &private_key_chain,
        &crate::encryption::get_app_private_key(app_config)?,
    ) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to get root private key from private key blockchain.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to get root private key from private key blockchain: {}",
                e
            ));
        }
    };
    let root_valid = match crate::encryption::validate_self_signed_root_pair(&root_cert, &root_key)
    {
        Ok(valid) => valid,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to validate root certificate and root private key pair.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to validate root certificate and root private key pair: {}",
                e
            ));
        }
    };
    if !root_valid {
        tracing::error!(
            "get_initialized_storage -> Root certificate and root private key pair are not valid."
        );
        return Err(anyhow::anyhow!(
            "get_initialized_storage -> Root certificate and root private key pair are not valid."
        ));
    }
    let auth_store = match crate::encryption::build_client_auth_store_from_root_ca(&root_cert) {
        Ok(store) => store,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to build client auth store from root certificate.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to build client auth store from root certificate: {}",
                e
            ));
        }
    };
    let default_interm_cert = match crate::storage::get_default_admin_intermediate_certificate(
        &certificate_chain,
        &crate::encryption::get_app_private_key(app_config)?,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to get default admin intermediate certificate from certificate blockchain.");
            return Err(anyhow::anyhow!(
                    "get_initialized_storage -> Failed to get default admin intermediate certificate from certificate blockchain: {}",
                    e
                ));
        }
    };
    let admin_valid = match crate::encryption::validate_intermediate_cert_chain(
        &default_interm_cert,
        &auth_store,
    ) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to validate default admin intermediate certificate against root certificate.");
            return Err(anyhow::anyhow!(
                    "get_initialized_storage -> Failed to validate default admin intermediate certificate against root certificate: {}",
                    e
                ));
        }
    };
    if !admin_valid {
        tracing::error!(
            "get_initialized_storage -> Default admin intermediate certificate is not valid against root certificate."
        );
        return Err(anyhow::anyhow!(
            "get_initialized_storage -> Default admin intermediate certificate is not valid against root certificate."
        ));
    }
    let auth_chain = match openssl::stack::Stack::new() {
        Ok(mut stack) => {
            stack.push(default_interm_cert).map_err(|e| {
                tracing::error!(error = %e, "get_initialized_storage -> Failed to push default admin intermediate certificate onto stack for certificate chain validation.");
                anyhow::anyhow!(
                    "get_initialized_storage -> Failed to push default admin intermediate certificate onto stack for certificate chain validation: {}",
                    e
                )
            })?;
            stack
        }
        Err(e) => {
            tracing::error!(error = %e, "get_initialized_storage -> Failed to create stack for certificate chain validation.");
            return Err(anyhow::anyhow!(
                "get_initialized_storage -> Failed to create stack for certificate chain validation: {}",
                e
            ));
        }
    };
    Ok(Storage {
        state: crate::storage_initialized::Initialized {
            certificate_chain,
            private_key_chain,
            crl_chain,
            auth_store,
            auth_chain,
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
    let root_cert = match crate::storage::get_root_certificate(
        &certificate_chain,
        &crate::encryption::get_app_private_key(app_config)?,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to get root certificate from certificate blockchain.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to get root certificate from certificate blockchain: {}",
                e
            ));
        }
    };
    let root_key = match crate::storage::get_root_private_key(
        &private_key_chain,
        &crate::encryption::get_app_private_key(app_config)?,
    ) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to get root private key from private key blockchain.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to get root private key from private key blockchain: {}",
                e
            ));
        }
    };
    match crate::encryption::validate_self_signed_root_pair(&root_cert, &root_key) {
        Ok(valid) => {
            if valid {
                tracing::info!(
                    "get_ready_storage -> Root certificate and root private key pair is valid."
                );
            } else {
                tracing::error!(
                    "get_ready_storage -> Root certificate and root private key pair is not valid."
                );
                return Err(anyhow::anyhow!(
                    "get_ready_storage -> Root certificate and root private key pair is not valid."
                ));
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to validate root certificate and root private key pair.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to validate root certificate and root private key pair: {}",
                e
            ));
        }
    };
    // Zeroize the root private key from memory after validation and drop it
    zeroize::Zeroize::zeroize(&mut root_key.private_key_to_der().unwrap_or_default());
    drop(root_key);
    let auth_store = match crate::encryption::build_client_auth_store_from_root_ca(&root_cert) {
        Ok(store) => store,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to build client auth store from root certificate.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to build client auth store from root certificate: {}",
                e
            ));
        }
    };
    let admin_interm_cert = match crate::storage::get_default_admin_intermediate_certificate(
        &certificate_chain,
        &crate::encryption::get_app_private_key(app_config)?,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to get default admin intermediate certificate from certificate blockchain.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to get default admin intermediate certificate from certificate blockchain: {}",
                e
            ));
        }
    };
    match crate::encryption::validate_intermediate_cert_chain(&admin_interm_cert, &auth_store) {
        Ok(valid) => {
            if valid {
                tracing::info!(
                    "get_ready_storage -> Default admin intermediate certificate is valid and signed by root certificate."
                );
            } else {
                tracing::error!(
                    "get_ready_storage -> Default admin intermediate certificate is not valid or not signed by root certificate."
                );
                return Err(anyhow::anyhow!(
                    "get_ready_storage -> Default admin intermediate certificate is not valid or not signed by root certificate."
                ));
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "get_ready_storage -> Failed to validate default admin intermediate certificate against root certificate.");
            return Err(anyhow::anyhow!(
                "get_ready_storage -> Failed to validate default admin intermediate certificate against root certificate: {}",
                e
            ));
        }
    };
    let auth_chain = {
        let mut stack = openssl::stack::Stack::new()?;
        stack.push(admin_interm_cert)?;
        stack
    };
    Ok(Storage {
        state: crate::storage_ready::Ready {
            certificate_chain,
            private_key_chain,
            crl_chain,
            auth_store,
            auth_chain,
        },
        app_config: app_config.clone(),
    })
}
