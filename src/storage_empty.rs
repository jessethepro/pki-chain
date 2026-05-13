use serde::ser;

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
        let cert_count = match certificate_chain.block_count() {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "create_storage -> Failed to get block count of certificate chain.");
                std::process::exit(1);
            }
        };
        let key_count = match private_key_chain.block_count() {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "create_storage -> Failed to get block count of private key chain.");
                std::process::exit(1);
            }
        };
        if cert_count != 0 || key_count != 0 {
            tracing::error!("create_storage -> Certificate chain and private key chain must both be empty or both contain blocks. Current block counts - Certificate Chain: {}, Private Key Chain: {}", cert_count, key_count);
            std::process::exit(1);
        }

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
            let (app_cert, app_key) = match create_app_cert_and_key() {
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
            let serialized_cert = crate::storage::serialize_app_cert_or_key(
                match &app_cert.to_pem() {
                    Ok(pem) => pem,
                    Err(e) => {
                        tracing::error!(error = %e, "create_storage -> Failed to serialize app certificate PEM for storage.");
                        std::process::exit(1);
                    }
                },
            );
            let serialized_key = crate::storage::serialize_app_cert_or_key(
                match &app_key.private_key_to_pem_pkcs8() {
                    Ok(pem) => pem,
                    Err(e) => {
                        tracing::error!(error = %e, "create_storage -> Failed to serialize app private key PEM for storage.");
                        std::process::exit(1);
                    }
                },
            );
            match certificate_chain.put_block(&serialized_cert, &Vec::<u8>::new()) {
                Ok(_) => {
                    tracing::info!("create_storage -> Successfully added app certificate to certificate chain.");
                    match private_key_chain.put_block(&serialized_key, &Vec::<u8>::new()) {
                        Ok(_) => {
                            tracing::info!("create_storage -> Successfully added app private key to private key chain.");
                        }
                        Err(e) => {
                            certificate_chain.delete_last_block();
                            tracing::error!(error = %e, "create_storage -> Failed to add app private key block to private key chain.");
                            std::process::exit(1);
                        }
                    };
                }
                Err(e) => {
                    tracing::error!(error = %e, "create_storage -> Failed to add app certificate block to certificate chain.");
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

fn create_app_cert_and_key() -> anyhow::Result<(
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
)> {
    let rsa = match openssl::rsa::Rsa::generate(4096) {
        Ok(rsa) => rsa,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to generate RSA key pair: {}",
                e
            ))
        }
    };
    let private_key = match openssl::pkey::PKey::from_rsa(rsa) {
        Ok(key) => key,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to create PKey from RSA key pair: {}",
                e
            ))
        }
    };

    let mut builder = match openssl::x509::X509Builder::new() {
        Ok(b) => b,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to create X509 builder: {}",
                e
            ))
        }
    };
    match builder.set_version(2) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to set certificate version: {}",
                e
            ))
        }
    };
    // RFC 5280-compliant serial: positive, non-zero, and <= 20 bytes.
    let serial = match openssl::bn::BigNum::new() {
        Ok(mut bn) => {
            match bn.rand(128, openssl::bn::MsbOption::TWO_ONES, false) {
                Ok(_) => {
                    match bn.to_asn1_integer() {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "create_app_cert_and_key_pair -> Failed to convert certificate serial number to ASN1: {}",
                                e
                            ))
                        }
                    }
                },
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "create_app_cert_and_key_pair -> Failed to generate random serial number: {}",
                        e
                    ))
                }
            }
        },
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to create BigNum for serial number: {}",
                e
            ))
        }
    };
    match builder.set_serial_number(&serial) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to set certificate serial number: {}",
                e
            ))
        }
    }
    let not_before = match openssl::asn1::Asn1Time::days_from_now(0) {
        Ok(nb) => nb,
        Err(e) => {
            return Err(anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to set certificate not_before timestamp: {}",
            e
        ))
        }
    };
    let not_after = match openssl::asn1::Asn1Time::days_from_now(365 * 5) {
        Ok(na) => na,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to set certificate not_after timestamp: {}",
                e
            ))
        }
    };
    match builder.set_not_before(&not_before) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to apply certificate not_before timestamp: {}",
            e
        ))
        }
    };
    match builder.set_not_after(&not_after) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
            "create_app_cert_and_key_pair -> Failed to apply certificate not_after timestamp: {}",
            e
        ))
        }
    };
    let subject_name = match openssl::x509::X509NameBuilder::new() {
        Ok(mut b) => match b.append_entry_by_text("CN", "App Certificate") {
            Ok(_) => b.build(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "create_app_cert_and_key_pair -> Failed to build subject name: {}",
                    e
                ))
            }
        },
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to create X509 name builder: {}",
                e
            ))
        }
    };
    match builder.set_subject_name(&subject_name) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to set subject name: {}",
                e
            ))
        }
    }
    let issuer_name = match openssl::x509::X509NameBuilder::new() {
        Ok(mut b) => match b.append_entry_by_text("CN", "App Certificate") {
            Ok(_) => b.build(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "create_app_cert_and_key_pair -> Failed to build issuer name: {}",
                    e
                ))
            }
        },
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to create X509 name builder: {}",
                e
            ))
        }
    };
    match builder.set_issuer_name(&issuer_name) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to set issuer name: {}",
                e
            ))
        }
    }
    match builder.set_pubkey(&private_key) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to set public key in certificate: {}",
                e
            ))
        }
    }
    match builder.sign(&private_key, openssl::hash::MessageDigest::sha256()) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "create_app_cert_and_key_pair -> Failed to sign certificate: {}",
                e
            ))
        }
    }
    Ok((builder.build(), private_key))
}
