pub struct Initialized {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
}

impl crate::storage::Storage<Initialized> {
    pub fn add_admin_user(
        &self,
        admin_user_certificate_data: crate::pki_generator::CertificateData,
    ) -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let app_key = match crate::encryption::get_app_private_key(&self.app_config) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to get app private key.");
                std::process::exit(1);
            }
        };
        let root_private_key = match crate::storage::get_root_private_key(
            &self.state.private_key_chain,
            app_key,
        ) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to get root private key.");
                std::process::exit(1);
            }
        };
        let admin_intermediate_certificate_data = crate::pki_generator::CertificateData {
            subject_common_name: "Admin Intermediate CA".to_string(),
            issuer_common_name: self.app_config.root_ca_defaults.root_ca_common_name.clone(),
            organization: self
                .app_config
                .root_ca_defaults
                .root_ca_organization
                .clone(),
            organizational_unit: self
                .app_config
                .root_ca_defaults
                .root_ca_organizational_unit
                .clone(),
            locality: self.app_config.root_ca_defaults.root_ca_locality.clone(),
            state: self.app_config.root_ca_defaults.root_ca_state.clone(),
            country: self.app_config.root_ca_defaults.root_ca_country.clone(),
            validity_days: 365 * 3,
            cert_type: crate::pki_generator::CertificateDataType::IntermediateCA,
            is_admin: false,
        };
        let (admin_intermediate_key, admin_intermediate_cert) =
            match crate::pki_generator::generate_key_pair(
                admin_intermediate_certificate_data,
                &root_private_key,
            ) {
                Ok((key, cert)) => (key, cert),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to generate admin intermediate key pair.");
                    std::process::exit(1);
                }
            };
        let app_pub_key = match crate::encryption::get_app_public_key(&self.app_config.clone()) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let (encrypted_admin_intermdiate_cert, admin_cert_signature) =
            match crate::encryption::encrypt_and_sign_data(
                &match admin_intermediate_cert.to_der() {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin intermediate certificate to DER.");
                        std::process::exit(1);
                    }
                },
                app_pub_key.clone(),
                root_private_key.clone(),
            ) {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin intermediate certificate.");
                    std::process::exit(1);
                }
            };
        let cert_height = match self.state.certificate_chain.put_block(
            encrypted_admin_intermdiate_cert,
            admin_cert_signature.clone(),
        ) {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin intermediate certificate to chain.");
                std::process::exit(1);
            }
        };
        let encrypted_admin_intermediate_key = match crate::encryption::encrypt_data(
            &match admin_intermediate_key.private_key_to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin intermediate private key to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin intermediate private key.");
                std::process::exit(1);
            }
        };
        let key_height = match self
            .state
            .private_key_chain
            .put_block(encrypted_admin_intermediate_key, admin_cert_signature)
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin intermediate private key to chain.");
                std::process::exit(1);
            }
        };
        if key_height != cert_height {
            match self.state.certificate_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from certificate chain.");
                    std::process::exit(1);
                }
            }
            match self.state.private_key_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from private key chain.");
                    std::process::exit(1);
                }
            }
        }
        let (admin_user_key, admin_user_cert) = match crate::pki_generator::generate_key_pair(
            admin_user_certificate_data,
            &admin_intermediate_key,
        ) {
            Ok((key, cert)) => (key, cert),
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to generate admin user key pair.");
                std::process::exit(1);
            }
        };
        let (encrypted_admin_user_cert, admin_user_cert_signature) =
            match crate::encryption::encrypt_and_sign_data(
                &match admin_user_cert.to_der() {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin user certificate to DER.");
                        std::process::exit(1);
                    }
                },
                app_pub_key.clone(),
                root_private_key.clone(),
            ) {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin user certificate.");
                    std::process::exit(1);
                }
            };
        let encrypted_admin_user_key = match crate::encryption::encrypt_data(
            &match admin_user_key.private_key_to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin user private key to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin user private key.");
                std::process::exit(1);
            }
        };
        let cert_height = match self
            .state
            .certificate_chain
            .put_block(encrypted_admin_user_cert, admin_user_cert_signature.clone())
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin user certificate to chain.");
                std::process::exit(1);
            }
        };
        let key_height = match self
            .state
            .private_key_chain
            .put_block(encrypted_admin_user_key, admin_user_cert_signature)
        {
            Ok(height) => height,
            Err(e) => {
                match self.state.certificate_chain.delete_last_block() {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from certificate chain.");
                        std::process::exit(1);
                    }
                }
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin user private key to chain.");
                std::process::exit(1);
            }
        };
        if key_height != cert_height {
            match self.state.certificate_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from certificate chain.");
                    std::process::exit(1);
                }
            }
            match self.state.private_key_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from private key chain.");
                    std::process::exit(1);
                }
            }
        }
        (admin_user_cert, admin_user_key)
    }
}
