pub struct Created {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
}

impl crate::storage::Storage<Created> {
    pub fn initialize_storage(
        self,
    ) -> crate::storage::Storage<crate::storage_initialized::Initialized> {
        let app_public_key = match crate::encryption::get_app_public_key(&self.app_config) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let (root_private_key, root_cert) = || -> (openssl::pkey::PKey<openssl::pkey::Private>, openssl::x509::X509) {
            let root_cert_data = crate::pki_generator::CertificateData {
                subject_common_name: self.app_config.root_ca_defaults.root_ca_common_name.clone(),
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
                validity_days: self.app_config.root_ca_defaults.root_ca_validity_days,
                cert_type: crate::pki_generator::CertificateDataType::RootCA,
                is_admin: false,
            };
            match crate::pki_generator::generate_root_ca(root_cert_data) {
                Ok((root_private_key, root_cert)) => (root_private_key, root_cert),
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to generate root CA.");
                    std::process::exit(1);
                }
            }
        }();
        let encrypted_root_private_key = match crate::encryption::encrypt_data(
            match &root_private_key.private_key_to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to convert root private key to DER.");
                    std::process::exit(1);
                }
            },
            &app_public_key,
        ) {
            Ok(encrypted_key) => encrypted_key,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to encrypt root private key.");
                std::process::exit(1);
            }
        };
        let root_encrypted_cert = match crate::encryption::encrypt_data(
            &match root_cert.to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to convert root certificate to DER.");
                    std::process::exit(1);
                }
            },
            &app_public_key,
        ) {
            Ok(encrypted_cert) => encrypted_cert,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to encrypt root certificate.");
                std::process::exit(1);
            }
        };
        let root_cert_signature = match crate::encryption::sign_data(
            root_encrypted_cert.as_slice(),
            &root_private_key,
        ) {
            Ok(signature) => signature,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to sign root certificate.");
                std::process::exit(1);
            }
        };
        match self
            .state
            .certificate_chain
            .put_block(root_encrypted_cert, root_cert_signature.clone())
        {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to put root certificate block.");
                std::process::exit(1);
            }
        };

        match self
            .state
            .private_key_chain
            .put_block(encrypted_root_private_key, root_cert_signature)
        {
            Ok(_) => {}
            Err(e) => {
                match self.state.certificate_chain.delete_last_block() {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "initialize_storage -> Failed to delete last certificate block.");
                        std::process::exit(1);
                    }
                }
                tracing::error!(error = %e, "initialize_storage -> Failed to put root private key block.");
                std::process::exit(1);
            }
        };
        let (admin_private_key, admin_cert) = || -> (openssl::pkey::PKey<openssl::pkey::Private>, openssl::x509::X509) {
            let admin_cert_data = crate::pki_generator::CertificateData {
                subject_common_name: self.app_config.admin_ca_defaults.admin_ca_common_name.clone(),
                issuer_common_name: self.app_config.root_ca_defaults.root_ca_common_name.clone(),
                organization: self
                    .app_config
                    .admin_ca_defaults
                    .admin_ca_organization
                    .clone(),
                organizational_unit: self
                    .app_config
                    .admin_ca_defaults
                    .admin_ca_organizational_unit
                    .clone(),
                locality: self.app_config.admin_ca_defaults.admin_ca_locality.clone(),
                state: self.app_config.admin_ca_defaults.admin_ca_state.clone(),
                country: self.app_config.admin_ca_defaults.admin_ca_country.clone(),
                validity_days: self.app_config.admin_ca_defaults.admin_ca_validity_days,
                cert_type: crate::pki_generator::CertificateDataType::IntermediateCA,
                is_admin: true,
            };
            match crate::pki_generator::generate_key_pair(admin_cert_data, &root_private_key) {
                Ok((admin_private_key, admin_cert)) => (admin_private_key, admin_cert),
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to generate root CA.");
                    std::process::exit(1);
                }
            }
        }();
        let encrypted_admin_private_key = match crate::encryption::encrypt_data(
            match &admin_private_key.private_key_to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to convert admin private key to DER.");
                    std::process::exit(1);
                }
            },
            &app_public_key,
        ) {
            Ok(encrypted_key) => encrypted_key,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to encrypt admin private key.");
                std::process::exit(1);
            }
        };
        let admin_encrypted_cert = match crate::encryption::encrypt_data(
            &match admin_cert.to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to convert admin certificate to DER.");
                    std::process::exit(1);
                }
            },
            &app_public_key,
        ) {
            Ok(encrypted_cert) => encrypted_cert,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to encrypt admin certificate.");
                std::process::exit(1);
            }
        };
        let admin_cert_signature = match crate::encryption::sign_data(
            admin_encrypted_cert.as_slice(),
            &admin_private_key,
        ) {
            Ok(signature) => signature,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to sign admin certificate.");
                std::process::exit(1);
            }
        };
        match self
            .state
            .certificate_chain
            .put_block(admin_encrypted_cert, admin_cert_signature.clone())
        {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to put admin certificate block.");
                std::process::exit(1);
            }
        };

        match self
            .state
            .private_key_chain
            .put_block(encrypted_admin_private_key, admin_cert_signature)
        {
            Ok(_) => {}
            Err(e) => {
                match self.state.certificate_chain.delete_last_block() {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "initialize_storage -> Failed to delete last certificate block.");
                        std::process::exit(1);
                    }
                }
                tracing::error!(error = %e, "initialize_storage -> Failed to put admin private key block.");
                std::process::exit(1);
            }
        };
        let auth_store = match crate::encryption::build_client_auth_store_from_root_ca(&root_cert) {
            Ok(store) => store,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to create auth store.");
                std::process::exit(1);
            }
        };
        let auth_chain = match openssl::stack::Stack::new() {
            Ok(mut stack) => {
                stack.push(admin_cert).unwrap_or_else(|e| {
                    tracing::error!(error = %e, "initialize_storage -> Failed to push admin cert to auth chain.");
                    std::process::exit(1);
                });
                stack
            }
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to create auth chain stack.");
                std::process::exit(1);
            }
        };
        crate::storage::Storage {
            state: crate::storage_initialized::Initialized {
                certificate_chain: self.state.certificate_chain,
                private_key_chain: self.state.private_key_chain,
                crl_chain: self.state.crl_chain,
                auth_store,
                auth_chain,
            },
            app_config: self.app_config,
        }
    }
}
