pub struct Created {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
}

impl crate::storage::Storage<Created> {
    pub fn initialize_storage(
        self,
    ) -> crate::storage::Storage<crate::storage_initialized::Initialized> {
        let (private_key, cert) = || -> (openssl::pkey::PKey<openssl::pkey::Private>, openssl::x509::X509) {
            let validity_days = 365 * 5;
            let cert_data = crate::pki_generator::CertificateData {
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
                validity_days,
                cert_type: crate::pki_generator::CertificateDataType::RootCA,
                is_admin: false,
            };
            match crate::pki_generator::generate_root_ca(cert_data) {
                Ok((private_key, cert)) => (private_key, cert),
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to generate root CA.");
                    std::process::exit(1);
                }
            }
        }();
        let app_public_key = match crate::encryption::get_app_public_key(&self.app_config.clone()) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let encrypted_private_key = match crate::encryption::encrypt_data(
            match &private_key.private_key_to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to convert root private key to DER.");
                    std::process::exit(1);
                }
            },
            app_public_key.clone(),
        ) {
            Ok(encrypted_key) => encrypted_key,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to encrypt root private key.");
                std::process::exit(1);
            }
        };
        let encrypted_cert = match crate::encryption::encrypt_data(
            &match cert.to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to convert root certificate to DER.");
                    std::process::exit(1);
                }
            },
            app_public_key,
        ) {
            Ok(encrypted_cert) => encrypted_cert,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to encrypt root certificate.");
                std::process::exit(1);
            }
        };
        let cert_signature = match crate::encryption::sign_data(
            encrypted_cert.as_slice(),
            private_key.clone(),
        ) {
            Ok(signature) => signature,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to sign root certificate.");
                std::process::exit(1);
            }
        };
        let cert_height = match self
            .state
            .certificate_chain
            .put_block(encrypted_cert, cert_signature.clone())
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to put root certificate block.");
                std::process::exit(1);
            }
        };

        let key_height = match self
            .state
            .private_key_chain
            .put_block(encrypted_private_key, cert_signature)
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "initialize_storage -> Failed to put root private key block.");
                std::process::exit(1);
            }
        };

        if key_height != cert_height {
            match self.state.certificate_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to delete last certificate block.");
                    std::process::exit(1);
                }
            }
            match self.state.private_key_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "initialize_storage -> Failed to delete last private key block.");
                    std::process::exit(1);
                }
            }
        }
        crate::storage::Storage {
            state: crate::storage_initialized::Initialized {
                certificate_chain: self.state.certificate_chain,
                private_key_chain: self.state.private_key_chain,
                crl_chain: self.state.crl_chain,
            },
            app_config: self.app_config,
        }
    }
}
