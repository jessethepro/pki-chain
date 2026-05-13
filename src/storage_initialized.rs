pub struct Initialized {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: std::sync::Arc<openssl::x509::store::X509Store>,
}

impl crate::storage::Storage<Initialized> {
    pub fn add_admin_user(
        &self,
        admin_user_certificate_data: crate::pki_generator::CertificateData,
    ) -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let app_priv_key = match crate::storage::get_app_private_key(&self.state.private_key_chain)
        {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get app private key.");
                std::process::exit(1);
            }
        };
        let app_pub_key = match crate::storage::get_app_certificate(&self.state.certificate_chain) {
            Ok(cert) => match cert.public_key() {
                Ok(key) => key,
                Err(e) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to extract public key from app certificate.");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let admin_ca_cert = match crate::storage::get_admin_intermediate_certificate(
            &self.state.certificate_chain,
            &app_priv_key,
        ) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get admin intermediate certificate.");
                std::process::exit(1);
            }
        };
        let admin_intermediate_key = match crate::storage::get_admin_intermediate_private_key(
            &self.state.private_key_chain,
            &app_priv_key,
        ) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get admin intermediate private key.");
                std::process::exit(1);
            }
        };
        let (admin_user_key, admin_user_cert) =
            match crate::pki_generator::generate_user_cert_and_private_key(
                admin_user_certificate_data,
                &admin_intermediate_key,
                &admin_ca_cert,
            ) {
                Ok((key, cert)) => (key, cert),
                Err(e) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to generate admin user key pair.");
                    std::process::exit(1);
                }
            };
        tracing::info!(
            "add_admin_user -> Generated admin user certificate and key successfully: {:?}",
            admin_user_cert
        );
        let auth_chain = match openssl::stack::Stack::new() {
            Ok(mut stack) => match stack.push(admin_user_cert.clone()) {
                Ok(_) => stack,
                Err(e) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to push admin user certificate onto auth chain stack.");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to create auth chain stack.");
                std::process::exit(1);
            }
        };
        match crate::encryption::verify_user_cert(
            &self.state.auth_store,
            &auth_chain,
            &admin_user_cert,
        ) {
            Ok(valid) => {
                if !valid {
                    tracing::error!(
                        error = "N/A",
                        "add_admin_user -> Generated admin user certificate is not valid."
                    );
                    std::process::exit(1);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to verify generated admin user certificate.");
                std::process::exit(1);
            }
        };
        match crate::storage::store_user_keypair_and_intermediate_cert(
            &admin_user_cert,
            &admin_ca_cert,
            &self.state.certificate_chain,
            &app_pub_key,
        ) {
            Ok(_) => {
                match crate::storage::store_private_key(
                    &admin_user_key,
                    &self.state.private_key_chain,
                    &app_pub_key,
                ) {
                    Ok(_) => (),
                    Err(e) => {
                        match self.state.certificate_chain.delete_last_block() {
                            Ok(_) => (),
                            Err(e) => {
                                tracing::error!(error = %e, "add_admin_user -> Failed to delete last block from certificate chain after failing to store admin user private key.");
                                std::process::exit(1);
                            }
                        }
                        tracing::error!(error = %e, "add_admin_user -> Failed to store admin user private key.");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to store admin user certificate and intermediate certificate.");
                std::process::exit(1);
            }
        };
        (admin_user_cert, admin_user_key)
    }
}
