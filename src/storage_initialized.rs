const ROOT_HEIGHT: u64 = 0;
const ADMIN_HEIGHT: u64 = 1;

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
        let app_priv_key = match crate::encryption::get_app_private_key(&self.app_config) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get app private key.");
                std::process::exit(1);
            }
        };
        let (root_cert_block, root_cert_signature) = match self
            .state
            .certificate_chain
            .get_block_by_height(ROOT_HEIGHT)
        {
            (Ok(block), Ok(signature)) => (block, signature),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get root certificate block.");
                std::process::exit(1);
            }
        };
        let (root_cert, root_cert_verified) = match crate::encryption::verify_and_decrypt_cert(
            root_cert_block.block_data().as_slice(),
            &root_cert_signature,
            app_priv_key.clone(),
        ) {
            (Ok(cert), Ok(verified)) => (cert, verified),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to verify and decrypt root certificate.");
                std::process::exit(1);
            }
        };
        if !root_cert_verified {
            tracing::error!("add_admin_user -> Root certificate verification failed.");
            std::process::exit(1);
        }
        let (root_private_key_block, root_private_key_signature) = match self
            .state
            .private_key_chain
            .get_block_by_height(ROOT_HEIGHT)
        {
            (Ok(block), Ok(signature)) => (block, signature),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get root private key block.");
                std::process::exit(1);
            }
        };
        let root_private_key = match crate::encryption::verify_and_decrypt_priv_key(
            root_private_key_block.block_data().as_slice(),
            &root_private_key_signature,
            &root_cert,
            app_priv_key.clone(),
        ) {
            (Ok(key), Ok(verified)) => {
                if !verified {
                    tracing::error!("add_admin_user -> Root private key verification failed.");
                    std::process::exit(1);
                }
                key
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to verify and decrypt root private key.");
                std::process::exit(1);
            }
        };
        let app_pub_key = match crate::encryption::get_app_public_key(&self.app_config.clone()) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let (admin_interm_cert, admin_intermediate_signature) = match self
            .state
            .certificate_chain
            .get_block_by_height(ADMIN_HEIGHT)
        {
            (Ok(block), Ok(signature)) => (block, signature),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get admin intermediate certificate block.");
                std::process::exit(1);
            }
        };
        let (admin_intermediate_cert, admin_intermediate_verified) =
            match crate::encryption::verify_and_decrypt_cert(
                admin_interm_cert.block_data().as_slice(),
                &admin_intermediate_signature,
                app_priv_key.clone(),
            ) {
                (Ok(cert), Ok(verified)) => (cert, verified),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to verify and decrypt admin intermediate certificate.");
                    std::process::exit(1);
                }
            };
        if !admin_intermediate_verified {
            tracing::error!(
                "add_admin_user -> Admin intermediate certificate verification failed."
            );
            std::process::exit(1);
        }
        let (admin_interm_private_key_block, admin_intermediate_private_key_signature) = match self
            .state
            .private_key_chain
            .get_block_by_height(ADMIN_HEIGHT)
        {
            (Ok(block), Ok(signature)) => (block, signature),
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get admin intermediate private key block.");
                std::process::exit(1);
            }
        };
        let admin_intermediate_key = match crate::encryption::verify_and_decrypt_priv_key(
            admin_interm_private_key_block.block_data().as_slice(),
            &admin_intermediate_private_key_signature,
            &admin_intermediate_cert,
            app_priv_key.clone(),
        ) {
            (Ok(key), Ok(verified)) => {
                if !verified {
                    tracing::error!(
                        "add_admin_user -> Admin intermediate private key verification failed."
                    );
                    std::process::exit(1);
                }
                key
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to verify and decrypt admin intermediate private key.");
                std::process::exit(1);
            }
        };
        let (admin_user_key, admin_user_cert) = match crate::pki_generator::generate_key_pair(
            admin_user_certificate_data,
            &admin_intermediate_key,
        ) {
            Ok((key, cert)) => (key, cert),
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to generate admin user key pair.");
                std::process::exit(1);
            }
        };
        let (encrypted_admin_user_cert, admin_user_cert_signature) =
            match crate::encryption::encrypt_and_sign_data(
                &match admin_user_cert.to_der() {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!(error = %e, "add_admin_user -> Failed to convert admin user certificate to DER.");
                        std::process::exit(1);
                    }
                },
                app_pub_key.clone(),
                root_private_key.clone(),
            ) {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to encrypt admin user certificate.");
                    std::process::exit(1);
                }
            };
        let encrypted_admin_user_key = match crate::encryption::encrypt_data(
            &match admin_user_key.private_key_to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to convert admin user private key to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to encrypt admin user private key.");
                std::process::exit(1);
            }
        };
        match self
            .state
            .certificate_chain
            .put_block(encrypted_admin_user_cert, admin_user_cert_signature.clone())
        {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to add admin user certificate to chain.");
                std::process::exit(1);
            }
        };
        match self
            .state
            .private_key_chain
            .put_block(encrypted_admin_user_key, admin_user_cert_signature)
        {
            Ok(_) => {}
            Err(e) => {
                match self.state.certificate_chain.delete_last_block() {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "add_admin_user -> Failed to delete last block from certificate chain.");
                        std::process::exit(1);
                    }
                }
                tracing::error!(error = %e, "add_admin_user -> Failed to add admin user private key to chain.");
                std::process::exit(1);
            }
        };
        (admin_user_cert, admin_user_key)
    }
}
