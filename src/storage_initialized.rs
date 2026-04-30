const ROOT_HEIGHT: u64 = 0;
const ADMIN_HEIGHT: u64 = 1;

pub struct Initialized {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: openssl::x509::store::X509Store,
    pub auth_chain: openssl::stack::Stack<openssl::x509::X509>,
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
        let app_pub_key = match crate::encryption::get_app_public_key(&self.app_config) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let admin_interm_private_key_block = match self
            .state
            .private_key_chain
            .get_block_by_height(ADMIN_HEIGHT)
        {
            (Ok(block), Ok(_)) => block,
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to get admin intermediate private key block.");
                std::process::exit(1);
            }
        };
        let admin_intermediate_key = match crate::encryption::decrypt_data(
            &admin_interm_private_key_block.block_data(),
            &app_priv_key,
        ) {
            Ok(decrypted) => match openssl::pkey::PKey::private_key_from_der(&decrypted) {
                Ok(key) => key,
                Err(e) => {
                    tracing::error!(error = %e, "add_admin_user -> Failed to parse admin intermediate private key DER.");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "add_admin_user -> Failed to decrypt admin intermediate private key.");
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
        if !crate::encryption::verify_client_auth_cert_chain(
            &self.state.auth_store,
            &self.state.auth_chain,
            &admin_user_cert,
        ) {
            tracing::error!(
                error = "N/A",
                "add_admin_user -> Generated admin user certificate is not valid."
            );
            std::process::exit(1);
        }
        let (encrypted_admin_user_cert, admin_user_cert_signature) =
            match crate::encryption::encrypt_and_sign_data(
                &match admin_user_cert.to_der() {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!(error = %e, "add_admin_user -> Failed to convert admin user certificate to DER.");
                        std::process::exit(1);
                    }
                },
                &app_pub_key,
                &admin_user_key,
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
            &app_pub_key,
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
