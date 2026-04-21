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
        crate::storage::Storage {
            state: crate::storage_created::Created {
                certificate_chain,
                private_key_chain,
                crl_chain,
            },
            app_config: self.app_config,
        }
    }
}
