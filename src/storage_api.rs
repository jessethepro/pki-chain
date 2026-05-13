pub struct API {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: std::sync::Arc<openssl::x509::store::X509Store>,
    pub app_private_key: openssl::pkey::PKey<openssl::pkey::Private>,
}

impl crate::storage::Storage<API> {
    pub fn close(self) -> anyhow::Result<crate::storage::Storage<crate::storage_ready::Ready>> {
        let private_key_chain = match libblockchain::blockchain::open_chain(
            match self.app_config.blockchains.private_key_path.to_str() {
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
        Ok(crate::storage::Storage {
            state: crate::storage_ready::Ready {
                certificate_chain: self.state.certificate_chain,
                private_key_chain,
                crl_chain: self.state.crl_chain,
                auth_store: self.state.auth_store,
            },
            app_config: self.app_config,
        })
    }
    pub fn get_certificate_by_serial(
        &self,
        cert_serial: openssl::bn::BigNum,
    ) -> anyhow::Result<Option<(openssl::x509::X509, openssl::x509::X509)>> {
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 3..block_count - 1 {
            let (cert, intermeidate) = match crate::storage::get_user_and_intermediate_cert(
                i,
                &self.state.certificate_chain,
                &self.state.app_private_key,
            ) {
                Ok((cert, intermeidate)) => (cert, intermeidate),
                Err(e) => {
                    return Err(anyhow::anyhow!(
                    "get_certificate_by_serial -> Failed to retrieve certificate at height {}: {}",
                    i,
                    e
                ))
                }
            };
            if cert.serial_number().to_bn()? == cert_serial {
                return Ok(Some((cert, intermeidate)));
            }
        }
        Ok(None)
    }
}
