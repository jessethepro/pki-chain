pub struct API {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: openssl::x509::store::X509Store,
    pub auth_chain: openssl::stack::Stack<openssl::x509::X509>,
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
                auth_chain: self.state.auth_chain,
            },
            app_config: self.app_config,
        })
    }
    pub fn get_certificate_by_serial(
        &mut self,
        cert_serial: openssl::bn::BigNum,
    ) -> anyhow::Result<(openssl::x509::X509, bool)> {
        let app_key = crate::encryption::get_app_private_key(&self.app_config)?;
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 2..block_count - 1 {
            let cert_block = match self.state.certificate_chain.get_block_by_height(i) {
                (Ok(block), Ok(_)) => block,
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "get_certificate_by_serial -> Failed to get block by height {}: {}",
                        i,
                        e
                    ))
                }
            };
            let cert_data =
                match crate::encryption::decrypt_data(cert_block.block_data().as_slice(), &app_key)
                {
                    Ok(data) => data,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                    "get_certificate_by_serial -> Failed to decrypt certificate at height {}: {}",
                    i,
                    e
                ))
                    }
                };
            let cert = match openssl::x509::X509::from_der(&cert_data) {
                Ok(cert) => cert,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "get_certificate_by_serial -> Failed to parse certificate at height {}: {}",
                        i,
                        e
                    ))
                }
            };
            if crate::storage::cert_is_intermediate(&cert, &self.app_config) {
                let cert_der = match cert.to_der() {
                    Ok(der) => der,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "get_certificate_by_serial -> Failed to convert certificate to DER at height {}: {}",
                            i,
                            e
                        ))
                    }
                };
                let cert_in_chain =
                    self.state
                        .auth_chain
                        .iter()
                        .any(|existing| match existing.to_der() {
                            Ok(existing_der) => existing_der == cert_der,
                            Err(_) => false,
                        });
                if !cert_in_chain {
                    match &mut self.state.auth_chain.push(cert.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "get_certificate_by_serial -> Failed to push certificate to auth chain at height {}: {}",
                                i,
                                e
                            ));
                        }
                    }
                }
            } else {
                if cert.serial_number().to_bn()? == cert_serial {
                    match crate::encryption::verify_client_auth_cert_chain(
                        &self.state.auth_store,
                        &self.state.auth_chain,
                        &cert,
                    ) {
                        Ok(is_valid) => return Ok((cert, is_valid)),
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "get_certificate_by_serial -> Failed to verify certificate with serial number {}: {}",
                                cert_serial.to_dec_str()?,
                                e
                            ));
                        }
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "get_certificate_by_serial -> Certificate with serial number {} not found",
            cert_serial.to_dec_str()?
        ))
    }
    pub fn get_certificate_by_common_name(
        &mut self,
        common_name: &str,
    ) -> anyhow::Result<(openssl::x509::X509, bool)> {
        let app_key = crate::encryption::get_app_private_key(&self.app_config)?;
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 2..block_count - 1 {
            let cert_block = match self.state.certificate_chain.get_block_by_height(i) {
                (Ok(block), Ok(_)) => block,
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "get_certificate_by_serial -> Failed to get block by height {}: {}",
                        i,
                        e
                    ))
                }
            };
            let cert_data =
                match crate::encryption::decrypt_data(cert_block.block_data().as_slice(), &app_key)
                {
                    Ok(data) => data,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                    "get_certificate_by_serial -> Failed to decrypt certificate at height {}: {}",
                    i,
                    e
                ))
                    }
                };
            let cert = match openssl::x509::X509::from_der(&cert_data) {
                Ok(cert) => cert,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "get_certificate_by_serial -> Failed to parse certificate at height {}: {}",
                        i,
                        e
                    ))
                }
            };
            if crate::storage::cert_is_intermediate(&cert, &self.app_config) {
                let cert_der = match cert.to_der() {
                    Ok(der) => der,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "get_certificate_by_serial -> Failed to convert certificate to DER at height {}: {}",
                            i,
                            e
                        ))
                    }
                };
                let cert_in_chain =
                    self.state
                        .auth_chain
                        .iter()
                        .any(|existing| match existing.to_der() {
                            Ok(existing_der) => existing_der == cert_der,
                            Err(_) => false,
                        });
                if !cert_in_chain {
                    match &mut self.state.auth_chain.push(cert.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "get_certificate_by_serial -> Failed to push certificate to auth chain at height {}: {}",
                                i,
                                e
                            ));
                        }
                    }
                }
            } else {
                if cert
                    .subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .any(|entry| {
                        entry
                            .data()
                            .as_utf8()
                            .map_or(false, |data| data.to_string() == common_name)
                    })
                {
                    match crate::encryption::verify_client_auth_cert_chain(
                        &self.state.auth_store,
                        &self.state.auth_chain,
                        &cert,
                    ) {
                        Ok(is_valid) => return Ok((cert, is_valid)),
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "get_certificate_by_common_name -> Failed to verify certificate with common name '{}': {}",
                                common_name,
                                e
                            ));
                        }
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "get_certificate_by_common_name -> Certificate with common name '{}' not found",
            common_name
        ))
    }
}
