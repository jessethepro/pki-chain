pub struct API {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: openssl::x509::store::X509Store,
    pub auth_chain: openssl::stack::Stack<openssl::x509::X509>,
}

impl crate::storage::Storage<API> {
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
                    &mut self.state.auth_chain.push(cert.clone())?;
                }
            } else {
                if cert.serial_number().to_bn()? == cert_serial {
                    let is_valid = crate::encryption::verify_client_auth_cert_chain(
                        &self.state.auth_store,
                        &self.state.auth_chain,
                        &cert,
                    );
                    return Ok((cert, is_valid));
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
                    &mut self.state.auth_chain.push(cert.clone())?;
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
                    let is_valid = crate::encryption::verify_client_auth_cert_chain(
                        &self.state.auth_store,
                        &self.state.auth_chain,
                        &cert,
                    );
                    return Ok((cert, is_valid));
                }
            }
        }
        Err(anyhow::anyhow!(
            "get_certificate_by_common_name -> Certificate with common name '{}' not found",
            common_name
        ))
    }
}
