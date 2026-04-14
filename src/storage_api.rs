pub struct API {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
}

impl crate::storage::Storage<API> {
    pub fn get_certificate_by_serial(
        &self,
        cert_serial: openssl::bn::BigNum,
    ) -> anyhow::Result<(openssl::x509::X509, u64)> {
        let app_key = crate::encryption::get_app_private_key(&self.app_config)?;
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 1..block_count {
            let (cert_block, cert_signature) =
                match self.state.certificate_chain.get_block_by_height(i) {
                    (Ok(block), Ok(signature)) => (block, signature),
                    (Err(e), _) | (_, Err(e)) => {
                        return Err(anyhow::anyhow!(
                            "Failed to get block by height {}: {}",
                            i,
                            e
                        ))
                    }
                };
            let (cert, cert_verified) = match crate::encryption::verify_and_decrypt_cert(
                cert_block.block_data().as_slice(),
                cert_signature.as_slice(),
                app_key.clone(),
            ) {
                (Ok(data), Ok(verified)) => (data, verified),
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "Failed to verify and decrypt certificate: {}",
                        e
                    ))
                }
            };
            if !cert_verified {
                return Err(anyhow::anyhow!(
                    "Certificate at height {} failed signature verification",
                    i
                ));
            }
            if cert.serial_number().to_bn()? == cert_serial {
                return Ok((cert, i));
            }
        }
        Err(anyhow::anyhow!(
            "Certificate with serial number {} not found",
            cert_serial.to_dec_str()?
        ))
    }

    pub fn get_certificate_by_common_name(
        &self,
        common_name: &str,
    ) -> anyhow::Result<(openssl::x509::X509, u64)> {
        let app_key = crate::encryption::get_app_private_key(&self.app_config)?;
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 1..block_count {
            let (cert_block, cert_signature) =
                match self.state.certificate_chain.get_block_by_height(i) {
                    (Ok(block), Ok(signature)) => (block, signature),
                    (Err(e), _) | (_, Err(e)) => {
                        return Err(anyhow::anyhow!(
                            "Failed to get block by height {}: {}",
                            i,
                            e
                        ))
                    }
                };
            let (cert, cert_verified) = match crate::encryption::verify_and_decrypt_cert(
                cert_block.block_data().as_slice(),
                cert_signature.as_slice(),
                app_key.clone(),
            ) {
                (Ok(data), Ok(verified)) => (data, verified),
                (Err(e), _) | (_, Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "Failed to verify and decrypt certificate: {}",
                        e
                    ))
                }
            };
            if !cert_verified {
                return Err(anyhow::anyhow!(
                    "Certificate at height {} failed signature verification",
                    i
                ));
            }
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
                return Ok((cert, i));
            }
        }
        Err(anyhow::anyhow!(
            "Certificate with common name '{}' not found",
            common_name
        ))
    }
}
