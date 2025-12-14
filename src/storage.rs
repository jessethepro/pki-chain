use std::sync::Arc;

use anyhow::{Context, Result};
use libblockchain::blockchain::BlockChain;

pub struct Storage {
    // Initialize blockchain storage for certificates and private keys
    pub certificate_chain: Arc<BlockChain>,
    pub private_chain: Arc<BlockChain>,
}

impl Storage {
    pub fn new(app_key_path: &str) -> Result<Self> {
        Ok(Storage {
            // Initialize blockchain storage for certificates and private keys
            certificate_chain: Arc::new(BlockChain::new("data/certificates", app_key_path)?),
            private_chain: Arc::new(BlockChain::new("data/private_keys", app_key_path)?),
        })
    }
    pub fn store_key_certificate(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        certificate: &openssl::x509::X509,
    ) -> Result<u64> {
        // Save certificate to blockchain
        let certificate_height = self
            .certificate_chain
            .put_block(certificate.to_pem()?)
            .context("Failed to store Root CA certificate in blockchain")?;

        // Store private key with rollback on failure
        let private_key_height = self
            .private_chain
            .put_block(private_key.private_key_to_der()?)
            .or_else(|e| {
                // Rollback certificate block if private key storage fails
                let _ = self.certificate_chain.delete_latest_block();
                Err(e)
            })?;
        if private_key_height == certificate_height {
            let certificate_block = self
                .certificate_chain
                .get_block_by_height(private_key_height)?;
            let certificate_signature: Result<Vec<u8>> = (|| {
                let mut signer = openssl::sign::Signer::new(
                    openssl::hash::MessageDigest::sha256(),
                    &private_key,
                )
                .context("Failed to create signer for certificate signature")?;
                let signature = signer
                    .sign_oneshot_to_vec(&certificate_block.block_data)
                    .context("Failed to sign certificate block data")?;
                Ok(signature)
            })();
            let signature = certificate_signature?;
            let cert_signature_height = self
                .certificate_chain
                .put_signature(private_key_height, signature.clone())?;
            let key_signature_height = self
                .private_chain
                .put_signature(private_key_height, signature)?;
            assert_eq!(
                self.certificate_chain
                    .get_signature_by_height(cert_signature_height)?,
                self.private_chain
                    .get_signature_by_height(key_signature_height)?,
                "Stored signatures do not match"
            );
        }

        Ok(certificate_height)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.certificate_chain.block_count()? == 0 && self.private_chain.block_count()? == 0)
    }

    pub fn verify_stored_key(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        height: u64,
    ) -> Result<bool> {
        let stored_key = {
            let block = self.private_chain.get_block_by_height(height)?;
            openssl::pkey::PKey::private_key_from_der(&block.block_data)
                .context("Failed to parse stored Root CA key")?
        };
        Ok(stored_key.private_key_to_der()? == private_key.private_key_to_der()?)
    }

    pub fn verify_stored_certificate(
        &self,
        certificate: &openssl::x509::X509,
        height: u64,
    ) -> Result<bool> {
        let stored_cert = {
            let block = self.certificate_chain.get_block_by_height(height)?;
            openssl::x509::X509::from_pem(&block.block_data)
                .context("Failed to parse stored Root CA certificate")?
        };
        Ok(stored_cert.to_pem()? == certificate.to_pem()?)
    }

    pub fn verify_stored_key_certificate_pair(
        &self,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        certificate: &openssl::x509::X509,
        height: u64,
    ) -> Result<bool> {
        Ok(self.verify_stored_key(private_key, height)?
            && self.verify_stored_certificate(certificate, height)?)
    }

    pub fn validate(&self) -> Result<bool> {
        let cert_iter = self.certificate_chain.iter();
        for cert_block in cert_iter {
            let cert_block = cert_block?;
            let height = cert_block.block_header.height;
            let cert_signature = self.certificate_chain.get_signature_by_height(height)?;
            let key_signature = self.private_chain.get_signature_by_height(height)?;
            if cert_signature != key_signature {
                return Ok(false);
            }
        }
        self.certificate_chain.validate()?;
        self.private_chain.validate()?;
        Ok(true)
    }
}
