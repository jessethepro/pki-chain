//! Protocol Module
//!
//! Defines the Request and Response enums for actions related to certificate management.
//! Processes the actions and returns appropriate responses.

use anyhow::{Context, Result};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509StoreContext;
use serde::{Deserialize, Serialize};

use crate::generate_intermediate_ca::RsaIntermediateCABuilder;
use crate::generate_user_keypair::RsaUserKeyPairBuilder;
use crate::storage::Storage;

/// Certificate data structure
#[derive(Debug, Clone)]
pub struct CertificateData {
    pub subject_common_name: String,
    pub issuer_common_name: String,
    pub serial_number: String,
    pub organization: String,
    pub organizational_unit: String,
    pub locality: String,
    pub state: String,
    pub country: String,
    pub validity_days: Option<u32>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub type_of_certificate: String,
    pub x509: Option<openssl::x509::X509>,
}

/// Filter options for listing certificates
#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum Filter {
    All,
    Intermediate,
    User,
    Root,
}

/// Request types from external applications
pub enum Request {
    CreateIntermediate {
        certificate_data: CertificateData,
    },
    CreateUser {
        certificate_data: CertificateData,
    },
    ListCertificates {
        filter: String,
    },
    PKIStatus,
    ValidateCertificate {
        subject_certficate_data: CertificateData,
        intermediate_certificate_data: CertificateData,
    },
}

/// Response types sent back to clients
#[derive(Debug, Clone)]
pub enum Response {
    CreateIntermediate {
        message: String,
        certificate_data: CertificateData,
        height: u64,
    },
    CreateUser {
        message: String,
        certificate_data: CertificateData,
        height: u64,
    },
    ListCertificates {
        message: String,
        certificates: Vec<CertificateData>,
        count: usize,
    },
    PKIStatus {
        message: String,
        status: String,
        total_certificates: u64,
        total_keys: u64,
        tracked_subject_names: usize,
        certificate_chain_valid: bool,
        private_key_chain_valid: bool,
        pki_chain_in_sync: bool,
    },
    ValidateCertificate {
        message: String,
        leaf_is_valid: bool,
        intermediate_is_valid: bool,
        root_is_valid: bool,
    },
    Error {
        message: String,
    },
}

pub struct Protocol {
    pub storage: Storage,
}

impl Protocol {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    fn get_key_certificate_by_height(
        &self,
        height: u64,
    ) -> Result<(
        openssl::pkey::PKey<openssl::pkey::Private>,
        openssl::x509::X509,
    )> {
        let cert_block = match self.storage.certificate_chain.get_block_by_height(height) {
            Ok(block) => block,
            Err(e) => return Err(e.into()),
        };
        let cert = match openssl::x509::X509::from_pem(&cert_block.block_data) {
            Ok(c) => c,
            Err(e) => return Err(e.into()),
        };

        let key_block = match self.storage.private_chain.get_block_by_height(height) {
            Ok(block) => block,
            Err(e) => return Err(e.into()),
        };
        let key = match openssl::pkey::PKey::private_key_from_der(&key_block.block_data) {
            Ok(k) => k,
            Err(e) => return Err(e.into()),
        };

        Ok((key, cert))
    }

    pub fn process_request(&self, request: Request) -> Result<Response> {
        match request {
            Request::CreateIntermediate { certificate_data } => {
                // Get Root CA from blockchain (height 0)
                let (root_key, root_cert) = match self.get_key_certificate_by_height(0) {
                    Ok((k, c)) => (k, c),
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve Root CA: {}", e),
                        })
                    }
                };
                // Generate intermediate certificate
                let (int_key, int_cert) = match RsaIntermediateCABuilder::new(root_key, root_cert)
                    .subject_common_name(certificate_data.subject_common_name.clone())
                    .organization(certificate_data.organization.clone())
                    .organizational_unit(certificate_data.organizational_unit.clone())
                    .locality(certificate_data.locality.clone())
                    .state(certificate_data.state.clone())
                    .country(certificate_data.country.clone())
                    .validity_days(certificate_data.validity_days.unwrap_or(1825))
                    .build()
                {
                    Ok((key, cert)) => (key, cert),
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to generate intermediate CA: {}", e),
                        })
                    }
                };

                // Store in blockchain
                let height = match self.storage.store_key_certificate(&int_key, &int_cert) {
                    Ok(h) => h,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to store intermediate CA: {}", e),
                        })
                    }
                };
                return Ok(Response::CreateIntermediate {
                    message: "Intermediate CA created successfully".to_string(),
                    certificate_data: CertificateData {
                        subject_common_name: certificate_data.subject_common_name,
                        issuer_common_name: certificate_data.issuer_common_name,
                        serial_number: int_cert
                            .serial_number()
                            .to_bn()
                            .unwrap()
                            .to_hex_str()
                            .unwrap()
                            .to_string(),
                        organization: certificate_data.organization,
                        organizational_unit: certificate_data.organizational_unit,
                        locality: certificate_data.locality,
                        state: certificate_data.state,
                        country: certificate_data.country,
                        validity_days: certificate_data.validity_days,
                        not_before: Some(
                            int_cert
                                .not_before()
                                .to_string()
                                .trim_end_matches('\0')
                                .to_string(),
                        ),
                        not_after: Some(
                            int_cert
                                .not_after()
                                .to_string()
                                .trim_end_matches('\0')
                                .to_string(),
                        ),
                        type_of_certificate: "Intermediate".to_string(),
                        x509: Some(int_cert.clone()),
                    },
                    height,
                });
            }
            Request::CreateUser { certificate_data } => {
                // Find issuer intermediate CA by common name
                let issuer_height = match self
                    .storage
                    .subject_name_to_height
                    .lock()
                    .unwrap()
                    .get(&certificate_data.issuer_common_name)
                {
                    Some(&h) => h,
                    None => {
                        return Ok(Response::Error {
                            message: format!(
                                "Issuer intermediate CA with common name '{}' not found",
                                certificate_data.issuer_common_name
                            ),
                        })
                    }
                };
                let (issuer_key, issuer_cert) = match self
                    .get_key_certificate_by_height(issuer_height)
                {
                    Ok((k, c)) => (k, c),
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve issuer intermediate CA: {}", e),
                        })
                    }
                };

                // Generate user keypair and certificate
                let (user_key, user_cert) =
                    match RsaUserKeyPairBuilder::new(issuer_key, issuer_cert)
                        .subject_common_name(certificate_data.subject_common_name.clone())
                        .organization(certificate_data.organization.clone())
                        .organizational_unit(certificate_data.organizational_unit.clone())
                        .locality(certificate_data.locality.clone())
                        .state(certificate_data.state.clone())
                        .country(certificate_data.country.clone())
                        .validity_days(certificate_data.validity_days.unwrap_or(1095))
                        .build()
                    {
                        Ok((key, cert)) => (key, cert),
                        Err(e) => {
                            return Ok(Response::Error {
                                message: format!("Failed to generate user keypair: {}", e),
                            })
                        }
                    };

                // Store in blockchain
                let height = match self.storage.store_key_certificate(&user_key, &user_cert) {
                    Ok(h) => h,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to store user keypair: {}", e),
                        })
                    }
                };

                return Ok(Response::CreateUser {
                    message: "User keypair created successfully".to_string(),
                    certificate_data: CertificateData {
                        subject_common_name: certificate_data.subject_common_name,
                        issuer_common_name: certificate_data.issuer_common_name,
                        serial_number: user_cert
                            .serial_number()
                            .to_bn()
                            .unwrap()
                            .to_hex_str()
                            .unwrap()
                            .to_string(),
                        organization: certificate_data.organization,
                        organizational_unit: certificate_data.organizational_unit,
                        locality: certificate_data.locality,
                        state: certificate_data.state,
                        country: certificate_data.country,
                        validity_days: certificate_data.validity_days,
                        not_before: Some(
                            user_cert
                                .not_before()
                                .to_string()
                                .trim_end_matches('\0')
                                .to_string(),
                        ),
                        not_after: Some(
                            user_cert
                                .not_after()
                                .to_string()
                                .trim_end_matches('\0')
                                .to_string(),
                        ),
                        type_of_certificate: "User".to_string(),
                        x509: Some(user_cert.clone()),
                    },
                    height,
                });
            }
            Request::ListCertificates { filter } => {
                let filter = match filter.as_str() {
                    "All" => Filter::All,
                    "Intermediate" => Filter::Intermediate,
                    "User" => Filter::User,
                    "Root" => Filter::Root,
                    _ => {
                        return Ok(Response::Error {
                            message: format!("Invalid filter option: {}", filter),
                        })
                    }
                };
                // Handle ListCertificates request
                let (certs, count) = match (|| -> Result<(Vec<CertificateData>, usize)> {
                    let mut certificates = Vec::new();
                    let cert_iter = self.storage.certificate_chain.iter();
                    for block_result in cert_iter {
                        let block = block_result?;
                        let cert = openssl::x509::X509::from_pem(&block.block_data)?;
                        let subject_common_name = cert
                            .subject_name()
                            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                            .next()
                            .unwrap()
                            .data()
                            .as_utf8()?
                            .to_string();
                        let issuer_common_name = cert
                            .issuer_name()
                            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                            .next()
                            .unwrap()
                            .data()
                            .as_utf8()?
                            .to_string();
                        let serial_number = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
                        // Determine type of certificate
                        let is_self_signed = subject_common_name == issuer_common_name;

                        // Check if certificate has CA basic constraints (pathlen indicates CA cert)
                        let pathlen = cert.pathlen();
                        let is_ca = match pathlen {
                            Some(_) => true,
                            None => false,
                        };
                        let type_of_certificate = {
                            if is_self_signed {
                                "Root".to_string()
                            } else if is_ca {
                                "Intermediate".to_string()
                            } else {
                                "User".to_string()
                            }
                        };
                        // Apply filter
                        match &filter {
                            Filter::All => {}
                            Filter::Intermediate if type_of_certificate != "Intermediate" => {
                                continue
                            }
                            Filter::User if type_of_certificate != "User" => continue,
                            Filter::Root if type_of_certificate != "Root" => continue,
                            _ => {}
                        }
                        let certificate_data = CertificateData {
                            subject_common_name,
                            issuer_common_name,
                            serial_number,
                            organization: "".to_string(),
                            organizational_unit: "".to_string(),
                            locality: "".to_string(),
                            state: "".to_string(),
                            country: "".to_string(),
                            validity_days: None,
                            not_before: Some(
                                cert.not_before()
                                    .to_string()
                                    .trim_end_matches('\0')
                                    .to_string(),
                            ),
                            not_after: Some(
                                cert.not_after()
                                    .to_string()
                                    .trim_end_matches('\0')
                                    .to_string(),
                            ),
                            type_of_certificate,
                            x509: Some(cert),
                        };
                        certificates.push(certificate_data);
                    }
                    let count = certificates.len();
                    Ok((certificates, count))
                })() {
                    Ok((c, cnt)) => (c, cnt),
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to list certificates: {}", e),
                        })
                    }
                };
                Ok(Response::ListCertificates {
                    message: "Certificates listed successfully".to_string(),
                    certificates: certs,
                    count,
                })
            }
            Request::PKIStatus => {
                let total_certificates = match self.storage.certificate_chain.block_count() {
                    Ok(len) => len,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to get total certificates: {}", e),
                        })
                    }
                };
                let total_keys = match self.storage.private_chain.block_count() {
                    Ok(len) => len,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to get total keys: {}", e),
                        })
                    }
                };
                let tracked_subject_names =
                    self.storage.subject_name_to_height.lock().unwrap().len();
                let pki_chain_in_sync = match self.storage.validate() {
                    Ok(valid) => valid,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to validate private key chain: {}", e),
                        })
                    }
                };
                // Handle PKIStatus request
                return Ok(Response::PKIStatus {
                    message: " PKI status retrieved successfully".to_string(),
                    status: if pki_chain_in_sync {
                        "Healthy".to_string()
                    } else {
                        "Unhealthy".to_string()
                    },
                    total_certificates,
                    total_keys,
                    tracked_subject_names,
                    certificate_chain_valid: true,
                    private_key_chain_valid: true,
                    pki_chain_in_sync,
                });
            }
            Request::ValidateCertificate {
                subject_certficate_data,
                intermediate_certificate_data,
            } => {
                // Handle ValidateCertificateChain request
                let root_cert = match self.get_key_certificate_by_height(0) {
                    Ok((_, c)) => c,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve Root CA: {}", e),
                        })
                    }
                };
                let mut store_builder =
                    X509StoreBuilder::new().context("Failed to create X509 store builder")?;
                store_builder
                    .add_cert(root_cert)
                    .context("Failed to add Root CA to X509 store")?;
                let store = store_builder.build();
                let mut chain = Stack::new().context("Failed to create X509 stack")?;
                chain
                    .push(
                        intermediate_certificate_data
                            .x509
                            .context("Intermediate certificate X509 missing")?,
                    )
                    .context("Failed to push intermediate certificate to chain")?;
                let mut verify_context =
                    X509StoreContext::new().context("Failed to create X509 store context")?;
                let is_valid = verify_context
                    .init(
                        &store,
                        subject_certficate_data
                            .x509
                            .as_ref()
                            .context("Subject certificate X509 missing")?,
                        &chain,
                        |c| c.verify_cert(),
                    )
                    .context("Failed to initialize X509 store context")?;
                if !is_valid {
                    return Ok(Response::ValidateCertificate {
                        message: "Certificate chain validation failed".to_string(),
                        leaf_is_valid: false,
                        intermediate_is_valid: false,
                        root_is_valid: false,
                    });
                }
                return Ok(Response::ValidateCertificate {
                    message: "Certificate chain validation completed".to_string(),
                    leaf_is_valid: true,
                    intermediate_is_valid: true,
                    root_is_valid: true,
                });
            }
        }
    }
}
