//! Protocol Module
//!
//! Provides a high-level abstraction layer for PKI certificate management operations.
//! This module owns the Storage layer and processes certificate-related requests through
//! a clean Request/Response pattern, enabling separation between UI logic and storage operations.
//!
//! # Architecture
//!
//! The Protocol layer:
//! - Owns the [`Storage`] instance for blockchain and key management
//! - Processes [`Request`] enums for certificate operations (Create, List, Validate, Status)
//! - Returns [`Response`] enums with operation results or errors
//! - Handles certificate chain validation and integrity checks
//! - Retrieves private keys from encrypted storage for signing operations
//!
//! # Usage Pattern
//!
//! ```no_run
//! use pki_chain::protocol::{Protocol, Request, Response};
//! use pki_chain::storage::Storage;
//! use pki_chain::configs::AppConfig;
//! use pki_chain::pki_generator::{CertificateData, CertificateDataType};
//!
//! # fn example() -> anyhow::Result<()> {
//! // Initialize storage and protocol
//! let config = AppConfig::load()?;
//! let storage = Storage::new(config)?;
//! let protocol = Protocol::new(storage);
//!
//! // Create an intermediate CA
//! let request = Request::CreateIntermediate {
//!     certificate_data: CertificateData {
//!         subject_common_name: "My Intermediate CA".to_string(),
//!         issuer_common_name: "MenaceLabs Root CA".to_string(),
//!         organization: "My Org".to_string(),
//!         organizational_unit: "IT".to_string(),
//!         locality: "City".to_string(),
//!         state: "State".to_string(),
//!         country: "US".to_string(),
//!         validity_days: 365 * 3,
//!         cert_type: CertificateDataType::IntermediateCA,
//!     },
//! };
//!
//! match protocol.process_request(request)? {
//!     Response::CreateIntermediate { message, height, .. } => {
//!         println!("{} at height {}", message, height);
//!     },
//!     Response::Error { message } => {
//!         eprintln!("Error: {}", message);
//!     },
//!     _ => {}
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! Protocol instances are typically wrapped in `Arc<Protocol>` for sharing across threads
//! (e.g., in TUI event handlers). The underlying Storage uses Mutex for thread-safe access
//! to the subject name index.

use crate::pki_generator::{generate_key_pair, CertificateData};
use crate::storage::Storage;
use anyhow::{Context, Result};
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509VerifyResult, X509};
use serde::{Deserialize, Serialize};

/// Filter options for listing certificates by type
#[derive(Debug, Deserialize, Serialize)]
pub(crate) enum Filter {
    /// List all certificates
    All,
    /// List only Intermediate CA certificates
    Intermediate,
    /// List only User certificates
    User,
    /// List only Root CA certificates
    Root,
}

/// Request types for certificate management operations
///
/// All certificate operations flow through these request types, which are processed
/// by [`Protocol::process_request()`] to perform the actual operations and return
/// appropriate [`Response`] variants.
pub enum Request {
    /// Create a new Intermediate CA certificate signed by the Root CA
    CreateIntermediate { certificate_data: CertificateData },
    /// Create a new User certificate signed by a specified Intermediate CA
    CreateUser { certificate_data: CertificateData },
    /// List certificates filtered by type
    ListCertificates { filter: String },
    /// Get current PKI system status and statistics
    PKIStatus,
    /// Validate a certificate chain (leaf → intermediate → root)
    ValidateCertificate {
        subject_certificate_data: CertificateData,
        intermediate_certificate_data: CertificateData,
    },
}

/// Response types returned from certificate operations
///
/// Each successful request returns a specific Response variant containing
/// operation results. Errors are returned as `Response::Error` variants.
#[derive(Debug, Clone)]
pub enum Response {
    /// Intermediate CA certificate created successfully
    CreateIntermediate {
        message: String,
        certificate_data: X509,
        height: u64,
    },
    /// User certificate created successfully
    CreateUser {
        message: String,
        certificate_data: X509,
        height: u64,
    },
    /// Certificate list retrieved successfully
    ListCertificates {
        message: String,
        certificates: Vec<X509>,
        count: usize,
    },
    /// PKI system status and validation results
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
    /// Certificate chain validation results
    ValidateCertificate {
        message: String,
        leaf_is_valid: bool,
        intermediate_is_valid: bool,
        root_is_valid: bool,
    },
    /// Error occurred during request processing
    Error { message: String },
}

/// Protocol layer for PKI certificate management
///
/// Owns the Storage instance and provides a high-level interface for certificate
/// operations through the Request/Response pattern. Handles certificate generation,
/// storage, retrieval, and validation operations.
///
/// # Thread Safety
///
/// Typically wrapped in `Arc<Protocol>` for sharing across threads in the TUI.
pub struct Protocol {
    /// Storage layer for blockchain and encrypted key management
    pub storage: Storage,
}

impl Protocol {
    /// Creates a new Protocol instance that owns the given Storage
    ///
    /// # Arguments
    ///
    /// * `storage` - Initialized Storage instance with blockchain and encrypted key store
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pki_chain::protocol::Protocol;
    /// use pki_chain::storage::Storage;
    /// use pki_chain::configs::AppConfig;
    ///
    /// # fn example() -> anyhow::Result<()> {
    /// let config = AppConfig::load()?;
    /// let storage = Storage::new(config)?;
    /// let protocol = Protocol::new(storage);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    /// Processes a certificate management request and returns the appropriate response
    ///
    /// This is the main entry point for all certificate operations. Handles:
    /// - Creating Intermediate CA certificates (signed by Root CA)
    /// - Creating User certificates (signed by specified Intermediate CA)
    /// - Listing certificates with optional filtering
    /// - Getting PKI system status and validation results
    /// - Validating certificate chains
    ///
    /// # Arguments
    ///
    /// * `request` - The operation to perform
    ///
    /// # Returns
    ///
    /// * `Result<Response>` - The operation result or Response::Error on failure
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use pki_chain::protocol::{Protocol, Request, Response};
    /// # fn example(protocol: &Protocol) -> anyhow::Result<()> {
    /// let response = protocol.process_request(Request::PKIStatus)?;
    /// match response {
    ///     Response::PKIStatus { total_certificates, .. } => {
    ///         println!("Total certificates: {}", total_certificates);
    ///     },
    ///     _ => {}
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn process_request(&self, request: Request) -> Result<Response> {
        match request {
            Request::CreateIntermediate { certificate_data } => {
                // Get Root CA from blockchain (height 0)
                let root_key = match (|| -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                    let key = self
                        .storage
                        .encrypted_key_store
                        .retrieve_key(0)
                        .context("Failed to retrieve Root CA private key")?;
                    Ok(key)
                })() {
                    Ok(k) => k,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve Root CA: {}", e),
                        })
                    }
                };
                // Generate intermediate certificate
                let (int_key, int_cert) = match generate_key_pair(certificate_data, &root_key) {
                    Ok((k, c)) => (k, c),
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to generate intermediate CA: {}", e),
                        })
                    }
                };

                // Store in blockchain
                let height = match self
                    .storage
                    .store_key_certificate(int_key, int_cert.clone())
                {
                    Ok(h) => h,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to store intermediate CA: {}", e),
                        })
                    }
                };
                return Ok(Response::CreateIntermediate {
                    message: "Intermediate CA created successfully".to_string(),
                    certificate_data: int_cert.clone(),
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
                let issuer_key =
                    match (|| -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                        let key = self
                            .storage
                            .encrypted_key_store
                            .retrieve_key(issuer_height)
                            .context("Failed to retrieve issuer intermediate CA private key")?;
                        Ok(key)
                    })() {
                        Ok(k) => k,
                        Err(e) => {
                            return Ok(Response::Error {
                                message: format!(
                                    "Failed to retrieve issuer intermediate CA: {}",
                                    e
                                ),
                            })
                        }
                    };

                // Generate user keypair and certificate
                let (user_key, user_cert) = match generate_key_pair(certificate_data, &issuer_key) {
                    Ok((k, c)) => (k, c),
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to generate user keypair: {}", e),
                        })
                    }
                };

                // Store in blockchain
                let height = match self
                    .storage
                    .store_key_certificate(user_key, user_cert.clone())
                {
                    Ok(h) => h,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to store user keypair: {}", e),
                        })
                    }
                };

                return Ok(Response::CreateUser {
                    message: "User keypair created successfully".to_string(),
                    certificate_data: user_cert,
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
                let (certs, count) = match (|| -> Result<(Vec<X509>, usize)> {
                    let mut certificates = Vec::new();
                    let cert_iter = self.storage.certificate_chain.iter();
                    for block_result in cert_iter {
                        let block = block_result?;
                        let cert = X509::from_der(&block.block_data)
                            .context("Failed to parse certificate from PEM")?;
                        // Determine type of certificate
                        let is_self_signed = cert
                            .subject_name()
                            .entries_by_nid(Nid::COMMONNAME)
                            .next()
                            .and_then(|entry| entry.data().as_utf8().ok())
                            .map(|s| s.to_string())
                            .unwrap_or_default()
                            == cert
                                .issuer_name()
                                .entries_by_nid(Nid::COMMONNAME)
                                .next()
                                .and_then(|entry| entry.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_default();

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
                        certificates.push(cert);
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
                return Ok(Response::ListCertificates {
                    message: "Certificates listed successfully".to_string(),
                    certificates: certs,
                    count,
                });
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
                let pki_chain_in_sync = match self.storage.validate_certificates() {
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
                subject_certificate_data,
                intermediate_certificate_data,
            } => {
                // Handle ValidateCertificate request - validate each certificate level separately
                let root_cert = match (|| -> Result<X509> {
                    let cert_block = self
                        .storage
                        .certificate_chain
                        .get_block_by_height(0)
                        .context("Failed to retrieve Root CA certificate block")?;
                    let cert = X509::from_der(&cert_block.block_data)
                        .context("Failed to parse Root CA certificate from PEM")?;
                    Ok(cert)
                })() {
                    Ok(c) => c,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve Root CA: {}", e),
                        })
                    }
                };

                let intermediate_cert = match (|| -> Result<X509> {
                    let cert_block = self
                        .storage
                        .certificate_chain
                        .get_block_by_height(
                            *self
                                .storage
                                .subject_name_to_height
                                .lock()
                                .unwrap()
                                .get(&intermediate_certificate_data.subject_common_name)
                                .context("Intermediate CA common name not found")?,
                        )
                        .context("Failed to retrieve Intermediate CA certificate block")?;
                    let cert = X509::from_der(&cert_block.block_data)
                        .context("Failed to parse Intermediate CA certificate from DER")?;
                    Ok(cert)
                })() {
                    Ok(c) => c,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve Intermediate CA: {}", e),
                        })
                    }
                };
                let subject_cert = match (|| -> Result<X509> {
                    let cert_block = self
                        .storage
                        .certificate_chain
                        .get_block_by_height(
                            *self
                                .storage
                                .subject_name_to_height
                                .lock()
                                .unwrap()
                                .get(&subject_certificate_data.subject_common_name)
                                .context("Subject certificate common name not found")?,
                        )
                        .context("Failed to retrieve subject certificate block")?;
                    let cert = X509::from_der(&cert_block.block_data)
                        .context("Failed to parse subject certificate from DER")?;
                    Ok(cert)
                })() {
                    Ok(c) => c,
                    Err(e) => {
                        return Ok(Response::Error {
                            message: format!("Failed to retrieve subject certificate: {}", e),
                        })
                    }
                };

                // Validate root certificate (self-signed, not expired)
                let root_is_valid = root_cert.issued(&root_cert) == X509VerifyResult::OK
                    && root_cert.not_after()
                        > openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref();

                // Validate intermediate certificate against root
                let mut store_builder_intermediate = X509StoreBuilder::new()
                    .context("Failed to create X509 store builder for intermediate")?;
                store_builder_intermediate
                    .add_cert(root_cert.clone())
                    .context("Failed to add Root CA to store")?;
                let store_intermediate = store_builder_intermediate.build();
                let empty_chain = Stack::new().context("Failed to create empty X509 stack")?;
                let mut verify_context_intermediate = X509StoreContext::new()
                    .context("Failed to create X509 store context for intermediate")?;
                let intermediate_is_valid = verify_context_intermediate
                    .init(&store_intermediate, &intermediate_cert, &empty_chain, |c| {
                        c.verify_cert()
                    })
                    .context("Failed to verify intermediate certificate")?;

                // Validate subject certificate against full chain (intermediate + root)
                let mut store_builder_leaf = X509StoreBuilder::new()
                    .context("Failed to create X509 store builder for leaf")?;
                store_builder_leaf
                    .add_cert(root_cert)
                    .context("Failed to add Root CA to leaf store")?;
                let store_leaf = store_builder_leaf.build();
                let mut chain = Stack::new().context("Failed to create X509 stack for leaf")?;
                chain
                    .push(intermediate_cert.clone())
                    .context("Failed to push intermediate certificate to chain")?;
                let mut verify_context_leaf = X509StoreContext::new()
                    .context("Failed to create X509 store context for leaf")?;
                let leaf_is_valid = verify_context_leaf
                    .init(&store_leaf, &subject_cert, &chain, |c| c.verify_cert())
                    .context("Failed to verify subject certificate")?;

                let all_valid = root_is_valid && intermediate_is_valid && leaf_is_valid;
                return Ok(Response::ValidateCertificate {
                    message: if all_valid {
                        "Certificate chain validation successful".to_string()
                    } else {
                        format!(
                            "Certificate chain validation failed - Root: {}, Intermediate: {}, Leaf: {}",
                            root_is_valid, intermediate_is_valid, leaf_is_valid
                        )
                    },
                    leaf_is_valid,
                    intermediate_is_valid,
                    root_is_valid,
                });
            }
        }
    }
}
