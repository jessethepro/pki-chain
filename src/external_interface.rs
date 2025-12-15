//! External Interface Module
//!
//! Provides Unix socket-based IPC for external applications to interact with the PKI chain.

use crate::generate_user_keypair::RsaUserKeyPairBuilder;
use crate::storage::Storage;
use anyhow::{Context, Result};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

const SOCKET_PATH: &str = "/tmp/pki_socket";

/// Filter options for listing certificates
#[derive(Debug, Deserialize, Serialize)]
enum Filter {
    All,
    Intermediate,
    User,
    Root,
}

/// Request types from external applications
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Request {
    CreateIntermediate {
        subject_common_name: String,
        organization: String,
        organizational_unit: String,
        locality: String,
        state: String,
        country: String,
        validity_days: u32,
    },
    CreateUser {
        subject_common_name: String,
        organization: String,
        organizational_unit: String,
        locality: String,
        state: String,
        country: String,
        validity_days: u32,
        issuer_common_name: String,
    },
    ListCertificates {
        filter: String,
    },
    PKIStatus,
    SocketTest,
}

/// Response types sent back to clients
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum Response {
    Success {
        message: String,
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}

/// Start the Unix socket server and listen for incoming requests
///
/// # Returns
/// * `Result<()>` - Returns Ok if server starts successfully
///
/// # Example
/// ```no_run
/// use external_interface::start_socket_server;
/// start_socket_server().expect("Failed to start socket server");
/// ```
pub fn start_socket_server(storage: Arc<Storage>) -> Result<()> {
    // Remove existing socket file if it exists
    if Path::new(SOCKET_PATH).exists() {
        fs::remove_file(SOCKET_PATH).context(format!(
            "Failed to remove existing socket at {}",
            SOCKET_PATH
        ))?;
    }
    // Initialize the state if needed
    let chain_iter = storage.certificate_chain.iter();
    for (height, block_result) in chain_iter.enumerate() {
        if let Ok(block) = block_result {
            if let Ok(cert) = openssl::x509::X509::from_pem(&block.block_data) {
                let subject_name =
                    cert.subject_name()
                        .entries()
                        .next()
                        .map_or("Unknown".to_string(), |entry| {
                            entry
                                .data()
                                .as_utf8()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|_| "InvalidUTF8".to_string())
                        });
                storage
                    .subject_name_to_height
                    .lock()
                    .unwrap()
                    .insert(subject_name, height as u64);
            }
        }
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(SOCKET_PATH)
        .context(format!("Failed to bind Unix socket at {}", SOCKET_PATH))?;

    println!("✓ Unix socket server started at {}", SOCKET_PATH);
    println!("  Listening for external requests...\n");

    // Accept incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let storage_clone = Arc::clone(&storage);
                if let Err(e) = handle_client(stream, storage_clone) {
                    eprintln!("Error handling client request: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}

/// Handle an individual client connection
fn handle_client(mut stream: UnixStream, storage: Arc<Storage>) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let request: Request = {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let mut buf = vec![0u8; u32::from_le_bytes(len_buf) as usize];
        reader.read_exact(&mut buf)?;
        let message_str = String::from_utf8(buf).context("Failed to read message from client")?;
        println!("Received raw message: {}", message_str);
        serde_json::from_str(&message_str).context("Failed to parse JSON message")?
    };

    println!("Received request: {:?}", request);

    // Process request and generate response
    let response = match request {
        Request::CreateIntermediate {
            subject_common_name,
            organization,
            organizational_unit,
            locality,
            state,
            country,
            validity_days,
        } => handle_create_intermediate(
            subject_common_name,
            organization,
            organizational_unit,
            locality,
            state,
            country,
            validity_days,
            &storage,
        ),
        Request::CreateUser {
            subject_common_name,
            organization,
            organizational_unit,
            locality,
            state,
            country,
            validity_days,
            issuer_common_name,
        } => handle_create_user(
            subject_common_name,
            organization,
            organizational_unit,
            locality,
            state,
            country,
            issuer_common_name,
            validity_days,
            &storage,
        ),
        Request::ListCertificates { filter } => match filter.as_str() {
            "All" => handle_list_certificates(&storage, Filter::All),
            "Intermediate" => handle_list_certificates(&storage, Filter::Intermediate),
            "User" => handle_list_certificates(&storage, Filter::User),
            "Root" => handle_list_certificates(&storage, Filter::Root),
            _ => Response::Error {
                message: format!("Invalid filter option: {}", filter),
            },
        },
        Request::PKIStatus => handle_pki_status(&storage),
        Request::SocketTest => Response::Success {
            message: "Socket test successful".to_string(),
            data: None,
        },
    };

    // Send response back to client
    let response_bytes = {
        let mut bytes_buf = Vec::new();
        let response_json = serde_json::to_string(&response)?;
        //println!("Sending response: {}", response_json);
        bytes_buf.extend_from_slice(&(response_json.len() as u32).to_le_bytes());
        bytes_buf.extend_from_slice(response_json.as_bytes());
        bytes_buf
    };
    stream.write_all(&response_bytes)?;
    stream.flush()?;

    Ok(())
}

/// Handle CreateIntermediate request
fn handle_create_intermediate(
    subject_common_name: String,
    organization: String,
    organizational_unit: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
    storage: &Storage,
) -> Response {
    if storage
        .subject_name_to_height
        .lock()
        .unwrap()
        .get(&subject_common_name)
        .is_some()
    {
        return Response::Error {
            message: format!(
                "An entry with the subject common name '{}' already exists",
                subject_common_name
            ),
        };
    }
    use crate::generate_intermediate_ca::RsaIntermediateCABuilder;
    println!(
        "Creating Intermediate CA: CN={}, O={}, OU={}",
        subject_common_name, organization, organizational_unit
    );
    let (root_key, root_cert) = match (|| -> Result<(PKey<Private>, X509)> {
        let cert_block = storage
            .certificate_chain
            .get_block_by_height(0)
            .context("Failed to get Root CA certificate block at height 0")?;

        println!(
            "Root CA cert block size: {} bytes",
            cert_block.block_data.len()
        );

        let cert = openssl::x509::X509::from_pem(&cert_block.block_data)
            .context("Failed to parse Root CA certificate from blockchain")?;

        let key_block = storage
            .private_chain
            .get_block_by_height(0)
            .context("Failed to get Root CA private key block at height 0")?;

        println!(
            "Root CA key block size: {} bytes",
            key_block.block_data.len()
        );

        let key = openssl::pkey::PKey::private_key_from_der(&key_block.block_data)
            .context("Failed to parse Root CA private key from blockchain")?;

        Ok((key, cert))
    })() {
        Ok(result) => result,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to retrieve Root CA from blockchain: {}", e),
            };
        }
    };
    let (private_key, certificate) = match RsaIntermediateCABuilder::new(root_key, root_cert)
        .subject_common_name(subject_common_name.clone())
        .organization(organization.clone())
        .organizational_unit(organizational_unit.clone())
        .locality(locality.clone())
        .state(state.clone())
        .country(country.clone())
        .validity_days(validity_days)
        .build()
    {
        Ok(result) => result,
        Err(e) => {
            return Response::Error {
                message: format!(
                    "Failed to build intermediate certificate or private key: {}",
                    e
                ),
            };
        }
    };

    // Store certificate in blockchain
    let height = storage
        .store_key_certificate(&private_key, &certificate)
        .map_err(|e| Response::Error {
            message: format!("Failed to store key-certificate pair: {}", e),
        })
        .ok();
    match height {
        Some(h) => {
            storage
                .subject_name_to_height
                .lock()
                .unwrap()
                .insert(subject_common_name.clone(), h);
            println!(
                "✓ Intermediate CA certificate and private key stored in blockchain at height {}",
                h
            );
        }
        None => {
            return Response::Error {
                message: "Failed to store intermediate key-certificate pair".to_string(),
            };
        }
    }
    Response::Success {
        message: format!(
            "Intermediate certificate creation requested for CN={}",
            subject_common_name
        ),
        data: Some(serde_json::json!({
            "common_name": subject_common_name,
            "organization": organization,
            "organizational_unit": organizational_unit,
            "country": country,
        })),
    }
}

/// Handle CreateUser request
fn handle_create_user(
    subject_common_name: String,
    organization: String,
    organizational_unit: String,
    locality: String,
    state: String,
    country: String,
    issuer_common_name: String,
    validity_days: u32,
    storage: &Storage,
) -> Response {
    println!(
        "Creating User Certificate: CN={}, O={}, OU={}, Issuer CN={}",
        subject_common_name, organization, organizational_unit, issuer_common_name
    );
    if storage
        .subject_name_to_height
        .lock()
        .unwrap()
        .get(&subject_common_name)
        .is_some()
    {
        return Response::Error {
            message: format!(
                "An entry with the subject common name '{}' already exists",
                subject_common_name
            ),
        };
    }
    let (intermediate_key, intermediate_cert) = match (|| -> Result<(PKey<Private>, X509)> {
        let intermediate_height = {
            match storage
                .subject_name_to_height
                .lock()
                .unwrap()
                .get(&issuer_common_name)
            {
                Some(height) => height.clone(),
                None => {
                    return Err(anyhow::anyhow!(
                        "Issuer common name not found in state: {}",
                        issuer_common_name
                    ));
                }
            }
        };

        let block = storage
            .certificate_chain
            .get_block_by_height(intermediate_height)?;

        let cert = openssl::x509::X509::from_pem(&block.block_data)
            .context("Failed to parse intermediate certificate from blockchain")?;

        let key_block = storage
            .private_chain
            .get_block_by_height(intermediate_height)?;

        let key = openssl::pkey::PKey::private_key_from_der(&key_block.block_data)
            .context("Failed to parse intermediate private key from blockchain")?;

        Ok((key, cert))
    })() {
        Ok(result) => result,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to retrieve Intermediate CA from blockchain: {}", e),
            };
        }
    };
    let (private_key, certificate) =
        match RsaUserKeyPairBuilder::new(intermediate_key, intermediate_cert)
            .subject_common_name(subject_common_name.clone())
            .organization(organization.clone())
            .organizational_unit(organizational_unit.clone())
            .locality(locality.clone())
            .state(state.clone())
            .country(country.clone())
            .validity_days(validity_days)
            .build()
        {
            Ok(result) => result,
            Err(e) => {
                return Response::Error {
                    message: format!(
                        "Failed to build intermediate certificate or private key: {}",
                        e
                    ),
                };
            }
        };
    // Store certificate and key in blockchain
    let height = storage
        .store_key_certificate(&private_key, &certificate)
        .map_err(|e| Response::Error {
            message: format!("Failed to store key-certificate pair: {}", e),
        })
        .ok();
    match height {
        Some(h) => {
            storage
                .subject_name_to_height
                .lock()
                .unwrap()
                .insert(subject_common_name.clone(), h);
            println!(
                "✓ User certificate and private key stored in blockchain at height {}",
                h
            );
        }
        None => {
            return Response::Error {
                message: "Failed to store user key-certificate pair".to_string(),
            };
        }
    }

    Response::Success {
        message: format!(
            "User certificate creation requested for CN={}",
            subject_common_name
        ),
        data: Some(serde_json::json!({
            "common_name": subject_common_name,
            "organization": organization,
            "organizational_unit": organizational_unit,
            "locality": locality,
            "state": state,
            "country": country,
            "issuer_common_name": issuer_common_name,
            "validity_days": validity_days,
        })),
    }
}

/// Handle ListCertificates request
fn handle_list_certificates(storage: &Storage, filter: Filter) -> Response {
    // Each certificate should have the format:
    // {
    //   "subject_common_name": "Example CN",
    //   "organization": "Example Org",
    //   "organizational_unit": "Example OU",
    //   "country": "US",
    //   "state": "California",
    //   "locality": "San Francisco",
    //   "validity_from": "2025-01-01T00:00:00Z",
    //   "validity_to": "2026-01-01T00:00:00Z",
    //   "issuer_common_name": "Issuer CN",
    //   "serial_number": "1234567890",
    //   "type": "Root CA" | "Intermediate CA" | "User",
    // }
    let response_data_json = (|| -> Result<serde_json::Value, serde_json::Error> {
        let certificates: Vec<serde_json::Value> = {
            let chain_iter = storage.certificate_chain.iter();
            let mut certs = Vec::new();
            for block_result in chain_iter {
                if let Ok(block) = block_result {
                    if let Ok(cert) = openssl::x509::X509::from_pem(&block.block_data) {
                        let subject_name = cert.subject_name().entries().next().map_or(
                            "Unknown".to_string(),
                            |entry| {
                                entry
                                    .data()
                                    .as_utf8()
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|_| "InvalidUTF8".to_string())
                            },
                        );
                        let issuer_name = cert.issuer_name().entries().next().map_or(
                            "Unknown".to_string(),
                            |entry| {
                                entry
                                    .data()
                                    .as_utf8()
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|_| "InvalidUTF8".to_string())
                            },
                        );
                        let serial_number = cert
                            .serial_number()
                            .to_bn()
                            .ok()
                            .and_then(|bn| bn.to_hex_str().ok())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "Unknown".to_string());

                        // Determine certificate type by checking basic constraints
                        let cert_type = {
                            let subject_bytes = cert.subject_name().to_der().unwrap_or_default();
                            let issuer_bytes = cert.issuer_name().to_der().unwrap_or_default();
                            let is_self_signed = subject_bytes == issuer_bytes;

                            // Check if certificate has CA basic constraints (pathlen indicates CA cert)
                            let pathlen = cert.pathlen();
                            let is_ca = match pathlen {
                                Some(_) => true,
                                None => false,
                            };

                            if is_self_signed {
                                "Root CA".to_string()
                            } else if is_ca {
                                "Intermediate CA".to_string()
                            } else {
                                "User Certificate".to_string()
                            }
                        };

                        // Extract certificate details
                        let (organization, organizational_unit, country, state, locality) = {
                            let subject = cert.subject_name();
                            let org = subject
                                .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
                                .next()
                                .and_then(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "Unknown".to_string());
                            let ou = subject
                                .entries_by_nid(openssl::nid::Nid::ORGANIZATIONALUNITNAME)
                                .next()
                                .and_then(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "Unknown".to_string());
                            let c = subject
                                .entries_by_nid(openssl::nid::Nid::COUNTRYNAME)
                                .next()
                                .and_then(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "Unknown".to_string());
                            let st = subject
                                .entries_by_nid(openssl::nid::Nid::STATEORPROVINCENAME)
                                .next()
                                .and_then(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "Unknown".to_string());
                            let loc = subject
                                .entries_by_nid(openssl::nid::Nid::LOCALITYNAME)
                                .next()
                                .and_then(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "Unknown".to_string());
                            (org, ou, c, st, loc)
                        };

                        let (validity_from, validity_to) = {
                            let not_before = cert.not_before().to_string();
                            let not_after = cert.not_after().to_string();
                            (not_before, not_after)
                        };
                        // Apply filter
                        match filter {
                            Filter::All => {}
                            Filter::Intermediate => {
                                if cert_type != "Intermediate CA" {
                                    continue;
                                }
                            }
                            Filter::User => {
                                if cert_type != "User Certificate" {
                                    continue;
                                }
                            }
                            Filter::Root => {
                                if cert_type != "Root CA" {
                                    continue;
                                }
                            }
                        }
                        certs.push(serde_json::json!({
                            "subject_common_name": subject_name,
                            "organization": organization,
                            "organizational_unit": organizational_unit,
                            "country": country,
                            "state": state,
                            "locality": locality,
                            "validity_from": validity_from,
                            "validity_to": validity_to,
                            "issuer_common_name": issuer_name,
                            "serial_number": serial_number,
                            "type": cert_type,
                        }));
                    }
                }
            }
            certs
        };
        Ok(serde_json::json!({ "certificates": certificates, "count": certificates.len() }))
    })();
    match response_data_json {
        Ok(data) => Response::Success {
            message: "Certificate list retrieved".to_string(),
            data: Some(data),
        },
        Err(e) => Response::Error {
            message: format!("Failed to serialize certificate list: {}", e),
        },
    }
}

/// Handle PKIStatus request
fn handle_pki_status(storage: &Storage) -> Response {
    // Validate both chains
    if !storage.validate().unwrap_or(false) {
        return Response::Error {
            message: "Blockchain validation failed".to_string(),
        };
    }

    Response::Success {
        message: "PKI system operational".to_string(),
        data: Some(serde_json::json!({
            "status": "running",
            "Total Certificates": storage.certificate_chain.block_count().unwrap_or(0),
            "total_Keys": storage.private_chain.block_count().unwrap_or(0),
            "tracked_subject_names": storage.subject_name_to_height.lock().unwrap().len(),
            "certificate_chain_valid": storage.certificate_chain.validate().is_ok(),
            "private_key_chain_valid": storage.private_chain.validate().is_ok(),
            "PKI Chain in Sync": true,
        })),
    }
}
