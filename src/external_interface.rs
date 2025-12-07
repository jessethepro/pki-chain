//! External Interface Module
//!
//! Provides Unix socket-based IPC for external applications to interact with the PKI chain.

use crate::chain_state::State;
use crate::generate_user_keypair::RsaUserKeyPairBuilder;
use anyhow::{Context, Result};
use libblockchain::blockchain::BlockChain;
use libblockchain::uuid::Uuid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

const SOCKET_PATH: &str = "/tmp/pki_socket";

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
    ListCertificates,
    PKIStatus,
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
pub fn start_socket_server(
    certificate_chain: Arc<Mutex<BlockChain>>,
    private_chain: Arc<Mutex<BlockChain>>,
) -> Result<()> {
    // Remove existing socket file if it exists
    if Path::new(SOCKET_PATH).exists() {
        fs::remove_file(SOCKET_PATH).context(format!(
            "Failed to remove existing socket at {}",
            SOCKET_PATH
        ))?;
    }
    let state = Arc::new(Mutex::new(State::new()));
    // Initialize the state if needed
    {
        let mut state_lock = state.lock().unwrap();
        if !state_lock.initialized {
            let chain = certificate_chain.lock().unwrap();
            state_lock.total_blocks = chain.block_count()? as u64;
            let chain_iter = chain.iter();
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
                        state_lock.map_subject_name_to_uid(
                            subject_name,
                            Uuid::from_bytes(block.block_header.block_uid)
                                .hyphenated()
                                .to_string(),
                        );
                    }
                }
            }
            state_lock.mark_initialized();
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
                let cert_chain = Arc::clone(&certificate_chain);
                let priv_chain = Arc::clone(&private_chain);
                let state_clone = Arc::clone(&state);
                if let Err(e) = handle_client(stream, cert_chain, priv_chain, state_clone) {
                    eprintln!("Error handling client: {}", e);
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
fn handle_client(
    mut stream: UnixStream,
    certificate_chain: Arc<Mutex<BlockChain>>,
    private_chain: Arc<Mutex<BlockChain>>,
    chain_state: Arc<Mutex<State>>,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    // Read JSON request from client
    reader.read_line(&mut line)?;

    // Parse JSON request
    let request: Request =
        serde_json::from_str(&line.trim()).context("Failed to parse JSON request")?;

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
            &certificate_chain,
            &private_chain,
            &chain_state,
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
            &certificate_chain,
            &private_chain,
            &chain_state,
        ),
        Request::ListCertificates => handle_list_certificates(&certificate_chain),
        Request::PKIStatus => handle_pki_status(&certificate_chain, &private_chain, &chain_state),
    };

    // Send response back to client
    let response_json = serde_json::to_string(&response)?;
    stream.write_all(response_json.as_bytes())?;
    stream.write_all(b"\n")?;
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
    _certificate_chain: &Arc<Mutex<BlockChain>>,
    _private_chain: &Arc<Mutex<BlockChain>>,
    chain_state: &Arc<Mutex<State>>,
) -> Response {
    use crate::generate_intermediate_ca::RsaIntermediateCABuilder;
    let (root_key, root_cert) = match (|| -> Result<(PKey<Private>, X509)> {
        _certificate_chain
            .lock()
            .unwrap()
            .get_block_by_height(0)
            .and_then(|block| {
                let cert = openssl::x509::X509::from_pem(&block.block_data)
                    .context("Failed to parse Root CA certificate from blockchain")?;
                let key = _private_chain
                    .lock()
                    .unwrap()
                    .get_block_by_height(0)
                    .and_then(|key_block| {
                        openssl::pkey::PKey::private_key_from_der(&key_block.block_data)
                            .context("Failed to parse Root CA private key from blockchain")
                    })?;
                Ok((key, cert))
            })
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
    if let Err(e) = (|| -> Result<()> {
        let cert_pem = certificate
            .to_pem()
            .context("Failed to convert certificate to PEM")?;
        _certificate_chain
            .lock()
            .unwrap()
            .put_block(cert_pem)
            .context("Failed to store certificate in blockchain")?;
        Ok(())
    })() {
        return Response::Error {
            message: format!("Failed to store certificate: {}", e),
        };
    }

    // Store private key in blockchain
    if let Err(e) = (|| -> Result<()> {
        let key_der = private_key
            .private_key_to_der()
            .context("Failed to convert key to DER")?;
        _private_chain
            .lock()
            .unwrap()
            .put_block(key_der)
            .context("Failed to store private key in blockchain")?;
        Ok(())
    })() {
        return Response::Error {
            message: format!("Failed to store private key: {}", e),
        };
    }
    {
        let mut state_lock = chain_state.lock().unwrap();
        state_lock.map_subject_name_to_uid(
            subject_common_name.clone(),
            Uuid::new_v4().hyphenated().to_string(),
        );
        state_lock.increment_block_count();
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
    _certificate_chain: &Arc<Mutex<BlockChain>>,
    _private_chain: &Arc<Mutex<BlockChain>>,
    chain_state: &Arc<Mutex<State>>,
) -> Response {
    let (intermediate_key, intermediate_cert) = match (|| -> Result<(PKey<Private>, X509)> {
        let intermediate_uid = {
            match chain_state
                .lock()
                .unwrap()
                .subject_name_to_height
                .get(&issuer_common_name)
            {
                Some(uid_hex) => {
                    let uuid = Uuid::parse_str(uid_hex)
                        .context("Failed to parse intermediate UID from state")?;
                    *uuid.as_bytes()
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Issuer common name not found in state: {}",
                        issuer_common_name
                    ));
                }
            }
        };

        let block = _certificate_chain
            .lock()
            .unwrap()
            .get_block_by_uuid(&intermediate_uid)?
            .ok_or_else(|| anyhow::anyhow!("Intermediate certificate not found in blockchain"))?;

        let cert = openssl::x509::X509::from_pem(&block.block_data)
            .context("Failed to parse intermediate certificate from blockchain")?;

        let key_block = _private_chain
            .lock()
            .unwrap()
            .get_block_by_uuid(&intermediate_uid)?
            .ok_or_else(|| anyhow::anyhow!("Intermediate private key not found in blockchain"))?;

        let key = openssl::pkey::PKey::private_key_from_der(&key_block.block_data)
            .context("Failed to parse intermediate private key from blockchain")?;

        Ok((key, cert))
    })() {
        Ok(result) => result,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to retrieve Root CA from blockchain: {}", e),
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
    // Store certificate in blockchain
    if let Err(e) = (|| -> Result<()> {
        let cert_pem = certificate
            .to_pem()
            .context("Failed to convert certificate to PEM")?;
        _certificate_chain
            .lock()
            .unwrap()
            .put_block(cert_pem)
            .context("Failed to store certificate in blockchain")?;
        Ok(())
    })() {
        return Response::Error {
            message: format!("Failed to store certificate: {}", e),
        };
    }

    // Store private key in blockchain
    if let Err(e) = (|| -> Result<()> {
        let key_der = private_key
            .private_key_to_der()
            .context("Failed to convert key to DER")?;
        _private_chain
            .lock()
            .unwrap()
            .put_block(key_der)
            .context("Failed to store private key in blockchain")?;
        Ok(())
    })() {
        return Response::Error {
            message: format!("Failed to store private key: {}", e),
        };
    }
    {
        let mut state_lock = chain_state.lock().unwrap();
        state_lock.map_subject_name_to_uid(
            subject_common_name.clone(),
            Uuid::new_v4().hyphenated().to_string(),
        );
        state_lock.increment_block_count();
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
fn handle_list_certificates(_certificate_chain: &Arc<Mutex<BlockChain>>) -> Response {
    // TODO: Implement certificate listing from blockchain
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
            let chain = _certificate_chain.lock().unwrap();
            let chain_iter = chain.iter();
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
                            let is_ca = cert.pathlen().is_some();

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
fn handle_pki_status(
    _certificate_chain: &Arc<Mutex<BlockChain>>,
    _private_chain: &Arc<Mutex<BlockChain>>,
    _chain_staate: &Arc<Mutex<State>>,
) -> Response {
    match _certificate_chain.lock().unwrap().validate() {
        Ok(_) => {}
        Err(e) => {
            return Response::Error {
                message: format!("Certificate chain validation failed: {}", e),
            };
        }
    }
    match _private_chain.lock().unwrap().validate() {
        Ok(_) => {}
        Err(e) => {
            return Response::Error {
                message: format!("Private key chain validation failed: {}", e),
            };
        }
    }
    Response::Success {
        message: "PKI system operational".to_string(),
        data: Some(serde_json::json!({
            "status": "running",
            "blockchain_initialized": _chain_staate.lock().unwrap().initialized,
            "total_blocks": _chain_staate.lock().unwrap().total_blocks,
            "tracked_subjects": _chain_staate.lock().unwrap().subject_name_to_height.len(),
            "certificate_chain_valid": true,
            "private_key_chain_valid": true,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_deserialization() {
        let json = r#"{"type":"CreateIntermediate","common_name":"Test CA","organization":"Test Org","organizational_unit":"IT","country":"US"}"#;
        let request: Request = serde_json::from_str(json).unwrap();
        match request {
            Request::CreateIntermediate {
                subject_common_name,
                ..
            } => {
                assert_eq!(subject_common_name, "Test CA");
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let response = Response::Success {
            message: "Test".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Success"));
    }
}
