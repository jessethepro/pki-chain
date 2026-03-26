use std::io::{Read, Write};

use crate::pki_generator::{self, CertificateData};

struct CAClientRequest {
    from_socket: std::os::unix::net::UnixStream,
    clent_ca_serial: openssl::bn::BigNum,
    request_type: String,
    request_string: String,
}

struct AdminLoginRequest {
    from_socket: std::os::unix::net::UnixStream,
    user_certificate: openssl::x509::X509,
    request_signature: Vec<u8>,
}

enum RequestType {
    GetCACertificate,
    CheckCRL,
    LoginAdmin,
}

const PROTOCOL_VERSION1: u32 = 1;

fn serialize_response(response_json: &serde_json::Value) -> (Vec<u8>, u32) {
    let response_str = serde_json::to_string(response_json).unwrap_or_else(|e| {
        tracing::error!(error = %e, "Failed to serialize response JSON, using empty response");
        "{}".to_string()
    });
    let mut response_data = Vec::new();
    response_data.extend_from_slice(&PROTOCOL_VERSION1.to_le_bytes());
    response_data.extend_from_slice(&(response_str.len() as u32).to_le_bytes());
    response_data.extend_from_slice(response_str.as_bytes());
    (response_data, response_str.len() as u32)
}

/*
* The JSON format for the response is:
{
    "status": "success" | "error",
    "message": "Detailed message about the result of the request",
    "data": {
        // Optional field containing additional data relevant to the request
    }
}
*/
fn send_response(
    mut response_socket: std::os::unix::net::UnixStream,
    response_json: &serde_json::Value,
) {
    let (response_data, _) = serialize_response(response_json);
    if let Err(e) = response_socket.write_all(&response_data) {
        tracing::error!(socket = ?response_socket, error = %e, "Failed to send response");
    }
}

fn recv_request(mut stream: std::os::unix::net::UnixStream, app_config: crate::configs::AppConfig) {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut version_buffer) {
        tracing::error!(error = %e, "Failed to read protocol version");
        return;
    }
    if let Err(e) = stream.read_exact(&mut length_buffer) {
        tracing::error!(error = %e, "Failed to read payload length");
        return;
    }
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "Payload length exceeds maximum allowed size"
        );
        return;
    }
    let mut payload_buffer = vec![0u8; payload_length];
    if let Err(e) = stream.read_exact(&mut payload_buffer) {
        tracing::error!(error = %e, "Failed to read payload data");
        return;
    }

    let request_json: serde_json::Value = match serde_json::from_slice(&payload_buffer) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse request JSON");
            return;
        }
    };
    let response_socket_str = match request_json.get("response_socket").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            tracing::error!("Request missing required field: response_socket");
            return;
        }
    };
    let response_socket = match std::os::unix::net::UnixStream::connect(response_socket_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(socket = response_socket_str, error = %e, "Failed to connect to response socket");
            return;
        }
    };
    let request_type = match request_json.get("request_type").and_then(|v| v.as_str()) {
        Some(rt) => rt,
        None => {
            tracing::error!("Request missing required field: request_type");
            send_response(
                response_socket,
                &serde_json::json!({
                    "status": "error",
                    "message": "Request missing required field: request_type",
                    "data": request_json,
                }),
            );
            return;
        }
    };
    match request_type {
        "GetCACertificate" => {
            // Handle GetCACertificate request
        }
        "CheckCRL" => {
            // Handle CheckCRL request
        }
        "LoginAdmin" => {
            // Handle LoginAdmin request
        }
        "GetState" => {
            let storage_state = match crate::storage::get_storage_state(&app_config) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to get Storage state");
                    send_response(
                        response_socket,
                        &serde_json::json!({
                            "status": "error",
                            "message": "Failed to get Storage state",
                        }),
                    );
                    return;
                }
            };
            match storage_state {
                crate::storage::StorageState::NotFound | crate::storage::StorageState::Empty => {
                    send_response(
                        response_socket,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Storage not found. Please initialize the storage or check the configuration.",
                            "data": {
                                "state": "NotFound",
                                "cert_path": app_config.blockchains.certificate_path.to_str().unwrap_or("N/A"),
                                "key_path": app_config.blockchains.private_key_path.to_str().unwrap_or("N/A"),
                                "crl_path": app_config.blockchains.crl_path.to_str().unwrap_or("N/A"),
                                "Root CA Defaults": {
                                    "common_name": app_config.root_ca_defaults.root_ca_common_name,
                                    "organization": app_config.root_ca_defaults.root_ca_organization,
                                    "organizational_unit": app_config.root_ca_defaults.root_ca_organizational_unit,
                                    "locality": app_config.root_ca_defaults.root_ca_locality,
                                    "state": app_config.root_ca_defaults.root_ca_state,
                                    "country": app_config.root_ca_defaults.root_ca_country,
                                    "validity_days": app_config.root_ca_defaults.root_ca_validity_days,
                                }
                            },
                        }),
                    );
                }
                crate::storage::StorageState::Created => {
                    send_response(
                        response_socket,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Storage created but not initialized. Please initialize the storage.",
                            "data": {
                                "cert_path": app_config.blockchains.certificate_path.to_str().unwrap_or("N/A"),
                                "state": "Created",
                                "key_path": app_config.blockchains.private_key_path.to_str().unwrap_or("N/A"),
                                "crl_path": app_config.blockchains.crl_path.to_str().unwrap_or("N/A"),
                                "Root CA Defaults": {
                                    "common_name": app_config.root_ca_defaults.root_ca_common_name,
                                    "organization": app_config.root_ca_defaults.root_ca_organization,
                                    "organizational_unit": app_config.root_ca_defaults.root_ca_organizational_unit,
                                    "locality": app_config.root_ca_defaults.root_ca_locality,
                                    "state": app_config.root_ca_defaults.root_ca_state,
                                    "country": app_config.root_ca_defaults.root_ca_country,
                                    "validity_days": app_config.root_ca_defaults.root_ca_validity_days,
                                }
                            },
                        }),
                    );
                }
                crate::storage::StorageState::Initialized => {
                    send_response(
                        response_socket,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Storage initialized. Please create the first admin user certificate and private key.",
                            "data": {
                                "state": "Initialized",
                                "cert_path": app_config.blockchains.certificate_path.to_str().unwrap_or("N/A"),
                                "key_path": app_config.blockchains.private_key_path.to_str().unwrap_or("N/A"),
                                "crl_path": app_config.blockchains.crl_path.to_str().unwrap_or("N/A"),
                                "Root CA Defaults": {
                                    "common_name": app_config.root_ca_defaults.root_ca_common_name,
                                    "organization": app_config.root_ca_defaults.root_ca_organization,
                                    "organizational_unit": app_config.root_ca_defaults.root_ca_organizational_unit,
                                    "locality": app_config.root_ca_defaults.root_ca_locality,
                                    "state": app_config.root_ca_defaults.root_ca_state,
                                    "country": app_config.root_ca_defaults.root_ca_country,
                                    "validity_days": app_config.root_ca_defaults.root_ca_validity_days,
                                }
                            },
                        }),
                    );
                }
                crate::storage::StorageState::Ready => {
                    send_response(
                        response_socket,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Storage is ready. All operations are available.",
                            "data": {
                                "state": "Ready"
                            }
                        }),
                    );
                }
                crate::storage::StorageState::Inconsistent => {
                    send_response(
                        response_socket,
                        &serde_json::json!({
                            "status": "error",
                            "message": "Storage is in an inconsistent state. Please check the storage files and configuration.",
                            "data": {
                                "state": "Inconsistent"
                            }
                        }),
                    );
                }
            }
        }
        _ => {}
    }
}

pub fn start_comm_server(app_config: crate::configs::AppConfig) {
    let _ = std::fs::remove_file(&app_config.server.comm_sock); // Remove existing socket file if it exists
    let listener = std::os::unix::net::UnixListener::bind(&app_config.server.comm_sock)
        .expect("Failed to bind to socket");
    println!(
        "Communication server started at {}",
        app_config.server.comm_sock.to_str().unwrap_or("N/A")
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let app_config = app_config.clone();
                std::thread::spawn(move || {
                    recv_request(stream, app_config.clone());
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

fn handle_setup_request(
    mut stream: std::os::unix::net::UnixStream,
    storage: &crate::storage::Storage<crate::storage::Initialized>,
) {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    match stream
        .read_exact(&mut version_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read version"))
    {
        Ok(_) => {}
        Err(_) => return,
    }
    match stream
        .read_exact(&mut length_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload length"))
    {
        Ok(_) => {}
        Err(_) => return,
    }
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "Payload length exceeds maximum allowed size"
        );
        return;
    }
    let mut payload_buffer = vec![0u8; payload_length];
    match stream
        .read_exact(&mut payload_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload data"))
    {
        Ok(_) => {}
        Err(_) => return,
    }
    let request_json: serde_json::Value = match serde_json::from_slice(&payload_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to parse request JSON"))
    {
        Ok(json) => json,
        Err(_) => return,
    };
    let request_type = match request_json.get("request_type").and_then(|v| v.as_str()) {
        Some(rt) => rt,
        None => {
            tracing::error!("Request missing required field: request_type");
            return;
        }
    };
    let response_sock = match request_json.get("response_socket").and_then(|v| v.as_str()) {
        Some(s) => match std::os::unix::net::UnixStream::connect(s).inspect_err(
            |e| tracing::error!(socket = s, error = %e, "Failed to connect to response socket"),
        ) {
            Ok(sock) => sock,
            Err(_) => return,
        },
        None => {
            tracing::error!("Request missing required field: response_socket");
            return;
        }
    };
    match request_type {
        "AddAdmin" => {
            let admin_cert_data = CertificateData {
                subject_common_name: match request_json
                    .pointer("/cert_data/subject_common_name")
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        tracing::error!(
                            "AddAdmin request missing required field: subject_common_name"
                        );
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: subject_common_name",
                            }),
                        );
                        return;
                    }
                },
                issuer_common_name: "Admin Intermediate CA".to_string(),
                organization: match request_json
                    .pointer("/cert_data/organization")
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        tracing::error!("AddAdmin request missing required field: organization");
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: organization",
                            }),
                        );
                        return;
                    }
                },
                organizational_unit: match request_json
                    .pointer("/cert_data/organizational_unit")
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        tracing::error!(
                            "AddAdmin request missing required field: organizational_unit"
                        );
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: organizational_unit",
                            }),
                        );
                        return;
                    }
                },
                locality: match request_json
                    .pointer("/cert_data/locality")
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        tracing::error!("AddAdmin request missing required field: locality");
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: locality",
                            }),
                        );
                        return;
                    }
                },
                state: match request_json
                    .pointer("/cert_data/state")
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        tracing::error!("AddAdmin request missing required field: state");
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: state",
                            }),
                        );
                        return;
                    }
                },
                country: match request_json
                    .pointer("/cert_data/country")
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s.to_string(),
                    None => {
                        tracing::error!("AddAdmin request missing required field: country");
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: country",
                            }),
                        );
                        return;
                    }
                },
                validity_days: match request_json
                    .pointer("/cert_data/validity_days")
                    .and_then(|v| v.as_u64())
                {
                    Some(v) => v as u32,
                    None => {
                        tracing::error!("AddAdmin request missing required field: validity_days");
                        send_response(
                            response_sock,
                            &serde_json::json!({
                                "status": "error",
                                "message": "AddAdmin request missing required field: validity_days",
                            }),
                        );
                        return;
                    }
                },
                cert_type: pki_generator::CertificateDataType::UserCert,
                is_admin: true,
            };
            let (admin_cert, admin_key) = storage.add_admin_user(admin_cert_data);
            let admin_cert_pem = match admin_cert.to_pem() {
                Ok(pem) => pem,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to convert admin certificate to PEM");
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "error",
                            "message": "Failed to convert admin certificate to PEM",
                        }),
                    );
                    return;
                }
            };
            let admin_key_pem = match admin_key.private_key_to_pem_pkcs8() {
                Ok(pem) => pem,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to convert admin private key to PEM");
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "error",
                            "message": "Failed to convert admin private key to PEM",
                        }),
                    );
                    return;
                }
            };
            send_response(
                response_sock,
                &serde_json::json!({
                    "status": "success",
                    "message": "Admin user certificate and private key created successfully",
                    "data": {
                        "certificate": String::from_utf8(admin_cert_pem).unwrap_or_else(|e| {
                            tracing::error!(error = %e, "Failed to convert admin certificate PEM to string");
                            "Failed to convert certificate PEM to string".to_string()
                        }),
                        "private_key": String::from_utf8(admin_key_pem).unwrap_or_else(|e| {
                            tracing::error!(error = %e, "Failed to convert admin private key PEM to string");
                            "Failed to convert private key PEM to string".to_string()
                        }),
                    },
                }),
            );
        }
        _ => {
            tracing::error!(
                "In the Initialized state only AddAdmin request is allowed: {}",
                request_type
            );
        }
    }
}

pub fn start_setup_server(
    app_config: crate::configs::AppConfig,
    storage: &crate::storage::Storage<crate::storage::Initialized>,
) {
    let _ = std::fs::remove_file(&app_config.server.comm_sock);
    let listener = std::os::unix::net::UnixListener::bind(&app_config.server.setup_sock)
        .expect("Failed to bind to setup socket");
    tracing::info!(
        socket = app_config.server.setup_sock.to_str().unwrap_or("N/A"),
        "Setup server started"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_setup_request(stream, storage),
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept connection");
            }
        }
    }
}
