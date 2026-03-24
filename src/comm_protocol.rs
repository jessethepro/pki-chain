use base64::Engine;
use std::io::{Read, Write};

macro_rules! unwrap_or_log {
    ($expr:expr, $msg:literal) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                tracing::error!("{}: {}", $msg, e);
                return Ok(());
            }
        }
    };
}

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
struct RequestPacket {
    version: u32,
    payload_size: u32,
    payload: Vec<u8>,
}

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

fn send_response(
    response_socket_str: &str,
    response_json: &serde_json::Value,
) -> anyhow::Result<()> {
    let (response_data, _) = serialize_response(response_json);
    let mut stream = std::os::unix::net::UnixStream::connect(response_socket_str)
        .inspect_err(|e| tracing::error!(socket = response_socket_str, error = %e, "Failed to connect to response socket"))?;
    stream.write_all(&response_data).inspect_err(
        |e| tracing::error!(socket = response_socket_str, error = %e, "Failed to send response"),
    )?;
    Ok(())
}

fn recv_request(
    mut stream: std::os::unix::net::UnixStream,
    app_config: crate::configs::AppConfig,
) -> anyhow::Result<()> {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    stream
        .read_exact(&mut version_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read protocol version"))?;
    stream
        .read_exact(&mut length_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload length"))?;
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "Payload length exceeds maximum allowed size"
        );
        return Ok(());
    }
    let mut payload_buffer = vec![0u8; payload_length];
    stream
        .read_exact(&mut payload_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload data"))?;
    let request_packet = RequestPacket {
        version: u32::from_le_bytes(version_buffer),
        payload_size: payload_length as u32,
        payload: payload_buffer,
    };
    let request_map: std::collections::HashMap<String, String> =
        serde_json::from_slice(&request_packet.payload)
            .inspect_err(|e| tracing::error!(error = %e, "Failed to parse request JSON"))?;
    if request_map.contains_key("request_type") {
        match request_map["request_type"].as_str() {
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
                match unwrap_or_log!(
                    crate::storage::get_storage_state(&app_config),
                    "Failed to get storage state"
                ) {
                    crate::storage::StorageState::NotFound
                    | crate::storage::StorageState::Empty => {
                        send_response(
                            &request_map["response_socket"],
                            &serde_json::json!({
                                "state": "NotFound",
                                "message": "Storage not found. Please initialize the storage or check the configuration.",
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
                            }),
                        )?;
                    }

                    crate::storage::StorageState::Created => {
                        send_response(
                            &request_map["response_socket"],
                            &serde_json::json!({
                                "state": "Created",
                                "message": "Storage created but not initialized. Please initialize the storage.",
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
                            }),
                        )?;
                    }
                    crate::storage::StorageState::Initialized => {
                        send_response(
                            &request_map["response_socket"],
                            &serde_json::json!({
                                "state": "Initialized",
                                "message": "Storage initialized. Please create the first admin user certificate and private key.",
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
                            }),
                        )?;
                    }
                    crate::storage::StorageState::Ready => {
                        send_response(
                            &request_map["response_socket"],
                            &serde_json::json!({"state": "Ready"}),
                        )?;
                    }
                    crate::storage::StorageState::Inconsistent => {
                        send_response(
                            &request_map["response_socket"],
                            &serde_json::json!({"state": "Inconsistent"}),
                        )?;
                    }
                }
            }
            _ => {
                tracing::error!("Unknown request type: {}", request_map["request_type"]);
            }
        }
    }
    Ok(())
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
                    if let Err(e) = recv_request(stream, app_config.clone()) {
                        tracing::error!(error = %e, "Error handling client request");
                    }
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
) -> anyhow::Result<()> {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    stream
        .read_exact(&mut version_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read version"))?;
    stream
        .read_exact(&mut length_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload length"))?;
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "Payload length exceeds maximum allowed size"
        );
        return Ok(());
    }
    let mut payload_buffer = vec![0u8; payload_length];
    stream
        .read_exact(&mut payload_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload data"))?;
    let request_map: std::collections::HashMap<String, String> =
        serde_json::from_slice(&payload_buffer)
            .inspect_err(|e| tracing::error!(error = %e, "Failed to parse request JSON"))?;

    if !request_map.contains_key("request_type") {
        return Ok(());
    }
    match request_map["request_type"].as_str() {
        "AddAdmin" => {
            let response_socket = &request_map["response_socket"];
            let admin_cert = (|| -> anyhow::Result<openssl::x509::X509> {
                let b64 = request_map
                    .get("admin_cert")
                    .ok_or_else(|| anyhow::anyhow!("Admin certificate not provided"))?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| anyhow::anyhow!("Failed to decode admin certificate: {}", e))?;
                openssl::x509::X509::from_der(&bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to parse admin certificate: {}", e))
            })();
            let admin_key = (|| -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                let b64 = request_map
                    .get("admin_key")
                    .ok_or_else(|| anyhow::anyhow!("Admin private key not provided"))?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| anyhow::anyhow!("Failed to decode admin private key: {}", e))?;
                openssl::pkey::PKey::private_key_from_der(&bytes)
                    .map_err(|e| anyhow::anyhow!("Failed to parse admin private key: {}", e))
            })();
            match (admin_cert, admin_key) {
                (Ok(cert), Ok(key)) => match storage.add_admin(&cert, &key) {
                    Ok(_) => {
                        tracing::info!("Admin user added successfully");
                        send_response(
                            response_socket,
                            &serde_json::json!({"status": "success", "message": "Admin user added successfully"}),
                        )
                        .inspect_err(|e| tracing::error!(error = %e, "Failed to send response"))
                        .ok();
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to add admin user");
                        send_response(
                            response_socket,
                            &serde_json::json!({"status": "error", "message": format!("Failed to add admin user: {}", e)}),
                        )
                        .inspect_err(|e| tracing::error!(error = %e, "Failed to send response"))
                        .ok();
                    }
                },
                (Err(e), _) | (_, Err(e)) => {
                    tracing::error!(error = %e, "Failed to process admin credentials");
                    send_response(
                        response_socket,
                        &serde_json::json!({"status": "error", "message": format!("Failed to process admin credentials: {}", e)}),
                    )
                    .inspect_err(|e| tracing::error!(error = %e, "Failed to send response"))
                    .ok();
                }
            }
        }
        _ => {
            tracing::error!(
                "In the Initialized state only AddAdmin request is allowed: {}",
                request_map["request_type"]
            );
        }
    }
    Ok(())
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
            Ok(stream) => {
                if let Err(e) = handle_setup_request(stream, storage) {
                    tracing::error!(error = %e, "Error handling setup request");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept connection");
            }
        }
    }
}
