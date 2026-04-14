use base64::Engine;
use std::{
    any,
    f32::consts::E,
    io::{Read, Write},
};

use crate::{
    pki_generator::{self, CertificateData},
    storage::{self, get_api_storage},
};

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
struct ClientRequest {
    version: Option<u32>,
    json_value: Option<serde_json::Value>,
    error_message: Option<String>,
}

fn get_client_request(mut stream: std::os::unix::net::UnixStream) -> ClientRequest {
    let mut client_request = ClientRequest {
        version: None,
        json_value: None,
        error_message: None,
    };
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    match stream.read_exact(&mut version_buffer) {
        Ok(_) => client_request.version = Some(u32::from_le_bytes(version_buffer)),
        Err(e) => {
            tracing::error!(error = %e, "Failed to read protocol version");
            client_request.error_message = Some(format!("Failed to read protocol version: {}", e));
            return client_request;
        }
    }
    match stream.read_exact(&mut length_buffer) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "Failed to read payload length");
            client_request.error_message = Some(format!("Failed to read payload length: {}", e));
            return client_request;
        }
    }
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "Payload length exceeds maximum allowed size"
        );
        client_request.error_message =
            Some("Payload length exceeds maximum allowed size".to_string());
        return client_request;
    }
    let mut payload_buffer = vec![0u8; payload_length];
    match stream.read_exact(&mut payload_buffer) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "Failed to read payload data");
            client_request.error_message = Some(format!("Failed to read payload data: {}", e));
            return client_request;
        }
    }
    match serde_json::from_slice(&payload_buffer) {
        Ok(json) => {
            client_request.json_value = Some(json);
            client_request
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse request JSON");
            client_request.error_message = Some(format!("Failed to parse request JSON: {}", e));
            client_request
        }
    }
}

fn handle_api_request(
    mut stream: std::os::unix::net::UnixStream,
    storage: &crate::storage::Storage<crate::storage_api::API>,
) {
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
            let storage_state = crate::storage::get_state(&storage.app_config, 1);
            send_response(
                response_socket,
                &serde_json::json!({
                    "status": "success",
                    "message": "Storage state retrieved successfully",
                    "data": {
                        "storage_state": serde_json::to_value(&storage_state).unwrap_or(serde_json::Value::Null),
                    },
                }),
            );
        }
        _ => {}
    }
}

fn handle_setup_request(
    mut stream: std::os::unix::net::UnixStream,
    app_config: &crate::configs::AppConfig,
    mut storage_status: crate::storage::StorageStatusResults,
) -> anyhow::Result<crate::storage::StorageStatusResults> {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    match stream
        .read_exact(&mut version_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read version"))
    {
        Ok(_) => {}
        Err(_) => return Err(anyhow::anyhow!("Failed to read version")),
    }
    match stream
        .read_exact(&mut length_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload length"))
    {
        Ok(_) => {}
        Err(_) => return Err(anyhow::anyhow!("Failed to read payload length")),
    }
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "Payload length exceeds maximum allowed size"
        );
        return Err(anyhow::anyhow!(
            "Payload length exceeds maximum allowed size"
        ));
    }
    let mut payload_buffer = vec![0u8; payload_length];
    match stream
        .read_exact(&mut payload_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read payload data"))
    {
        Ok(_) => {}
        Err(_) => return Err(anyhow::anyhow!("Failed to read payload data")),
    }
    let request_json: serde_json::Value = match serde_json::from_slice(&payload_buffer)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to parse request JSON"))
    {
        Ok(json) => json,
        Err(_) => return Err(anyhow::anyhow!("Failed to parse request JSON")),
    };
    let request_type = match request_json.get("request_type").and_then(|v| v.as_str()) {
        Some(rt) => rt,
        None => {
            tracing::error!("Request missing required field: request_type");
            return Err(anyhow::anyhow!(
                "Request missing required field: request_type"
            ));
        }
    };
    let response_sock = match request_json.get("response_socket").and_then(|v| v.as_str()) {
        Some(s) => match std::os::unix::net::UnixStream::connect(s).inspect_err(
            |e| tracing::error!(socket = s, error = %e, "Failed to connect to response socket"),
        ) {
            Ok(sock) => sock,
            Err(_) => return Err(anyhow::anyhow!("Failed to connect to response socket")),
        },
        None => {
            tracing::error!("Request missing required field: response_socket");
            return Err(anyhow::anyhow!(
                "Request missing required field: response_socket"
            ));
        }
    };
    match storage_status.storage_state {
        crate::storage::StorageState::Empty => {
            tracing::info!("Storage state is Empty, proceeding to create and initialize storage");
            match request_type {
                "CreateAndInitialize" => {
                    // Handle CreateAndInitialize request
                    let storage = crate::storage::Storage {
                        state: crate::storage_empty::Empty {},
                        app_config: app_config.clone(),
                    };
                    storage.create_storage().initialize_storage();
                    tracing::info!("Storage created and initialized successfully during setup");
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Storage created and initialized successfully",
                        }),
                    );
                    storage_status.storage_state = crate::storage::StorageState::Initialized;
                    return Ok(storage_status);
                }
                _ => {
                    tracing::error!("Invalid request type for setup server: {}", request_type);
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "error",
                            "message": format!("Invalid request type for setup server: {}", request_type),
                        }),
                    );
                    return Err(anyhow::anyhow!(
                        "Invalid request type for setup server: {}",
                        request_type
                    ));
                }
            }
        }
        crate::storage::StorageState::Created => {
            let storage = match crate::storage::get_created_storage(app_config) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to get created storage");
                    return Err(anyhow::anyhow!("Failed to get created storage: {}", e));
                }
            };
            tracing::info!("Storage state is Created, proceeding to initialize storage");
            let storage = match storage::get_created_storage(&storage.app_config) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to get created storage");
                    return Err(anyhow::anyhow!("Failed to get created storage: {}", e));
                }
            };
            match request_type {
                "Initialize" => {
                    // Handle Initialize request
                    storage.initialize_storage();
                    tracing::info!("Storage initialized successfully during setup");
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Storage initialized successfully",
                        }),
                    );
                    storage_status.storage_state = crate::storage::StorageState::Initialized;
                    return Ok(storage_status);
                }
                _ => {
                    tracing::error!("Invalid request type for setup server: {}", request_type);
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "error",
                            "message": format!("Invalid request type for setup server: {}", request_type),
                        }),
                    );
                    return Err(anyhow::anyhow!(
                        "Invalid request type for setup server: {}",
                        request_type
                    ));
                }
            }
        }
        crate::storage::StorageState::Inconsistent => {
            tracing::error!("Storage state is Inconsistent, setup cannot proceed");
            send_response(
                response_sock,
                &serde_json::json!({
                    "status": "error",
                    "message": "Storage state is Inconsistent, setup cannot proceed",
                }),
            );
            return Err(anyhow::anyhow!(
                "Storage state is Inconsistent, setup cannot proceed"
            ));
        }
        crate::storage::StorageState::Ready => {
            tracing::error!(
                "Setup functions cannot be performed in current storage state: {:?}",
                storage_status.storage_state
            );
            send_response(
                response_sock,
                &serde_json::json!({
                    "status": "error",
                    "message": format!("Setup functions cannot be performed in current storage state: {:?}. Please log in as the admin user to perform admin functions.", storage_status.storage_state)}),
            );
            return Err(anyhow::anyhow!(
                "Cannot add admin user in current storage state"
            ));
        }
        crate::storage::StorageState::Initialized => {
            tracing::info!("Storage state is Initialized, proceeding to add admin user");
            match request_type {
                "AddFirstAdmin" => {
                    // Handle AddFirstAdmin request
                    let admin_cert_data = match pki_generator::parse_certificate_data_from_json(
                        request_json.clone(),
                    ) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to parse certificate data from JSON");
                            return Err(anyhow::anyhow!(
                                "Failed to parse certificate data from JSON: {}",
                                e
                            ));
                        }
                    };
                    let storage = match crate::storage::get_initialized_storage(app_config) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to get initialized storage");
                            return Err(anyhow::anyhow!(
                                "Failed to get initialized storage: {}",
                                e
                            ));
                        }
                    };
                    let (admin_cert, admin_key) = storage.add_admin_user(admin_cert_data);
                    tracing::info!("Admin user added successfully during setup");
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "success",
                            "message": "Admin user added successfully",
                            "data": {
                                "admin_certificate": base64::engine::general_purpose::STANDARD.encode(admin_cert.to_der().unwrap_or_default()),
                                "admin_private_key": base64::engine::general_purpose::STANDARD.encode(admin_key.private_key_to_der().unwrap_or_default()),
                            },
                        }),
                    );
                    storage_status.storage_state = crate::storage::StorageState::Ready;
                    return Ok(storage_status);
                }
                _ => {
                    tracing::error!("Invalid request type for setup server: {}", request_type);
                    send_response(
                        response_sock,
                        &serde_json::json!({
                            "status": "error",
                            "message": format!("Invalid request type for setup server: {}", request_type),
                        }),
                    );
                    return Err(anyhow::anyhow!(
                        "Invalid request type for setup server: {}",
                        request_type
                    ));
                }
            }
        }
    }
}

pub fn start_api_server(
    app_config: &crate::configs::AppConfig,
    storage_status: crate::storage::StorageStatusResults,
) -> crate::storage::StorageStatusResults {
    let _ = std::fs::remove_file(&app_config.server.comm_sock); // Remove existing socket file if it exists
    let listener = std::os::unix::net::UnixListener::bind(&app_config.server.comm_sock)
        .expect("Failed to bind to socket");
    println!(
        "Communication server started at {}",
        app_config.server.comm_sock.to_str().unwrap_or("N/A")
    );
    let storage = match crate::storage::get_ready_storage(app_config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to get ready storage");
            std::process::exit(1);
        }
    };
    let storage = get_api_storage(storage).expect("Failed to get API storage");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_api_request(stream, &storage);
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
    storage_status
}
pub fn start_setup_server(
    app_config: &crate::configs::AppConfig,
    storage_status: crate::storage::StorageStatusResults,
) -> crate::storage::StorageStatusResults {
    let _ = std::fs::remove_file(app_config.server.comm_sock.clone());
    let listener = std::os::unix::net::UnixListener::bind(app_config.server.setup_sock.clone())
        .expect("Failed to bind to setup socket");
    tracing::info!(
        socket = app_config.server.setup_sock.to_str().unwrap_or("N/A"),
        "Setup server started"
    );
    if storage_status.error_message.is_some() {
        tracing::error!(
            error = storage_status
                .error_message
                .as_ref()
                .unwrap_or(&"Unknown error".to_string()),
            "Failed to get storage state during setup"
        );
        return storage_status;
    }
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let storage_status =
                    match handle_setup_request(stream, app_config, storage_status.clone()) {
                        Ok(status) => status,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to handle setup request");
                            continue;
                        }
                    };
                if storage_status.error_message.is_some() {
                    tracing::error!(
                        error = storage_status
                            .error_message
                            .as_ref()
                            .unwrap_or(&"Unknown error".to_string()),
                        "Error occurred during setup request handling"
                    );
                } else {
                    tracing::info!(
                        "Setup request handled successfully, updated storage status: {:?}",
                        storage_status.storage_state
                    );
                    return storage_status;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept connection on setup socket");
            }
        }
    }
    storage_status
}

pub fn start_repair_server(
    app_config: &crate::configs::AppConfig,
    storage_status: crate::storage::StorageStatusResults,
) -> crate::storage::StorageStatusResults {
    // For now, we will just log that the repair server is not implemented and return the same storage status
    tracing::warn!("Repair server is not implemented yet, returning current storage status");
    storage_status
}
