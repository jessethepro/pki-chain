use base64::Engine;
use keyutils::keytypes::user;
use openssl::x509::CertificateIssuer;
use std::{
    f32::consts::E,
    io::{Read, Write},
};

use crate::storage::{self, ValidationResult};

const PROTOCOL_VERSION1: u32 = 1;

fn serialize_response(response_json: &serde_json::Value) -> (Vec<u8>, u32) {
    let response_str = serde_json::to_string(response_json).unwrap_or_else(|e| {
        tracing::error!(error = %e, "serialize_response -> Failed to serialize response JSON, using empty response");
        "{}".to_string()
    });
    let mut response_data = Vec::new();
    response_data.extend_from_slice(&PROTOCOL_VERSION1.to_le_bytes());
    response_data.extend_from_slice(&(response_str.len() as u32).to_le_bytes());
    response_data.extend_from_slice(response_str.as_bytes());
    (response_data, response_str.len() as u32)
}

pub fn recv_request(
    mut request_socket: &std::os::unix::net::UnixStream,
) -> anyhow::Result<serde_json::Value> {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    if let Err(e) = request_socket.read_exact(&mut version_buffer) {
        tracing::error!(error = %e, "recv_request -> Failed to read protocol version");
        return Err(anyhow::anyhow!(
            "recv_request -> Failed to read protocol version"
        ));
    }
    if let Err(e) = request_socket.read_exact(&mut length_buffer) {
        tracing::error!(error = %e, "recv_request -> Failed to read payload length");
        return Err(anyhow::anyhow!(
            "recv_request -> Failed to read payload length"
        ));
    }
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "recv_request -> Payload length exceeds maximum allowed size"
        );
        return Err(anyhow::anyhow!(
            "recv_request -> Payload length exceeds maximum allowed size"
        ));
    }
    let mut payload_buffer = vec![0u8; payload_length];
    if let Err(e) = request_socket.read_exact(&mut payload_buffer) {
        tracing::error!(error = %e, "recv_request -> Failed to read payload data");
        return Err(anyhow::anyhow!(
            "recv_request -> Failed to read payload data"
        ));
    }
    match serde_json::from_slice(&payload_buffer) {
        Ok(json) => Ok(json),
        Err(e) => {
            tracing::error!(error = %e, "recv_request -> Failed to parse request JSON");
            Err(anyhow::anyhow!(
                "recv_request -> Failed to parse request JSON"
            ))
        }
    }
}

/* The response will be a JSON object with the following format:
{
    "response": {
        "request_id": "The unique ID of the request being responded to",
        "status": "success" | "error",
        "message": "Detailed message about the result of the request",
        "storage_state": "The current storage state after handling the request",
        "data": {
            // Optional field containing additional data relevant to the request
            // For AddFirstAdmin request, this will include the admin certificate and private key in base64 format
            "admin_certificate": "Base64-encoded DER format of the admin certificate",
            "admin_private_key": "Base64-encoded DER format of the admin private key",
        }
    }
}
*/
fn send_response(
    mut response_socket: &std::os::unix::net::UnixStream,
    response_json: &serde_json::Value,
) {
    let (response_data, _) = serialize_response(response_json);
    if let Err(e) = response_socket.write_all(&response_data) {
        tracing::error!(socket = ?response_socket, error = %e, "send_response -> Failed to send response");
    }
}

/*
* The format for Public API server request is a JSON object with the following fields:
{
    "request_type": "Public",
    "request": {
        "response_socket": "Path to the Unix socket where the response should be sent",
        "request_action": "ValidateCertificate",
        "requested_certificate": "PEM formatted of the certificate to validate",
        "requester_certificate": "PEM formatted certificate of the requester, used for logging and auditing purposes",
    },
    "request_signature": "Base64-encoded signature of the request JSON (excluding the
        request_signature field) signed by the requester's private key"
}
* The response format for a Public API request will be:
{
    "response": {
        "request_id": "A unique identifier for the request/response pair, will be a UUID",
        "status": "success" | "not_found",
        "message": "Detailed message about the result of the request",
        "requested_certificate": "PEM formatted certificate that was validated (if found)",
        "intermediate_certificate": "PEM formatted intermediate certificate (if applicable)",
        "root_certificate": "PEM formatted root certificate (if applicable)",
    }
}
* The format for a Private API server request is a JSON object with the following fields:
{
    "request_type": "Private",
    "request": {
    [encrypted request data, the exact fields will depend on the specific private API request being made,
    but it will generally include the following common fields:]
        "response_socket": "Path to the Unix socket where the response should be sent",
        "request_action": "GetState",
        "data": {
            // Optional field containing additional data relevant to the request
        },
    },
    "request_signature": "Base64-encoded signature of the request JSON (excluding the
        request_signature field) signed by the requester's private key",
    "requester_certificate_serial": "String representation of the serial number of the requester certificate, used to look up the requester certificate in storage for authentication"
}
* The API server will verify the signature of the request using the public key from the requester certificate
* and verify the signature with the stored certificate in the database to ensure that the requester is authorized
* before processing the request.
* The response will be a JSON object with the following format:
{
    "response": {
        "id": "A unique identifier for the request/response pair, can be a UUID or a timestamp",
        "status": "success" | "error",
        "message": "Detailed message about the result of the request",
        "data": {
            // Optional field containing additional data relevant to the request
            // For GetCACertificate request, this will include the requested certificate in base64 format and its height in the certificate chain
            "requested_certificate": "Base64-encoded DER format of the requested certificate",
            "intermediate_certificate": "Base64-encoded DER format of the intermediate certificate (if applicable)",
            "root_certificate": "Base64-encoded DER format of the root certificate (if applicable)",
        }
    }
}
*/

pub fn start_api_server(
    app_config: &crate::configs::AppConfig,
    storage: &crate::storage::Storage<crate::storage_api::API>,
) {
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
                handle_api_request(&stream, storage);
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

fn handle_public_api_request(
    request_id: String,
    request_json: serde_json::Value,
    storage: &crate::storage::Storage<crate::storage_api::API>,
) {
    // Handle public API request
    let request = match request_json.pointer("/request") {
        Some(r) => r,
        None => {
            tracing::error!("handle_api_request -> Request ID {} -> Request JSON missing required field: request", request_id);
            return;
        }
    };
    let request_signature_base64 = match request_json
        .pointer("/request_signature")
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => {
            tracing::error!("handle_api_request -> Request ID {} -> Request JSON missing required field: request_signature", request_id);
            return;
        }
    };
    let request_signature = match base64::engine::general_purpose::STANDARD
        .decode(request_signature_base64)
    {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to decode request signature from base64", request_id);
            return;
        }
    };
    let request_bytes = match serde_json::to_vec(request) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to serialize request JSON for signature verification", request_id);
            return;
        }
    };
    let requester_certificate_pem = match request_json
        .pointer("/request/requester_certificate")
        .and_then(|v| v.as_str())
    {
        Some(rc) => rc,
        None => {
            tracing::error!("handle_api_request -> Request ID {} -> Request missing required field: requester_certificate", request_id);
            return;
        }
    };
    let requester_certificate = match openssl::x509::X509::from_pem(
        requester_certificate_pem.as_bytes(),
    ) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to parse requester certificate from PEM", request_id);
            return;
        }
    };
    let valid_signature = match requester_certificate.public_key() {
        Ok(public_key) => match crate::encryption::verify_signature(
            &request_bytes,
            &request_signature,
            &public_key,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to verify request signature", request_id);
                return;
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to extract public key from requester certificate", request_id);
            return;
        }
    };
    let response_socket_str = match request_json
        .pointer("/request/response_socket")
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => {
            tracing::error!("handle_api_request -> Request ID {} -> Request missing required field: response_socket", request_id);
            return;
        }
    };
    let response_socket = match std::os::unix::net::UnixStream::connect(response_socket_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(socket = response_socket_str, error = %e, "handle_api_request -> Request ID {} -> Failed to connect to response socket", request_id);
            return;
        }
    };
    if !valid_signature {
        tracing::error!(
            "handle_api_request -> Request ID {} -> Request signature verification failed",
            request_id
        );
        send_response(
            &response_socket,
            &serde_json::json!({
                "response": {
                    "request_id": request_id,
                    "status": "not_found",
                    "message": "Request signature verification failed",
                }
            }),
        );
    }
    let request_action = match request
        .pointer("/request/request_action")
        .and_then(|v| v.as_str())
    {
        Some(ra) => ra,
        None => {
            tracing::error!("handle_api_request -> Request ID {} -> Request missing required field: request_action", request_id);
            send_response(
                &response_socket,
                &serde_json::json!({
                    "response": {
                        "request_id": request_id,
                        "status": "not_found",
                        "message": "Request missing required field: request_action",
                    }
                }),
            );
            return;
        }
    };
    match request_action {
        "ValidateCertificate" => {
            // Handle ValidateCertificate request
            let requested_cert_pem = match request
                .pointer("/request/requested_certificate")
                .and_then(|v| v.as_str())
            {
                Some(rc) => rc,
                None => {
                    tracing::error!("handle_api_request -> Request ID {} -> ValidateCertificate request missing required field: requested_certificate", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "ValidateCertificate request missing required field: requested_certificate",
                            }
                        }),
                    );
                    return;
                }
            };
            let requested_cert = match openssl::x509::X509::from_pem(requested_cert_pem.as_bytes())
            {
                Ok(cert) => cert,
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to parse requested certificate from PEM", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to parse requested certificate from PEM",
                            }
                        }),
                    );
                    return;
                }
            };
            let requested_cert_serial = match requested_cert.serial_number().to_bn() {
                Ok(serial) => serial,
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to convert requested certificate serial number", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to convert requested certificate serial number",
                            }
                        }),
                    );
                    return;
                }
            };
            let (requested_cert, intermediate) = match storage
                .get_certificate_by_serial(requested_cert_serial)
            {
                Ok(Some((cert, intermediate))) => (cert, intermediate),
                Ok(None) => {
                    tracing::warn!("handle_api_request -> Request ID {} -> Requested certificate not found in storage by serial number", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Requested certificate not found in storage by serial number",
                            }
                        }),
                    );
                    return;
                }
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to retrieve requested certificate from storage by serial number", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to retrieve requested certificate from storage by serial number",
                            }
                        }),
                    );
                    return;
                }
            };
            let auth_chain = match openssl::stack::Stack::new() {
                Ok(mut stack) => match stack.push(intermediate.clone()) {
                    Ok(_) => stack,
                    Err(e) => {
                        tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to build auth chain stack", request_id);
                        send_response(
                            &response_socket,
                            &serde_json::json!({
                                "response": {
                                    "request_id": request_id,
                                    "status": "not_found",
                                    "message": "Failed to build auth chain stack",
                                }
                            }),
                        );
                        return;
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to create auth chain stack", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to create auth chain stack",
                            }
                        }),
                    );
                    return;
                }
            };
            let is_valid = match crate::encryption::verify_user_cert(
                &storage.state.auth_store,
                &auth_chain,
                &requested_cert,
            ) {
                Ok(valid) => valid,
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to verify requested certificate against cert chain", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to verify requested certificate against cert chain",
                            }
                        }),
                    );
                    return;
                }
            };
            if !is_valid {
                tracing::error!(
                    "handle_api_request -> Request ID {} -> Requested certificate is not valid",
                    request_id
                );
                send_response(
                    &response_socket,
                    &serde_json::json!({
                        "response": {
                            "request_id": request_id,
                            "status": "not_found",
                            "message": "Requested certificate is not valid",
                        }
                    }),
                );
                return;
            }
            let request_cert_pem = match requested_cert.to_pem() {
                Ok(pem) => String::from_utf8_lossy(&pem).to_string(),
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to convert requested certificate to PEM format", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to convert requested certificate to PEM format",
                            }
                        }),
                    );
                    return;
                }
            };
            let intermediate_cert_pem = match intermediate.to_pem() {
                Ok(pem) => String::from_utf8_lossy(&pem).to_string(),
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to convert intermediate certificate to PEM format", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to convert intermediate certificate to PEM format",
                            }
                        }),
                    );
                    return;
                }
            };
            let root_cert = match crate::storage::get_root_certificate(
                &storage.state.certificate_chain,
                &storage.state.app_private_key,
            ) {
                Ok(cert) => cert,
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to retrieve root certificate", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to retrieve root certificate",
                            }
                        }),
                    );
                    return;
                }
            };
            let root_cert_pem = match root_cert.to_pem() {
                Ok(pem) => String::from_utf8_lossy(&pem).to_string(),
                Err(e) => {
                    tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to convert root certificate to PEM format", request_id);
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "response": {
                                "request_id": request_id,
                                "status": "not_found",
                                "message": "Failed to convert root certificate to PEM format",
                            }
                        }),
                    );
                    return;
                }
            };
            send_response(
                &response_socket,
                &serde_json::json!({
                    "response": {
                        "request_id": request_id,
                        "status": "success",
                        "message": "Certificate validated successfully",
                        "requested_certificate": request_cert_pem,
                        "intermediate_certificate": intermediate_cert_pem,
                        "root_certificate": root_cert_pem,
                    }
                }),
            );
        }
        _ => {
            tracing::error!(
                "handle_api_request -> Request ID {} -> Unknown request action: {}",
                request_id,
                request_action
            );
            send_response(
                &response_socket,
                &serde_json::json!({
                    "response": {
                        "request_id": request_id,
                        "status": "not_found",
                        "message": format!("Unknown request action: {}", request_action),
                    }
                }),
            );
        }
    }
}

fn handle_api_request(
    stream: &std::os::unix::net::UnixStream,
    storage: &crate::storage::Storage<crate::storage_api::API>,
) {
    let request_id = uuid::Uuid::new_v4().to_string();
    let request_json = match recv_request(stream) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!(error = %e, "handle_api_request -> Request ID {} -> Failed to receive or parse request", request_id);
            return;
        }
    };
    let request_type = match request_json
        .pointer("/request_type")
        .and_then(|v| v.as_str())
    {
        Some(rt) => rt,
        None => {
            tracing::error!("handle_api_request -> Request ID {} -> Request JSON missing required field: request_type", request_id);
            return;
        }
    };
    match request_type {
        "Public" => handle_public_api_request(request_id, request_json, storage),
        //"Private" => handle_private_api_request(request_id, request_json, storage),
        _ => {
            tracing::error!(
                "handle_api_request -> Request ID {} -> Unknown request type: {}",
                request_id,
                request_type
            );
            return;
        }
    }
}

fn handle_setup_request(
    mut stream: &std::os::unix::net::UnixStream,
    app_config: &crate::configs::AppConfig,
    mut storage_status: crate::storage::StorageStatusResults,
) -> anyhow::Result<crate::storage::StorageStatusResults> {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    let request_id = uuid::Uuid::new_v4().to_string();
    match stream.read_exact(&mut version_buffer).inspect_err(
        |e| tracing::error!(error = %e, "handle_setup_request -> Failed to read version"),
    ) {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Failed to read version. Request ID: {}",
                request_id
            ))
        }
    }
    match stream.read_exact(&mut length_buffer).inspect_err(
        |e| tracing::error!(error = %e, "handle_setup_request -> Failed to read payload length. Request ID: {}", request_id),
    ) {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Failed to read payload length. Request ID: {}", request_id
            ))
        }
    }
    let payload_length = u32::from_le_bytes(length_buffer) as usize;
    if payload_length > 10 * 1024 * 1024 {
        tracing::error!(
            payload_length,
            "handle_setup_request -> Payload length exceeds maximum allowed size. Request ID: {}",
            request_id
        );
        return Err(anyhow::anyhow!(
            "handle_setup_request -> Payload length exceeds maximum allowed size. Request ID: {}",
            request_id
        ));
    }
    let mut payload_buffer = vec![0u8; payload_length];
    match stream.read_exact(&mut payload_buffer).inspect_err(
        |e| tracing::error!(error = %e, "handle_setup_request -> Failed to read payload data. Request ID: {}", request_id),
    ) {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Failed to read payload data. Request ID: {}", request_id
            ))
        }
    }
    let request_json: serde_json::Value = match serde_json::from_slice(&payload_buffer).inspect_err(
        |e| tracing::error!(error = %e, "handle_setup_request -> Failed to parse request JSON. Request ID: {}", request_id),
    ) {
        Ok(json) => {
            tracing::info!(
                "handle_setup_request -> Received request JSON: {}. Request ID: {}",
                json,
                request_id
            );
            json
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Failed to parse request JSON. Request ID: {}", request_id
            ))
        }
    };
    let request_type = match request_json
        .pointer("/request/request_type")
        .and_then(|v| v.as_str())
    {
        Some(rt) => rt,
        None => {
            tracing::error!("handle_setup_request -> Request missing required field: request_type. Request ID: {}", request_id);
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Request missing required field: request_type. Request ID: {}", request_id
            ));
        }
    };
    let response_sock = match request_json.pointer("/request/response_socket").and_then(|v| v.as_str()) {
        Some(s) => match std::os::unix::net::UnixStream::connect(s).inspect_err(
            |e| tracing::error!(socket = s, error = %e, "handle_setup_request -> Failed to connect to response socket. Request ID: {}", request_id),
        ) {
            Ok(sock) => sock,
            Err(_) => return Err(anyhow::anyhow!("handle_setup_request -> Failed to connect to response socket. Request ID: {}", request_id)),
        },
        None => {
            tracing::error!("handle_setup_request -> Request missing required field: response_socket. Request ID: {}", request_id);
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Request missing required field: response_socket. Request ID: {}", request_id
            ));
        }
    };
    match request_type {
        "GetState" => {
            tracing::info!(
                "handle_setup_request -> Received request type: {}, current storage state: {:?}",
                request_type,
                storage_status.storage_state
            );
            send_response(
                &response_sock,
                &serde_json::json!({
                    "response": {
                        "request_id": request_id,
                        "status": "success",
                        "message": "handle_setup_request -> Storage state retrieved successfully",
                        "data": {
                            "storage_status": serde_json::to_value(&storage_status).unwrap_or(serde_json::Value::Null),
                        },
                    }
                }),
            );
            return Ok(storage_status);
        }
        "CreateAndInitialize" => {
            tracing::info!(
                "handle_setup_request -> Received request type: {}, current storage state: {:?}",
                request_type,
                storage_status.storage_state
            );
            match storage_status.storage_state {
                crate::storage::StorageState::Empty => {
                    tracing::info!("handle_setup_request -> Storage state is Empty, proceeding to create and initialize storage");
                    let new_storage: bool = match request_json
                        .pointer("/request/create_new_storage")
                        .and_then(|v| v.as_bool())
                    {
                        Some(b) => b,
                        None => {
                            tracing::error!("handle_setup_request -> CreateAndInitialize request missing required field: create_new_storage");
                            send_response(
                                &response_sock,
                                &serde_json::json!({
                                    "response": {
                                        "status": "error",
                                        "message": format!("CreateAndInitialize request missing required field: create_new_storage. Request ID: {}", request_id),
                                        "data": request_json,
                                    }
                                }),
                            );
                            return Err(anyhow::anyhow!(
                                "handle_setup_request -> CreateAndInitialize request missing required field: create_new_storage. Request ID: {}",
                                request_id
                            ));
                        }
                    };
                    if new_storage {
                        let mut new_admin_data =
                            match crate::pki_generator::parse_certificate_data_from_json(
                                &request_json,
                                &request_id,
                            ) {
                                Ok(data) => data,
                                Err(e) => {
                                    tracing::error!(error = %e, "handle_setup_request -> Failed to parse admin certificate data from request");
                                    send_response(
                                        &response_sock,
                                        &serde_json::json!({
                                            "response": {
                                                "status": "error",
                                                "message": format!("Failed to parse admin certificate data from request: {}. Request ID: {}", e, request_id),
                                                "data": request_json,
                                            }
                                        }),
                                    );
                                    return Err(anyhow::anyhow!(
                                    "handle_setup_request -> Failed to parse admin certificate data from request: {}. Request ID: {}",
                                    e,
                                    request_id
                                ));
                                }
                            };
                        if new_admin_data.issuer_common_name == "None" {
                            tracing::info!("handle_setup_request -> Admin certificate data missing issuer common name, using default from app config");
                            new_admin_data.issuer_common_name =
                                app_config.admin_ca_defaults.admin_ca_common_name.clone();
                            tracing::info!("handle_setup_request -> Admin certificate data after filling missing issuer common name: {:?}", new_admin_data);
                        }
                        let storage_empty = crate::storage::get_empty_storage(app_config);
                        let (admin_cert, admin_key) = storage_empty
                            .create_storage()
                            .initialize_storage()
                            .add_admin_user(new_admin_data);
                        send_response(
                            &response_sock,
                            &serde_json::json!({
                                "response": {
                                    "status": "success",
                                    "message": "Storage created and initialized successfully, admin user added",
                                    "data": {
                                        "admin_certificate": base64::engine::general_purpose::STANDARD.encode(admin_cert.to_der().unwrap_or_default()),
                                        "admin_private_key": base64::engine::general_purpose::STANDARD.encode(admin_key.private_key_to_der().unwrap_or_default()),
                                    },
                                }
                            }),
                        );
                        storage_status.storage_state = crate::storage::StorageState::Ready;
                        return Ok(storage_status);
                    } else {
                        tracing::info!("handle_setup_request -> CreateAndInitialize request indicated not to create new storage, sending success response with current storage state. Request ID: {}", request_id);
                        send_response(
                            &response_sock,
                            &serde_json::json!({
                                "response": {
                                    "status": "success",
                                    "message": "CreateAndInitialize request indicated not to create new storage, returning current storage state",
                                    "data": {
                                        "storage_state": serde_json::to_value(&storage_status).unwrap_or(serde_json::Value::Null),
                                    },
                                }
                            }),
                        );
                        return Ok(storage_status);
                    }
                }
                _ => {
                    tracing::warn!("handle_setup_request -> Received CreateAndInitialize request but storage state is not Empty, current storage state: {:?}, ignoring request. Request ID: {}", storage_status.storage_state, request_id);
                    send_response(
                        &response_sock,
                        &serde_json::json!({
                            "response": {
                                "status": "error",
                                "message": format!("Received CreateAndInitialize request but storage state is not Empty, current storage state: {:?}. Request ID: {}", storage_status.storage_state, request_id),
                                "data": request_json,
                            }
                        }),
                    );
                    return Err(anyhow::anyhow!(
                        "handle_setup_request -> Received CreateAndInitialize request but storage state is not Empty, current storage state: {:?}. Request ID: {}",
                        storage_status.storage_state,
                        request_id
                    ));
                }
            }
        }
        "Initialize" => {
            // Handle Initialize request
            match storage_status.storage_state {
                crate::storage::StorageState::Created => {
                    tracing::info!("handle_setup_request -> Storage state is Created, proceeding to initialize storage");
                    let storage_created = match crate::storage::get_created_storage(app_config) {
                        Ok(storage) => storage,
                        Err(e) => {
                            tracing::error!(error = %e, "handle_setup_request -> Failed to get created storage");
                            send_response(
                                &response_sock,
                                &serde_json::json!({
                                    "response": {
                                        "status": "error",
                                        "message": format!("Failed to get created storage: {}. Request ID: {}", e, request_id),
                                        "data": request_json,
                                        "request_id": request_id,
                                    }
                                }),
                            );
                            return Err(anyhow::anyhow!(
                                "handle_setup_request -> Failed to get created storage: {}",
                                e
                            ));
                        }
                    };
                    let new_admin_data = match parse_admin_cert_data(&request_json, app_config) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!(error = %e, "handle_setup_request -> Failed to parse admin certificate data from request");
                            send_response(
                                &response_sock,
                                &serde_json::json!({
                                    "response": {
                                        "status": "error",
                                        "message": format!("Failed to parse admin certificate data from request: {}. Request ID: {}", e, request_id),
                                        "data": request_json,
                                        "request_id": request_id,
                                    }
                                }),
                            );
                            return Err(anyhow::anyhow!(
                                "handle_setup_request -> Failed to parse admin certificate data from request: {}. Request ID: {}",
                                e,
                                request_id
                            ));
                        }
                    };
                    let (admin_cert, admin_key) = storage_created
                        .initialize_storage()
                        .add_admin_user(new_admin_data);
                    send_response(
                        &response_sock,
                        &serde_json::json!({
                            "response": {
                                "status": "success",
                                "message": "Storage initialized successfully, admin user added",
                                "data": {
                                    "admin_certificate": base64::engine::general_purpose::STANDARD.encode(admin_cert.to_der().unwrap_or_default()),
                                    "admin_private_key": base64::engine::general_purpose::STANDARD.encode(admin_key.private_key_to_der().unwrap_or_default()),
                                },
                                "request_id": request_id,
                            }
                        }),
                    );
                    storage_status.storage_state = crate::storage::StorageState::Ready;
                    return Ok(storage_status);
                }
                _ => {
                    tracing::warn!("handle_setup_request -> Received Initialize request but storage state is not Created, current storage state: {:?}. Request ID: {}, ignoring request", storage_status.storage_state, request_id);
                    send_response(
                        &response_sock,
                        &serde_json::json!({
                            "response": {
                                "status": "error",
                                "message": format!("Received Initialize request but storage state is not Created, current storage state: {:?}. Request ID: {}", storage_status.storage_state, request_id),
                                "data": request_json,
                                "request_id": request_id,
                            }
                        }),
                    );
                    return Err(anyhow::anyhow!(
                        "handle_setup_request -> Received Initialize request but storage state is not Created, current storage state: {:?}. Request ID: {}",
                        storage_status.storage_state,
                        request_id
                    ));
                }
            }
        }
        "AddFirstAdmin" => {
            // Handle AddFirstAdmin request
            match storage_status.storage_state {
                crate::storage::StorageState::Initialized => {
                    tracing::info!("handle_setup_request -> Storage state is Initialized, proceeding to add first admin user. Request ID: {}", request_id);
                    let storage_initialized = match crate::storage::get_initialized_storage(
                        app_config,
                    ) {
                        Ok(storage) => storage,
                        Err(e) => {
                            tracing::error!(error = %e, "handle_setup_request -> Failed to get initialized storage. Request ID: {}", request_id);
                            send_response(
                                &response_sock,
                                &serde_json::json!({
                                    "response": {
                                        "status": "error",
                                        "message": format!("Failed to get initialized storage: {}, request_id: {}", e, request_id),
                                        "data": request_json,
                                        "request_id": request_id,
                                    }
                                }),
                            );
                            return Err(anyhow::anyhow!(
                                "handle_setup_request -> Failed to get initialized storage: {}, request_id: {}",
                                e,
                                request_id
                            ));
                        }
                    };
                    let new_admin_data = match parse_admin_cert_data(&request_json, app_config) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::error!(error = %e, "handle_setup_request -> Failed to parse admin certificate data from request. request_id: {}", request_id);
                            send_response(
                                &response_sock,
                                &serde_json::json!({
                                    "response": {
                                        "status": "error",
                                        "message": format!("Failed to parse admin certificate data from request: {}", e),
                                        "data": request_json,
                                        "request_id": request_id,
                                    }
                                }),
                            );
                            return Err(anyhow::anyhow!(
                                "handle_setup_request -> Failed to parse admin certificate data from request: {}, request_id: {}",
                                e,
                                request_id
                            ));
                        }
                    };
                    let (admin_cert, admin_key) =
                        storage_initialized.add_admin_user(new_admin_data);
                    send_response(
                        &response_sock,
                        &serde_json::json!({
                            "response": {
                                "status": "success",
                                "message": "Admin user added successfully",
                                "data": {
                                    "admin_certificate": base64::engine::general_purpose::STANDARD.encode(admin_cert.to_der().unwrap_or_default()),
                                    "admin_private_key": base64::engine::general_purpose::STANDARD.encode(admin_key.private_key_to_der().unwrap_or_default()),
                                },
                                "request_id": request_id,
                            }
                        }),
                    );
                    storage_status.storage_state = crate::storage::StorageState::Ready;
                    return Ok(storage_status);
                }
                _ => {
                    tracing::warn!("handle_setup_request -> Received AddFirstAdmin request but storage state is not Initialized, current storage state: {:?}, ignoring request", storage_status.storage_state);
                    send_response(
                        &response_sock,
                        &serde_json::json!({
                            "response": {
                                "status": "error",
                                "message": format!("Received AddFirstAdmin request but storage state is not Initialized, current storage state: {:?}", storage_status.storage_state),
                                "data": request_json,
                                "request_id": request_id,
                            }
                        }),
                    );
                    return Err(anyhow::anyhow!(
                        "handle_setup_request -> Received AddFirstAdmin request but storage state is not Initialized, current storage state: {:?}, request_id: {}",
                        storage_status.storage_state,
                        request_id
                    ));
                }
            }
        }
        _ => {
            tracing::error!(
                "handle_setup_request -> Received request with unknown request_type: {}, request_id: {}",
                request_type,
                request_id
            );
            send_response(
                &response_sock,
                &serde_json::json!({
                    "response": {
                        "status": "error",
                        "message": format!("Received request with unknown request_type: {}, request_id: {}", request_type, request_id),
                        "data": request_json,
                        "request_id": request_id,
                    }
                }),
            );
            return Err(anyhow::anyhow!(
                "handle_setup_request -> Received request with unknown request_type: {}, request_id: {}",
                request_type,
                request_id
            ));
        }
    }
}

/*
 * The format for the setup server request is a JSON object with the following fields:
{   "Request":{
        "request_type": "CreateAndInitialize" | "Initialize" | "AddFirstAdmin" | "GetState", // CreateAndInitialize is used when storage state is Empty, Initialize is used when storage state is Created, AddFirstAdmin is used when storage state is Initialized, GetState can be used at any time to get the current storage state
        "response_socket": "Path to the Unix socket where the response should be sent",
        "create_new_storage": true | false, // Only applicable for CreateAndInitialize request type, indicates whether to create new storage or just initialize existing storage
        "data": {
            "certificate_data": {
                "subject_common_name": "Common Name for the admin certificate",
                "issuer_common_name": "Common Name for the issuer (Intermediate CA Name) certificate",
                "organization": "Organization for the admin certificate",
                "organizational_unit": "Organizational Unit for the admin certificate",
                "locality": "Locality for the admin certificate",
                "state": "State for the admin certificate",
                "country": "Country for the admin certificate",
                "validity_days": "Number of days the admin certificate should be valid for",
            }
        }
    }
}
* The setup server will perform the requested action (creating and initializing storage,
* or adding the first admin user) and then send a response back to the specified response socket.
*
* The response will be a JSON object with the following format:
{
    "response": {
        "request_id": "The unique ID of the request being responded to",
        "status": "success" | "error",
        "message": "Detailed message about the result of the request",
        "storage_state": "The current storage state after handling the request",
        "data": {
            // Optional field containing additional data relevant to the request
            // For AddFirstAdmin request, this will include the admin certificate and private key in base64 format
            "admin_certificate": "Base64-encoded DER format of the admin certificate",
            "admin_private_key": "Base64-encoded DER format of the admin private key",
        }
    }
}
*/
pub fn start_setup_server(
    app_config: &crate::configs::AppConfig,
    storage_status: &crate::storage::StorageStatusResults,
) {
    let _ = std::fs::remove_file(app_config.server.comm_sock.clone());
    let listener = std::os::unix::net::UnixListener::bind(app_config.server.comm_sock.clone())
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
        return;
    }
    while storage_status.error_message.is_none()
        || storage_status.storage_state != crate::storage::StorageState::Ready
    {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let storage_status =
                        match handle_setup_request(&stream, app_config, storage_status.clone()) {
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
                    }
                    if storage_status.storage_state == crate::storage::StorageState::Ready {
                        tracing::info!("Storage is now ready, shutting down setup server");
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to accept connection on setup socket");
                }
            }
        }
    }
}

pub fn start_repair_server(
    app_config: &crate::configs::AppConfig,
    storage_status: &crate::storage::StorageStatusResults,
) {
    // For now, we will just log that the repair server is not implemented and return the same storage status
    tracing::warn!("Repair server is not implemented yet, returning current storage status");
}

fn parse_admin_cert_data(
    request_json: &serde_json::Value,
    app_config: &crate::configs::AppConfig,
) -> Result<crate::pki_generator::CertificateData, anyhow::Error> {
    let admin_cert_data = crate::pki_generator::CertificateData {
        subject_common_name: match request_json
            .pointer("/request/data/admin_certificate_data/subject_common_name")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.subject_common_name");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.subject_common_name"
                ));
            }
        },
        issuer_common_name: match request_json
            .pointer("/request/data/admin_certificate_data/issuer_common_name")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::info!("parse_admin_cert_data -> request missing admin_certificate_data.issuer_common_name, defaulting to configured admin intermediate CN");
                app_config.admin_ca_defaults.admin_ca_common_name.clone()
            }
        },
        organization: match request_json
            .pointer("/request/data/admin_certificate_data/organization")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.organization");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.organization"
                ));
            }
        },
        organizational_unit: match request_json
            .pointer("/request/data/admin_certificate_data/organizational_unit")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.organizational_unit");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.organizational_unit"
                ));
            }
        },
        locality: match request_json
            .pointer("/request/data/admin_certificate_data/locality")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.locality");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.locality"
                ));
            }
        },
        state: match request_json
            .pointer("/request/data/admin_certificate_data/state")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.state");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.state"
                ));
            }
        },
        country: match request_json
            .pointer("/request/data/admin_certificate_data/country")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.country");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.country"                                    ));
            }
        },
        validity_days: match request_json
            .pointer("/request/data/admin_certificate_data/validity_days")
            .and_then(|v| v.as_u64())
        {
            Some(d) => d as u32,
            None => {
                tracing::error!("parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.validity_days");
                return Err(anyhow::anyhow!(
                    "parse_admin_cert_data -> CreateAndInitialize request missing required field: admin_certificate_data.validity_days"
                ));
            }
        },
        is_admin: true,
        cert_type: crate::pki_generator::CertificateDataType::UserCert,
    };
    Ok(admin_cert_data)
}
