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

pub fn recv_request(
    mut request_socket: &std::os::unix::net::UnixStream,
) -> anyhow::Result<serde_json::Value> {
    let mut version_buffer = [0u8; 4];
    let mut length_buffer = [0u8; 4];
    if let Err(e) = request_socket.read_exact(&mut version_buffer) {
        tracing::error!(error = %e, "Failed to read protocol version");
        return Err(anyhow::anyhow!("Failed to read protocol version"));
    }
    if let Err(e) = request_socket.read_exact(&mut length_buffer) {
        tracing::error!(error = %e, "Failed to read payload length");
        return Err(anyhow::anyhow!("Failed to read payload length"));
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
    if let Err(e) = request_socket.read_exact(&mut payload_buffer) {
        tracing::error!(error = %e, "Failed to read payload data");
        return Err(anyhow::anyhow!("Failed to read payload data"));
    }
    match serde_json::from_slice(&payload_buffer) {
        Ok(json) => Ok(json),
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse request JSON");
            Err(anyhow::anyhow!("Failed to parse request JSON"))
        }
    }
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
    mut response_socket: &std::os::unix::net::UnixStream,
    response_json: &serde_json::Value,
) {
    let (response_data, _) = serialize_response(response_json);
    if let Err(e) = response_socket.write_all(&response_data) {
        tracing::error!(socket = ?response_socket, error = %e, "Failed to send response");
    }
}

/*
* The format for the API server request is a JSON object with the following fields:
{
    "request": {
        "response_socket": "Path to the Unix socket where the response should be sent",
        "request_type": "GetCACertificate" | "CheckCRL" | "LoginAdmin" | "GetState" | "AdminRequest",
        // For GetCACertificate request type, the following additional fields are required:
        "subject_common_name": "The common name of the certificate to retrieve",
        "requester_certificate": "Base64-encoded DER format of the requester certificate,
        "data": {
            // Optional field containing additional data relevant to the request
        },
    },
    "request_signature": "Base64-encoded signature of the request JSON (excluding the
        request_signature field) signed by the requester certificate's private key"
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
                handle_api_request(&stream, &storage);
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
    storage_status
}

fn handle_api_request(
    stream: &std::os::unix::net::UnixStream,
    storage: &crate::storage::Storage<crate::storage_api::API>,
) {
    let request_json = match recv_request(stream) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!(error = %e, "Failed to receive or parse request");
            return;
        }
    };
    let request = match request_json.get("request") {
        Some(r) => r,
        None => {
            tracing::error!("Request JSON missing required field: request");
            return;
        }
    };
    let request_signature_base64 = match request_json
        .get("request_signature")
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => {
            tracing::error!("Request JSON missing required field: request_signature");
            return;
        }
    };
    let request_signature =
        match base64::engine::general_purpose::STANDARD.decode(request_signature_base64) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(error = %e, "Failed to decode request signature from base64");
                return;
            }
        };
    let request_bytes = match serde_json::to_vec(request) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize request JSON for signature verification");
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
    let requester_cert_base64 = request_json
        .pointer("/request/requester_certificate")
        .and_then(|v| v.as_str());
    let requester_cert_der = match requester_cert_base64 {
        Some(rc) => match base64::engine::general_purpose::STANDARD.decode(rc) {
            Ok(der) => der,
            Err(e) => {
                tracing::error!(error = %e, "Failed to decode requester certificate from base64");
                send_response(
                    &response_socket,
                    &serde_json::json!({
                        "status": "error",
                        "message": "Failed to decode requester certificate from base64",
                        "data": request_json,
                    }),
                );
                return;
            }
        },
        None => {
            tracing::error!("Request missing required field: requester_certificate");
            send_response(
                &response_socket,
                &serde_json::json!({
                    "status": "error",
                    "message": "Request missing required field: requester_certificate",
                    "data": request_json,
                }),
            );
            return;
        }
    };
    let requester_cert = match openssl::x509::X509::from_der(&requester_cert_der) {
        Ok(cert) => cert,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse requester certificate from DER");
            send_response(
                &response_socket,
                &serde_json::json!({
                    "status": "error",
                    "message": "Failed to parse requester certificate from DER",
                    "data": request_json,
                }),
            );
            return;
        }
    };
    let request_verified = match requester_cert.public_key() {
        Ok(public_key) => match crate::encryption::verify_signature(
            &request_bytes,
            &request_signature,
            public_key,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::error!(error = %e, "Failed to verify request signature");
                send_response(
                    &response_socket,
                    &serde_json::json!({
                        "status": "error",
                        "message": "Failed to verify request signature",
                        "data": request_json,
                    }),
                );
                return;
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "Failed to extract public key from requester certificate");
            send_response(
                &response_socket,
                &serde_json::json!({
                    "status": "error",
                    "message": "Failed to extract public key from requester certificate",
                    "data": request_json,
                }),
            );
            return;
        }
    };
    if !request_verified {
        tracing::error!("Request signature verification failed");
        send_response(
            &response_socket,
            &serde_json::json!({
                "status": "error",
                "message": "Request signature verification failed",
                "data": request_json,
            }),
        );
        return;
    }
    let authorized_user =
        match storage.get_certificate_by_serial(requester_cert.serial_number().to_bn().unwrap()) {
            Ok((cert, _)) => cert,
            Err(_) => {
                tracing::error!("Requester certificate not found in storage",);
                send_response(
                    &response_socket,
                    &serde_json::json!({
                        "status": "error",
                        "message": "Requester certificate not found in storage",
                        "data": request_json,
                    }),
                );
                return;
            }
        };
    let user_intermediate_cert = match storage.get_certificate_by_common_name(
        authorized_user
            .issuer_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string()
            .as_str(),
    ) {
        Ok((cert, _)) => cert,
        Err(_) => {
            tracing::error!("Intermediate certificate for requester not found in storage",);
            send_response(
                &response_socket,
                &serde_json::json!({
                    "status": "error",
                    "message": "Intermediate certificate for requester not found in storage",
                    "data": request_json,
                }),
            );
            return;
        }
    };
    let intermediate_cert_verified = match crate::encryption::verify_certificate_signature(
        &requester_cert,
        &user_intermediate_cert,
    ) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::error!(error = %e, "Failed to verify signature of intermediate certificate");
            send_response(
                &response_socket,
                &serde_json::json!({
                    "status": "error",
                    "message": "Failed to verify signature of intermediate certificate",
                    "data": request_json,
                }),
            );
            return;
        }
    };
    let request_type = match request_json.get("request_type").and_then(|v| v.as_str()) {
        Some(rt) => rt,
        None => {
            tracing::error!("Request missing required field: request_type");
            send_response(
                &response_socket,
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
            let requster_cert_base64 = match request_json
                .get("requester_certificate")
                .and_then(|v| v.as_str())
            {
                Some(rc) => rc,
                None => {
                    tracing::error!(
                        "GetCACertificate request missing required field: requester_certificate"
                    );
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "status": "error",
                            "message": "GetCACertificate request missing required field: requester_certificate",
                            "data": request_json,
                        }),
                    );
                    return;
                }
            };
            let requester_cert_der = match base64::engine::general_purpose::STANDARD
                .decode(requster_cert_base64)
            {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to decode requester certificate from base64");
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "status": "error",
                            "message": "Failed to decode requester certificate from base64",
                            "data": request_json,
                        }),
                    );
                    return;
                }
            };
            let requester_cert = match openssl::x509::X509::from_der(&requester_cert_der) {
                Ok(cert) => cert,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse requester certificate from DER");
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "status": "error",
                            "message": "Failed to parse requester certificate from DER",
                            "data": request_json,
                        }),
                    );
                    return;
                }
            };
            // The requester signs the base64-encoded certificate request with their private key,
            // and we verify the signature using the public key from the requester certificate.
            // This ensures that only someone with the private key corresponding to the requester
            // certificate can successfully make this request.
            let requester_cert_serial = requester_cert.serial_number().to_bn().unwrap();
            let stored_requester_cert =
                match storage.get_certificate_by_serial(requester_cert_serial) {
                    Ok((cert, _)) => cert,
                    Err(_) => {
                        tracing::error!("Requester certificate not found in storage",);
                        send_response(
                            &response_socket,
                            &serde_json::json!({
                                "status": "error",
                                "message": "Requester certificate not found in storage",
                                "data": request_json,
                            }),
                        );
                        return;
                    }
                };
            // Handle GetCACertificate request
            let subject_common_name = match request_json
                .get("subject_common_name")
                .and_then(|v| v.as_str())
            {
                Some(cn) => cn,
                None => {
                    tracing::error!(
                        "GetCACertificate request missing required field: subject_common_name"
                    );
                    send_response(
                        &response_socket,
                        &serde_json::json!({
                            "status": "error",
                            "message": "GetCACertificate request missing required field: subject_common_name",
                            "data": request_json,
                        }),
                    );
                    return;
                }
            };
            let (requested_cert, cert_height) =
                match storage.get_certificate_by_common_name(subject_common_name) {
                    Ok((cert, height)) => (cert, height),
                    Err(_) => {
                        tracing::error!(
                            "Certificate not found for subject_common_name: {}",
                            subject_common_name
                        );
                        send_response(
                            &response_socket,
                            &serde_json::json!({
                                "status": "error",
                                "message": "Certificate not found",
                                "data": request_json,
                            }),
                        );
                        return;
                    }
                };
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
                &response_socket,
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
    mut stream: &std::os::unix::net::UnixStream,
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
                        &response_sock,
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
                        &response_sock,
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
                        &response_sock,
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
                        &response_sock,
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
                &response_sock,
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
                &response_sock,
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
                        &response_sock,
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
                        &response_sock,
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

/*
 * The format for the setup server request is a JSON object with the following fields:
{
    "request_type": "CreateAndInitialize" | "Initialize" | "AddFirstAdmin",
    "response_socket": "Path to the Unix socket where the response should be sent",
    // For AddFirstAdmin request type, the following additional fields are required:
    "admin_certificate_data": {
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
* The setup server will perform the requested action (creating and initializing storage,
* or adding the first admin user) and then send a response back to the specified response socket.
*
* The response will be a JSON object with the following format:
{
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
*/
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
                    break;
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
