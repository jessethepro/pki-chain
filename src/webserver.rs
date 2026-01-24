use crate::configs::AppConfig;
use crate::pki_generator::CertificateData;
use crate::storage::{check_storage_state, clear_storage, Storage, StorageState};
use crate::templates;
use axum::Json;
use axum::{
    extract::{ConnectInfo, Multipart, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Verifier;
use openssl::x509::X509;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// CA Server State
//#[derive(Clone)]
enum CAServerState {
    NoExist,
    Initialized {
        root_ca_password: SecretString,
    },
    CreateAdmin {
        root_ca_password: SecretString,
    },
    Ready,
    Authenticated {
        root_ca_password: SecretString,
        user_cert_cn: String,
    },
}

/// Shared application state
type AppState = Arc<Mutex<CAServerState>>;

#[derive(Deserialize)]
struct InitializeForm {
    root_ca_password: String,
}

#[derive(Deserialize)]
struct CreateAdminForm {
    common_name: String,
    organization: String,
    organizational_unit: String,
    locality: String,
    state: String,
    country: String,
    root_ca_password: String,
}

#[derive(Deserialize)]
struct CreateIntermediateForm {
    common_name: String,
    organization: String,
    organizational_unit: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
    root_ca_password: String,
}

#[derive(Deserialize)]
struct CreateUserForm {
    intermediate_ca: String,
    common_name: String,
    organization: String,
    organizational_unit: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
}

#[derive(Deserialize)]
struct RevokeForm {
    serial_number: String,
    reason: Option<String>,
    //confirm: String,
}

// ============================================================================
// API Request/Response Structures
// ============================================================================

#[derive(Deserialize)]
struct GetCertificateRequest {
    requester_serial: String,
    target_cn: String,
    signature: String, // base64-encoded signature of target_cn
}

#[derive(Serialize)]
struct GetCertificateResponse {
    success: bool,
    certificate_pem: Option<String>,
    serial_number: Option<String>,
    subject_cn: Option<String>,
    issuer_cn: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    encrypted_hash: Option<String>, // base64-encoded encrypted hash
    error: Option<String>,
}

#[derive(Deserialize)]
struct VerifyCertificateRequest {
    requester_serial: String,
    target_serial: String,
    signature: String, // base64-encoded signature of target_serial
}

#[derive(Serialize)]
struct VerifyCertificateResponse {
    success: bool,
    valid: Option<bool>,
    serial_number: Option<String>,
    subject_cn: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    revoked: Option<bool>,
    encrypted_hash: Option<String>, // base64-encoded encrypted hash
    error: Option<String>,
}

// Login uses Multipart for file uploads

pub fn start_webserver() {
    // Create logs directory if it doesn't exist
    if let Err(e) = fs::create_dir_all("logs") {
        eprintln!("Failed to create logs directory: {}", e);
        std::process::exit(1);
    }

    // Set up logging to file and console
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "webserver.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pki_chain=info,axum=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .init();

    info!("Starting PKI Chain Certificate Authority web server");

    let rt = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            error!("Failed to create Tokio runtime: {}", e);
            eprintln!("Failed to create Tokio runtime: {}", e);
            std::process::exit(1);
        }
    };

    rt.block_on(async {
        // Load application configuration
        let app_config = match AppConfig::load() {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to load config.toml: {}", e);
                eprintln!(
                    "Failed to load config.toml. Ensure config.toml exists in the project root."
                );
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        // Check initial storage state
        let (initial_state, api_enabled) = match check_storage_state() {
            Ok(state) => match state {
                StorageState::NoExist => {
                    info!("Storage state: NoExist (fresh installation)");
                    (CAServerState::NoExist, false)
                }
                StorageState::Initialized => {
                    info!("Storage state: Initialized (Root CA exists)");
                    (
                        CAServerState::Initialized {
                            root_ca_password: SecretString::new(String::new().into()),
                        },
                        false,
                    )
                }
                StorageState::Ready => {
                    info!("Storage state: Ready (admin exists)");
                    info!("✅ REST API enabled - certificates available for programmatic access");
                    (CAServerState::Ready, true)
                }
            },
            Err(e) => {
                warn!(
                    "Failed to check storage state: {}. Defaulting to NoExist.",
                    e
                );
                (CAServerState::NoExist, false)
            }
        };

        let app_state = Arc::new(Mutex::new(initial_state));

        // Admin routes (localhost-only)
        let admin_routes = Router::new()
            .route("/", get(index))
            .route("/initialize", post(initialize))
            .route("/create-admin", post(create_admin))
            .route("/login", post(login))
            .route("/admin/dashboard", get(admin_dashboard))
            .route("/admin/create-user", get(admin_create_user))
            .route("/admin/create-intermediate", get(admin_create_intermediate))
            .route(
                "/admin/create-intermediate",
                post(submit_create_intermediate),
            )
            .route("/admin/create-user", post(submit_create_user))
            .route("/admin/status", get(admin_status))
            .route("/admin/revoke", get(admin_revoke))
            .route("/admin/revoke", post(submit_revoke))
            .route("/logout", post(logout))
            .layer(middleware::from_fn(localhost_only))
            .with_state(app_state.clone());

        // API routes (accessible from all networks)
        let api_routes = Router::new()
            .route("/api/get-certificate", post(api_get_certificate))
            .route("/api/verify-certificate", post(api_verify_certificate))
            .with_state(app_state);

        // Combine routes
        let app = Router::new().merge(admin_routes).merge(api_routes);

        // Configure TLS with certificates from config
        let tls_config = match RustlsConfig::from_pem_file(
            &app_config.server.tls_cert_path,
            &app_config.server.tls_key_path,
        )
        .await
        {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to load TLS certificates: {}", e);
                eprintln!("Failed to load TLS certificates. Run ./generate-certs.sh first.");
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        // Parse server address from config
        let addr: SocketAddr =
            match format!("{}:{}", app_config.server.host, app_config.server.port).parse() {
                Ok(addr) => addr,
                Err(e) => {
                    error!("Failed to parse server address from config: {}", e);
                    eprintln!("Failed to parse server address from config: {}", e);
                    std::process::exit(1);
                }
            };

        info!("🔒 PKI Chain Certificate Authority");
        info!(
            "   Admin Interface: https://127.0.0.1:{} (localhost only)",
            app_config.server.port
        );
        if api_enabled {
            info!(
                "   REST API: https://{}:{} (all networks) - ✅ ACTIVE",
                if app_config.server.host == "0.0.0.0" {
                    "<your-ip>"
                } else {
                    &app_config.server.host
                },
                app_config.server.port
            );
        } else {
            info!(
                "   REST API: https://{}:{} (all networks) - ⏸️  INACTIVE (complete initialization first)",
                if app_config.server.host == "0.0.0.0" {
                    "<your-ip>"
                } else {
                    &app_config.server.host
                },
                app_config.server.port
            );
        }
        info!("   TLS Cert: {}", app_config.server.tls_cert_path.display());
        info!("   TLS Key: {}", app_config.server.tls_key_path.display());
        info!("   Web Root: {}", app_config.server.web_root.display());
        info!("   Log Directory: logs/");
        info!("✅ Server ready!");

        println!("🔒 PKI Chain Certificate Authority");
        println!(
            "   Admin Interface: https://127.0.0.1:{} (localhost only)",
            app_config.server.port
        );
        if api_enabled {
            println!(
                "   REST API: https://{}:{} (all networks) - ✅ ACTIVE",
                if app_config.server.host == "0.0.0.0" {
                    "<your-ip>"
                } else {
                    &app_config.server.host
                },
                app_config.server.port
            );
            println!("   📡 API Endpoints:");
            println!("      POST /api/get-certificate");
            println!("      POST /api/verify-certificate");
        } else {
            println!(
                "   REST API: https://{}:{} (all networks) - ⏸️  INACTIVE",
                if app_config.server.host == "0.0.0.0" {
                    "<your-ip>"
                } else {
                    &app_config.server.host
                },
                app_config.server.port
            );
            println!("   ℹ️  Complete system initialization to enable API access");
        }
        println!("   TLS Cert: {}", app_config.server.tls_cert_path.display());
        println!("   TLS Key: {}", app_config.server.tls_key_path.display());
        println!("   Web Root: {}", app_config.server.web_root.display());
        println!("   Log Directory: logs/");
        println!("\n✅ Server ready!\n");

        if let Err(e) = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            error!("Server error: {}", e);
            eprintln!("Server error: {}", e);
            std::process::exit(1);
        }
    });
}

// ============================================================================
// Middleware
// ============================================================================

/// Middleware to restrict access to localhost only
async fn localhost_only(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check if request is from localhost (127.0.0.1 or ::1)
    let is_localhost = addr.ip().is_loopback();

    if !is_localhost {
        warn!("Blocked non-localhost access to admin route from: {}", addr);
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

// ============================================================================
// Route Handlers
// ============================================================================

async fn index(State(ca_state): State<AppState>) -> Html<String> {
    let ca_state = ca_state.lock().await;

    let markup = match &*ca_state {
        CAServerState::NoExist => templates::render_initialize_page(),
        CAServerState::Initialized { .. } | CAServerState::CreateAdmin { .. } => {
            templates::render_create_admin_page()
        }
        CAServerState::Ready => templates::render_login_page(),
        CAServerState::Authenticated { .. } => {
            drop(ca_state);
            return Html(
                "<meta http-equiv='refresh' content='0;url=/admin/dashboard'>".to_string(),
            );
        }
    };

    Html(markup.into_string())
}

async fn initialize(
    State(ca_state): State<AppState>,
    Form(form): Form<InitializeForm>,
) -> Html<String> {
    let config = match AppConfig::load() {
        Ok(c) => c,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to load config: {}", e)).into_string(),
            )
        }
    };

    // Clear existing storage if any
    if let Err(e) = clear_storage() {
        return Html(
            templates::render_error(&format!("Failed to clear storage: {}", e)).into_string(),
        );
    }

    // Initialize storage with Root CA
    let storage = match Storage::new() {
        Ok(s) => s,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to create storage: {}", e)).into_string(),
            )
        }
    };

    match storage.initialize(form.root_ca_password.clone()) {
        Ok(_) => {
            // Update state to CreateAdmin with password
            let mut state = ca_state.lock().await;
            *state = CAServerState::CreateAdmin {
                root_ca_password: SecretString::new(form.root_ca_password.into()),
            };

            Html(
                templates::render_success(
                    "Root CA initialized successfully! Please create the first admin user.",
                )
                .into_string(),
            )
        }
        Err(e) => {
            Html(templates::render_error(&format!("Failed to initialize: {}", e)).into_string())
        }
    }
}

async fn create_admin(
    State(ca_state): State<AppState>,
    Form(form): Form<CreateAdminForm>,
) -> impl IntoResponse {
    info!(
        "Received admin creation request for CN: {}",
        form.common_name
    );

    let mut state = ca_state.lock().await;

    // Verify we're in the correct state (Initialized or CreateAdmin)
    if !matches!(
        &*state,
        CAServerState::CreateAdmin { .. } | CAServerState::Initialized { .. }
    ) {
        error!("Invalid state for creating admin: current state does not allow admin creation");
        return Html(templates::render_error("Invalid state for creating admin").into_string())
            .into_response();
    }

    let admin_data = CertificateData {
        subject_common_name: form.common_name.clone(),
        issuer_common_name: String::new(), // Will be set by storage
        organization: form.organization,
        organizational_unit: format!("{} Admin", form.organizational_unit), // Mark as Admin
        locality: form.locality,
        state: form.state,
        country: form.country,
        cert_type: crate::pki_generator::CertificateDataType::UserCert,
        validity_days: 365 * 2, // 2 years
        is_admin: true,
    };

    let storage = match crate::storage::Storage::<crate::storage::Initialized>::open() {
        Ok(s) => s,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to open storage: {}", e)).into_string(),
            )
            .into_response()
        }
    };

    match storage.create_admin(admin_data, form.root_ca_password.clone()) {
        Ok((_storage, cert_pem, key_pem)) => {
            info!("Admin user created successfully: {}", form.common_name);
            // Transition to Ready state (password dropped)
            *state = CAServerState::Ready;
            drop(state); // Release lock

            // Create a simple HTML page with download links
            let cert_filename = format!("{}.crt", form.common_name.replace(" ", "_"));
            let key_filename = format!("{}.key", form.common_name.replace(" ", "_"));

            let cert_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_pem);
            let key_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_pem);

            let html_response = templates::render_admin_created_with_downloads(
                &cert_filename,
                &key_filename,
                &cert_b64,
                &key_b64,
            );

            Html(html_response.into_string()).into_response()
        }
        Err(e) => {
            Html(templates::render_error(&format!("Failed to create admin: {}", e)).into_string())
                .into_response()
        }
    }
}

async fn login(State(ca_state): State<AppState>, mut multipart: Multipart) -> Html<String> {
    info!("Received login request");

    let mut cert_data: Option<Vec<u8>> = None;
    let mut key_data: Option<Vec<u8>> = None;
    let mut root_ca_password: Option<String> = None;

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        let data = field.bytes().await.unwrap_or_default();

        match name.as_str() {
            "certificate" => cert_data = Some(data.to_vec()),
            "private_key" => key_data = Some(data.to_vec()),
            "root_ca_password" => {
                root_ca_password = Some(String::from_utf8_lossy(&data).to_string())
            }
            _ => {}
        }
    }

    // Validate all required fields are present
    let cert_bytes = match cert_data {
        Some(data) => data,
        None => return Html(templates::render_error("Certificate file is required").into_string()),
    };

    let key_bytes = match key_data {
        Some(data) => data,
        None => return Html(templates::render_error("Private key file is required").into_string()),
    };

    let password = match root_ca_password {
        Some(pwd) => pwd,
        None => return Html(templates::render_error("Root CA password is required").into_string()),
    };

    // Step 1: Parse certificate
    let user_cert = match X509::from_pem(&cert_bytes) {
        Ok(cert) => cert,
        Err(_) => {
            return Html(
                templates::render_error("Invalid certificate format (expected PEM)").into_string(),
            )
        }
    };

    // Step 2: Parse private key
    let user_private_key = match PKey::private_key_from_pem(&key_bytes) {
        Ok(key) => key,
        Err(_) => {
            return Html(
                templates::render_error("Invalid private key format (expected PEM)").into_string(),
            )
        }
    };

    // Step 3: Verify public/private key pair match
    let cert_public_key = match user_cert.public_key() {
        Ok(key) => key,
        Err(_) => {
            return Html(
                templates::render_error("Failed to extract public key from certificate")
                    .into_string(),
            )
        }
    };

    if !keys_match(&user_private_key, &cert_public_key) {
        return Html(
            templates::render_error("Private key does not match certificate").into_string(),
        );
    }

    // Step 4: Verify Root CA password by attempting to decrypt Root CA key
    let config = match AppConfig::load() {
        Ok(c) => c,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to load config: {}", e)).into_string(),
            )
        }
    };

    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to open storage: {}", e)).into_string(),
            )
        }
    };

    // Try to verify password by loading Root CA private key
    let root_ca_valid = verify_root_ca_password(&password);
    if !root_ca_valid {
        return Html(templates::render_error("Invalid Root CA password").into_string());
    }

    // Step 5: Verify certificate exists in blockchain
    let cert_subject = match user_cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string())
    {
        Some(cn) => cn,
        None => {
            return Html(templates::render_error("Certificate missing Common Name").into_string())
        }
    };

    // Verify certificate exists in storage
    let cert_exists = storage
        .get_certificate_by_subject(&cert_subject)
        .unwrap_or(None)
        .is_some();

    if !cert_exists {
        warn!(
            "Login attempt with certificate not found in PKI system: {}",
            cert_subject
        );
        return Html(templates::render_error("Certificate not found in PKI system").into_string());
    }

    // Step 6: Challenge-Response authentication
    // Generate random challenge data
    let mut challenge = vec![0u8; 32];
    openssl::rand::rand_bytes(&mut challenge).unwrap();

    // Sign challenge with private key
    let signature = match sign_data(&user_private_key, &challenge) {
        Ok(sig) => sig,
        Err(_) => {
            return Html(templates::render_error("Failed to sign challenge data").into_string())
        }
    };

    // Verify signature with certificate's public key
    let signature_valid = match verify_signature(&cert_public_key, &challenge, &signature) {
        Ok(valid) => valid,
        Err(_) => return Html(templates::render_error("Failed to verify signature").into_string()),
    };

    if !signature_valid {
        return Html(
            templates::render_error("Invalid signature - authentication failed").into_string(),
        );
    }

    // Step 7: Verify admin status - check if this is an admin certificate
    // Admin certificates have a specific marker that we check
    let is_admin = check_admin_status(&user_cert);
    if !is_admin {
        warn!("Login attempt with non-admin certificate: {}", cert_subject);
        return Html(
            templates::render_error(
                "Access denied: This certificate does not have administrative privileges. Only administrators can access the web interface."
            )
            .into_string(),
        );
    }

    // Step 8: Check if certificate has been revoked
    let serial = user_cert.serial_number();
    let serial_hex = match serial
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|s| s.to_string())
    {
        Ok(hex) => hex,
        Err(_) => {
            return Html(
                templates::render_error("Failed to extract certificate serial number")
                    .into_string(),
            )
        }
    };

    let is_revoked = match storage.is_certificate_revoked(&serial_hex) {
        Ok(revoked) => revoked,
        Err(e) => {
            error!("Failed to check revocation status: {}", e);
            return Html(
                templates::render_error("Failed to check certificate revocation status")
                    .into_string(),
            );
        }
    };

    if is_revoked {
        warn!(
            "Login attempt with revoked certificate: {} (Serial: {})",
            cert_subject, serial_hex
        );
        return Html(
            templates::render_error(
                "Access denied: This certificate has been revoked. Please contact your administrator to obtain a new certificate."
            )
            .into_string(),
        );
    }

    // All checks passed - authenticate user
    info!("Admin user authenticated successfully: {}", cert_subject);
    let mut state = ca_state.lock().await;
    *state = CAServerState::Authenticated {
        root_ca_password: SecretString::new(password.into()),
        user_cert_cn: cert_subject.clone(),
    };

    Html(templates::render_success("Login successful! Redirecting to dashboard...").into_string())
}

// Helper function to check if certificate has admin privileges
fn check_admin_status(cert: &X509) -> bool {
    // Check if the certificate was created as an admin certificate
    // Admin certificates have " Admin" suffix in their OU field
    // This is set during create_admin flow

    if let Some(ou) = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::ORGANIZATIONALUNITNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
    {
        // Check for " Admin" suffix (note the leading space)
        return ou.ends_with(" Admin");
    }

    false
}

// Helper function to verify public/private key pair match
fn keys_match(private_key: &PKey<Private>, public_key: &PKey<Public>) -> bool {
    // Sign test data with private key and verify with public key
    let test_data = b"authentication_test";

    match sign_data(private_key, test_data) {
        Ok(signature) => match verify_signature(public_key, test_data, &signature) {
            Ok(valid) => valid,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

// Helper function to sign data with private key
fn sign_data(
    private_key: &PKey<Private>,
    data: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    use openssl::sign::Signer;
    let mut signer = Signer::new(MessageDigest::sha256(), private_key)?;
    signer.update(data)?;
    signer.sign_to_vec()
}

// Helper function to verify signature with public key
fn verify_signature(
    public_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, openssl::error::ErrorStack> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key)?;
    verifier.update(data)?;
    verifier.verify(signature)
}

// Helper function to verify Root CA password
fn verify_root_ca_password(password: &str) -> bool {
    use std::fs;

    let config = match AppConfig::load() {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Try to open the private key blockchain and decrypt Root CA key
    let key_chain_path = config.blockchains.private_key_path;
    if !key_chain_path.exists() {
        return false;
    }

    match libblockchain::blockchain::open_read_only_chain(key_chain_path) {
        Ok(chain) => {
            if let Ok(count) = chain.block_count() {
                if count == 0 {
                    return false;
                }
            }

            // Try to get and decrypt Root CA key at height 0
            match chain.get_block_by_height(0) {
                Ok(block) => {
                    // Try to decrypt the key with the provided password
                    match PKey::private_key_from_pem_passphrase(
                        &block.block_data(),
                        password.as_bytes(),
                    ) {
                        Ok(_) => true,
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

async fn logout(State(ca_state): State<AppState>) -> Redirect {
    info!("User logged out");
    let mut state = ca_state.lock().await;
    *state = CAServerState::Ready;
    Redirect::to("/")
}

async fn admin_dashboard(State(ca_state): State<AppState>) -> Html<String> {
    let state = ca_state.lock().await;

    match &*state {
        CAServerState::Authenticated { user_cert_cn, .. } => {
            Html(templates::render_admin_dashboard(user_cert_cn).into_string())
        }
        _ => Html(templates::render_error("Not authenticated").into_string()),
    }
}

async fn admin_create_user(State(ca_state): State<AppState>) -> Html<String> {
    let state = ca_state.lock().await;

    match &*state {
        CAServerState::Authenticated { .. } => {
            drop(state); // Release lock before I/O

            // Open storage to get list of intermediate CAs
            let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
                Ok(s) => s,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to open storage: {}", e))
                            .into_string(),
                    )
                }
            };

            let intermediate_cas = match storage.list_intermediate_cas() {
                Ok(cas) => cas,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to list intermediate CAs: {}", e))
                            .into_string(),
                    )
                }
            };

            Html(templates::render_create_user_page(&intermediate_cas).into_string())
        }
        _ => Html(templates::render_error("Not authenticated").into_string()),
    }
}

async fn admin_create_intermediate(State(ca_state): State<AppState>) -> Html<String> {
    let state = ca_state.lock().await;

    match &*state {
        CAServerState::Authenticated { .. } => {
            Html(templates::render_create_intermediate_page().into_string())
        }
        _ => Html(templates::render_error("Not authenticated").into_string()),
    }
}

async fn submit_create_intermediate(
    State(ca_state): State<AppState>,
    Form(form): Form<CreateIntermediateForm>,
) -> Html<String> {
    info!(
        "Received intermediate CA creation request for CN: {}",
        form.common_name
    );

    let state = ca_state.lock().await;

    // Verify authenticated
    if !matches!(&*state, CAServerState::Authenticated { .. }) {
        return Html(templates::render_error("Not authenticated").into_string());
    }

    drop(state); // Release lock before long operations

    // Open storage
    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to open storage: {}", e)).into_string(),
            )
        }
    };

    // Prepare certificate data
    let cert_data = CertificateData {
        subject_common_name: form.common_name.clone(),
        issuer_common_name: String::new(), // Will be set to Root CA CN by storage
        organization: form.organization,
        organizational_unit: form.organizational_unit,
        locality: form.locality,
        state: form.state,
        country: form.country,
        cert_type: crate::pki_generator::CertificateDataType::IntermediateCA,
        validity_days: form.validity_days,
        is_admin: false,
    };

    // Create intermediate CA
    match storage.create_intermediate(cert_data, form.root_ca_password) {
        Ok((cert_pem, key_pem)) => {
            info!("Intermediate CA created successfully: {}", form.common_name);

            // Create download files
            let cert_filename = format!("{}.crt", form.common_name.replace(" ", "_"));
            let key_filename = format!("{}.key", form.common_name.replace(" ", "_"));

            let cert_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_pem);
            let key_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_pem);

            Html(
                templates::render_intermediate_created_with_downloads(
                    &cert_filename,
                    &key_filename,
                    &cert_b64,
                    &key_b64,
                )
                .into_string(),
            )
        }
        Err(e) => Html(
            templates::render_error(&format!("Failed to create intermediate CA: {}", e))
                .into_string(),
        ),
    }
}

async fn submit_create_user(
    State(ca_state): State<AppState>,
    Form(form): Form<CreateUserForm>,
) -> Html<String> {
    info!(
        "Received user certificate creation request for CN: {}",
        form.common_name
    );

    let state = ca_state.lock().await;

    // Verify authenticated
    if !matches!(&*state, CAServerState::Authenticated { .. }) {
        return Html(templates::render_error("Not authenticated").into_string());
    }

    drop(state); // Release lock before long operations

    // Open storage
    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to open storage: {}", e)).into_string(),
            )
        }
    };

    // Prepare certificate data
    let cert_data = CertificateData {
        subject_common_name: form.common_name.clone(),
        issuer_common_name: String::new(), // Will be set to intermediate CA CN by storage
        organization: form.organization,
        organizational_unit: form.organizational_unit,
        locality: form.locality,
        state: form.state,
        country: form.country,
        cert_type: crate::pki_generator::CertificateDataType::UserCert,
        validity_days: form.validity_days,
        is_admin: false,
    };

    // Create user certificate
    match storage.create_user_certificate(cert_data, &form.intermediate_ca) {
        Ok((cert_pem, key_pem)) => {
            info!(
                "User certificate created successfully: {}",
                form.common_name
            );

            // Create download files
            let cert_filename = format!("{}.crt", form.common_name.replace(" ", "_"));
            let key_filename = format!("{}.key", form.common_name.replace(" ", "_"));

            let cert_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_pem);
            let key_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_pem);

            Html(
                templates::render_user_created_with_downloads(
                    &cert_filename,
                    &key_filename,
                    &cert_b64,
                    &key_b64,
                )
                .into_string(),
            )
        }
        Err(e) => Html(
            templates::render_error(&format!("Failed to create user certificate: {}", e))
                .into_string(),
        ),
    }
}

async fn admin_status(State(ca_state): State<AppState>) -> Html<String> {
    let state = ca_state.lock().await;

    match &*state {
        CAServerState::Authenticated { .. } => {
            // Open storage to get statistics
            let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
                Ok(s) => s,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to open storage: {}", e))
                            .into_string(),
                    )
                }
            };

            // Get certificate count
            let cert_count = match storage.certificate_count() {
                Ok(count) => count,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to get certificate count: {}", e))
                            .into_string(),
                    )
                }
            };

            // Get private key count (from private_key_chain)
            let config = match AppConfig::load() {
                Ok(c) => c,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to load config: {}", e))
                            .into_string(),
                    )
                }
            };

            let key_count = match libblockchain::blockchain::open_read_only_chain(
                config.blockchains.private_key_path.clone(),
            ) {
                Ok(chain) => match chain.block_count() {
                    Ok(count) => count,
                    Err(e) => {
                        return Html(
                            templates::render_error(&format!("Failed to get key count: {}", e))
                                .into_string(),
                        )
                    }
                },
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to open key blockchain: {}", e))
                            .into_string(),
                    )
                }
            };

            // Validate blockchains
            let cert_validation_ok = if let Ok(chain) =
                libblockchain::blockchain::open_read_only_chain(
                    config.blockchains.certificate_path.clone(),
                ) {
                chain.validate().is_ok()
            } else {
                false
            };

            let key_validation_ok = if let Ok(chain) =
                libblockchain::blockchain::open_read_only_chain(
                    config.blockchains.private_key_path.clone(),
                ) {
                chain.validate().is_ok()
            } else {
                false
            };

            Html(
                templates::render_status_page(
                    cert_count,
                    key_count,
                    cert_validation_ok,
                    key_validation_ok,
                )
                .into_string(),
            )
        }
        _ => Html(templates::render_error("Not authenticated").into_string()),
    }
}

async fn admin_revoke(State(ca_state): State<AppState>) -> Html<String> {
    let state = ca_state.lock().await;

    match &*state {
        CAServerState::Authenticated { .. } => {
            drop(state); // Release lock before I/O

            // Open storage to get list of certificates
            let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
                Ok(s) => s,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to open storage: {}", e))
                            .into_string(),
                    )
                }
            };

            // Get list of all certificates (excluding Root CA at height 0)
            let certificates = match storage.list_certificates_for_revocation() {
                Ok(certs) => certs,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!("Failed to list certificates: {}", e))
                            .into_string(),
                    )
                }
            };

            // Get list of currently revoked certificates
            let revoked_certificates = match storage.get_revoked_certificates() {
                Ok(revoked) => revoked,
                Err(e) => {
                    return Html(
                        templates::render_error(&format!(
                            "Failed to get revoked certificates: {}",
                            e
                        ))
                        .into_string(),
                    )
                }
            };

            Html(
                templates::render_revoke_certificate_page(&certificates, &revoked_certificates)
                    .into_string(),
            )
        }
        _ => Html(templates::render_error("Not authenticated").into_string()),
    }
}

async fn submit_revoke(
    State(ca_state): State<AppState>,
    Form(form): Form<RevokeForm>,
) -> Html<String> {
    info!(
        "Received certificate revocation request for serial: {}",
        form.serial_number
    );

    let state = ca_state.lock().await;

    // Verify authenticated
    if !matches!(&*state, CAServerState::Authenticated { .. }) {
        return Html(templates::render_error("Not authenticated").into_string());
    }

    drop(state); // Release lock before long operations

    // Open storage
    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => {
            return Html(
                templates::render_error(&format!("Failed to open storage: {}", e)).into_string(),
            )
        }
    };

    // Revoke certificate
    match storage.revoke_certificate(&form.serial_number, form.reason.as_deref()) {
        Ok(common_name) => {
            info!(
                "Certificate revoked successfully: {} (Serial: {})",
                common_name, form.serial_number
            );

            Html(
                templates::render_certificate_revoked(&form.serial_number, &common_name)
                    .into_string(),
            )
        }
        Err(e) => Html(
            templates::render_error(&format!("Failed to revoke certificate: {}", e)).into_string(),
        ),
    }
}

// ============================================================================
// API Handlers
// ============================================================================

/// Authenticate API request by verifying certificate exists and signature is valid
fn authenticate_api_request(
    requester_serial: &str,
    data_to_verify: &str,
    signature_b64: &str,
) -> Result<X509, String> {
    // Open storage to get requester's certificate
    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => return Err(format!("Failed to open storage: {}", e)),
    };

    // Get certificate by serial number
    let cert = match storage.get_certificate_by_serial(requester_serial) {
        Ok(Some(c)) => c,
        Ok(None) => return Err("Certificate not found".to_string()),
        Err(e) => return Err(format!("Failed to get certificate: {}", e)),
    };

    // Check if this is the Root CA (self-signed certificate)
    // Root CA is not allowed to make API requests
    // Compare subject and issuer by extracting CN values
    let subject_cn = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string());

    let issuer_cn = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string());

    // If subject == issuer, it's a self-signed certificate (Root CA)
    if subject_cn.is_some() && subject_cn == issuer_cn {
        return Err("Root CA certificate cannot make API requests".to_string());
    }

    // Check if certificate is revoked
    let is_revoked = match storage.is_certificate_revoked(requester_serial) {
        Ok(revoked) => revoked,
        Err(e) => return Err(format!("Failed to check revocation status: {}", e)),
    };

    if is_revoked {
        return Err("Certificate has been revoked".to_string());
    }

    // Decode signature from base64
    let signature =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64) {
            Ok(sig) => sig,
            Err(_) => return Err("Invalid base64 signature".to_string()),
        };

    // Verify signature with certificate's public key
    let public_key = match cert.public_key() {
        Ok(key) => key,
        Err(_) => return Err("Failed to extract public key".to_string()),
    };

    let signature_valid = match verify_signature(&public_key, data_to_verify.as_bytes(), &signature)
    {
        Ok(valid) => valid,
        Err(_) => return Err("Failed to verify signature".to_string()),
    };

    if !signature_valid {
        return Err("Invalid signature".to_string());
    }

    Ok(cert)
}

/// Encrypt hash with requester's public key for response authentication
fn encrypt_response_hash(data: &str, requester_cert: &X509) -> Result<String, String> {
    use openssl::hash::Hasher;
    use openssl::rsa::Padding;

    // Create SHA-256 hash of response data
    let mut hasher = match Hasher::new(MessageDigest::sha256()) {
        Ok(h) => h,
        Err(_) => return Err("Failed to create hasher".to_string()),
    };

    if let Err(_) = hasher.update(data.as_bytes()) {
        return Err("Failed to hash data".to_string());
    }

    let hash = match hasher.finish() {
        Ok(h) => h,
        Err(_) => return Err("Failed to finish hash".to_string()),
    };

    // Encrypt hash with requester's public key (RSA-OAEP)
    let public_key = match requester_cert.public_key() {
        Ok(key) => key,
        Err(_) => return Err("Failed to extract public key".to_string()),
    };

    let rsa = match public_key.rsa() {
        Ok(r) => r,
        Err(_) => return Err("Failed to get RSA key".to_string()),
    };

    let mut encrypted_hash = vec![0u8; rsa.size() as usize];
    let len = match rsa.public_encrypt(&hash, &mut encrypted_hash, Padding::PKCS1_OAEP) {
        Ok(l) => l,
        Err(_) => return Err("Failed to encrypt hash".to_string()),
    };

    encrypted_hash.truncate(len);

    // Encode as base64
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted_hash,
    ))
}

async fn api_get_certificate(
    Json(request): Json<GetCertificateRequest>,
) -> Json<GetCertificateResponse> {
    info!(
        "API get-certificate request from serial: {}, target CN: {}",
        request.requester_serial, request.target_cn
    );

    // Authenticate requester
    let requester_cert = match authenticate_api_request(
        &request.requester_serial,
        &request.target_cn,
        &request.signature,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            warn!("API authentication failed: {}", e);
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some(format!("Authentication failed: {}", e)),
            });
        }
    };

    // Open storage to get target certificate
    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open storage: {}", e);
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    // Get certificate by CN
    let target_cert = match storage.get_certificate_by_subject(&request.target_cn) {
        Ok(Some(cert)) => cert,
        Ok(None) => {
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Certificate not found".to_string()),
            });
        }
        Err(e) => {
            error!("Failed to get certificate: {}", e);
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    // Get serial number and check if revoked
    let serial = target_cert.serial_number();
    let serial_hex = match serial
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|s| s.to_string())
    {
        Ok(hex) => hex,
        Err(_) => {
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Failed to extract serial number".to_string()),
            });
        }
    };

    // Check if certificate is revoked
    let is_revoked = match storage.is_certificate_revoked(&serial_hex) {
        Ok(revoked) => revoked,
        Err(e) => {
            error!("Failed to check revocation status: {}", e);
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    if is_revoked {
        return Json(GetCertificateResponse {
            success: false,
            certificate_pem: None,
            serial_number: None,
            subject_cn: None,
            issuer_cn: None,
            not_before: None,
            not_after: None,
            encrypted_hash: None,
            error: Some("Certificate has been revoked".to_string()),
        });
    }

    // Extract certificate details
    let cert_pem = match target_cert.to_pem() {
        Ok(pem) => String::from_utf8_lossy(&pem).to_string(),
        Err(_) => {
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Failed to export certificate".to_string()),
            });
        }
    };

    let subject_cn = target_cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let issuer_cn = target_cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let not_before = target_cert.not_before().to_string();
    let not_after = target_cert.not_after().to_string();

    // Create response data for hashing
    let response_data = format!(
        "{}|{}|{}|{}|{}",
        serial_hex, subject_cn, issuer_cn, not_before, not_after
    );

    // Encrypt hash with requester's public key
    let encrypted_hash = match encrypt_response_hash(&response_data, &requester_cert) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to encrypt response hash: {}", e);
            return Json(GetCertificateResponse {
                success: false,
                certificate_pem: None,
                serial_number: None,
                subject_cn: None,
                issuer_cn: None,
                not_before: None,
                not_after: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    info!(
        "API get-certificate successful: returned certificate for {}",
        subject_cn
    );

    Json(GetCertificateResponse {
        success: true,
        certificate_pem: Some(cert_pem),
        serial_number: Some(serial_hex),
        subject_cn: Some(subject_cn),
        issuer_cn: Some(issuer_cn),
        not_before: Some(not_before),
        not_after: Some(not_after),
        encrypted_hash: Some(encrypted_hash),
        error: None,
    })
}

async fn api_verify_certificate(
    Json(request): Json<VerifyCertificateRequest>,
) -> Json<VerifyCertificateResponse> {
    info!(
        "API verify-certificate request from serial: {}, target serial: {}",
        request.requester_serial, request.target_serial
    );

    // Authenticate requester
    let requester_cert = match authenticate_api_request(
        &request.requester_serial,
        &request.target_serial,
        &request.signature,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            warn!("API authentication failed: {}", e);
            return Json(VerifyCertificateResponse {
                success: false,
                valid: None,
                serial_number: None,
                subject_cn: None,
                not_before: None,
                not_after: None,
                revoked: None,
                encrypted_hash: None,
                error: Some(format!("Authentication failed: {}", e)),
            });
        }
    };

    // Open storage to get target certificate
    let storage = match crate::storage::Storage::<crate::storage::Ready>::open() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open storage: {}", e);
            return Json(VerifyCertificateResponse {
                success: false,
                valid: None,
                serial_number: None,
                subject_cn: None,
                not_before: None,
                not_after: None,
                revoked: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    // Get certificate by serial number
    let target_cert = match storage.get_certificate_by_serial(&request.target_serial) {
        Ok(Some(cert)) => cert,
        Ok(None) => {
            return Json(VerifyCertificateResponse {
                success: false,
                valid: Some(false),
                serial_number: Some(request.target_serial.clone()),
                subject_cn: None,
                not_before: None,
                not_after: None,
                revoked: None,
                encrypted_hash: None,
                error: Some("Certificate not found".to_string()),
            });
        }
        Err(e) => {
            error!("Failed to get certificate: {}", e);
            return Json(VerifyCertificateResponse {
                success: false,
                valid: None,
                serial_number: None,
                subject_cn: None,
                not_before: None,
                not_after: None,
                revoked: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    // Check if certificate is revoked
    let is_revoked = match storage.is_certificate_revoked(&request.target_serial) {
        Ok(revoked) => revoked,
        Err(e) => {
            error!("Failed to check revocation status: {}", e);
            return Json(VerifyCertificateResponse {
                success: false,
                valid: None,
                serial_number: None,
                subject_cn: None,
                not_before: None,
                not_after: None,
                revoked: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    // Extract certificate details
    let subject_cn = target_cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let not_before = target_cert.not_before().to_string();
    let not_after = target_cert.not_after().to_string();

    // Check if certificate is currently valid (dates)
    use openssl::asn1::Asn1Time;
    let now = Asn1Time::days_from_now(0).unwrap();
    let date_valid = target_cert.not_before() <= &now && &now <= target_cert.not_after();

    let is_valid = date_valid && !is_revoked;

    // Create response data for hashing
    let response_data = format!(
        "{}|{}|{}|{}|{}|{}",
        request.target_serial, subject_cn, not_before, not_after, is_valid, is_revoked
    );

    // Encrypt hash with requester's public key
    let encrypted_hash = match encrypt_response_hash(&response_data, &requester_cert) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to encrypt response hash: {}", e);
            return Json(VerifyCertificateResponse {
                success: false,
                valid: None,
                serial_number: None,
                subject_cn: None,
                not_before: None,
                not_after: None,
                revoked: None,
                encrypted_hash: None,
                error: Some("Internal server error".to_string()),
            });
        }
    };

    info!(
        "API verify-certificate successful: certificate {} is valid={}, revoked={}",
        subject_cn, is_valid, is_revoked
    );

    Json(VerifyCertificateResponse {
        success: true,
        valid: Some(is_valid),
        serial_number: Some(request.target_serial),
        subject_cn: Some(subject_cn),
        not_before: Some(not_before),
        not_after: Some(not_after),
        revoked: Some(is_revoked),
        encrypted_hash: Some(encrypted_hash),
        error: None,
    })
}
