use crate::configs::AppConfig;
use crate::protocol::{Protocol, Request, Response};
use crate::storage::Storage;
use axum::{routing::get, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::fs::ServeDir;

#[derive(Serialize)]
struct PKIStatusResponse {
    message: String,
    status: String,
    total_certificates: u64,
    total_keys: u64,
    tracked_subject_names: usize,
    certificate_chain_valid: bool,
    private_key_chain_valid: bool,
    pki_chain_in_sync: bool,
}

#[derive(Deserialize)]
struct CertRequest {
    subject_cn: String,
    issuer_cn: String,
    organization: String,
    organizational_unit: Option<String>,
    locality: Option<String>,
    state: Option<String>,
    country: Option<String>,
    validity_days: u32,
}

#[derive(Serialize)]
struct CertResponse {
    success: bool,
    message: String,
    certificate: Option<String>,
    subject_dn: String,
    issuer_dn: String,
}

pub fn start_webserver(_default_configs: AppConfig, storage: Storage) {
    let protocol = Arc::new(Protocol::new(storage));
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    rt.block_on(async {
        let protocol_clone = Arc::clone(&protocol);
        let app = Router::new()
            .route(
                "/api/status",
                get(move || get_pki_status(Arc::clone(&protocol_clone))),
            )
            .fallback_service(ServeDir::new("web_root"));

        // Configure TLS with generated certificates
        let config = RustlsConfig::from_pem_file(
            "web_certs/server/chain.pem",
            "web_certs/server/server.key",
        )
        .await
        .expect("Failed to load TLS certificates. Run ./generate-certs.sh first.");

        let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

        println!("🔒 HTTPS Server starting...");
        println!("   Address: https://localhost:3000");
        println!("   Serving static files from web_root/");
        println!("   API endpoint: POST /api/generate-cert");
        println!("\n📜 Using certificates:");
        println!("   Certificate chain: certs/server/chain.pem");
        println!("   Private key: certs/server/server.key");
        println!("\n⚠️  Make sure you've installed the root CA:");
        println!("   - System: Already done if you ran the script");
        println!("   - Firefox: See instructions from generate-certs.sh");
        println!("\n✅ Server ready!\n");

        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
}

async fn get_pki_status(protocol: Arc<Protocol>) -> Json<PKIStatusResponse> {
    match protocol.process_request(Request::PKIStatus) {
        Ok(Response::PKIStatus {
            message,
            status,
            total_certificates,
            total_keys,
            tracked_subject_names,
            certificate_chain_valid,
            private_key_chain_valid,
            pki_chain_in_sync,
        }) => Json(PKIStatusResponse {
            message,
            status,
            total_certificates,
            total_keys,
            tracked_subject_names,
            certificate_chain_valid,
            private_key_chain_valid,
            pki_chain_in_sync,
        }),
        _ => Json(PKIStatusResponse {
            message: "Failed to get PKI status".to_string(),
            status: "Error".to_string(),
            total_certificates: 0,
            total_keys: 0,
            tracked_subject_names: 0,
            certificate_chain_valid: false,
            private_key_chain_valid: false,
            pki_chain_in_sync: false,
        }),
    }
}
