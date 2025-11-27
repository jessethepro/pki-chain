use libblockchainstor::BlockchainDb;
use std::sync::Arc;
use anyhow::Result;

mod pfx_key;
mod app_key_store;

use app_key_store::AppKeyStore;

fn main() -> Result<()> {
    // Load application key store at startup
    // In production, get password from environment variable or secure config
    let app_pfx_password = std::env::var("APP_PFX_PASSWORD")
        .unwrap_or_else(|_| {
            eprintln!("Warning: APP_PFX_PASSWORD not set, using default");
            "default-password".to_string()
        });
    
    let app_key_store = Arc::new(
        AppKeyStore::load_from_pfx("key/pki-chain-app.pfx", &app_pfx_password)?
    );
    
    println!("Application key store loaded successfully");
    println!("Derived password hash: {}", app_key_store.get_derived_password());
    
    // Open blockchain databases
    let _certificate_chain = BlockchainDb::open("../data/certificates")
        .expect("Failed to open blockchain database");
    let _pfx_chain = BlockchainDb::open("../data/pfx")
        .expect("Failed to open blockchain database");
    
    println!("Blockchain databases opened successfully");
    
    // The app_key_store can be cloned (Arc) and passed to other parts of the application
    // The private key will be securely zeroized when the last Arc reference is dropped
    
    Ok(())
}
