use libblockchainstor::BlockchainDb;
use std::sync::Arc;
use std::io::{self, Write};
use anyhow::Result;

mod pfx_key;
mod app_key_store;
mod store_root_key;
mod store_root_cert;
mod store_intermediate_key;
mod store_user_key;
mod store_intermediate_cert;
mod store_user_cert;
mod statistics;
mod commands;

use app_key_store::AppKeyStore;
use commands::insert_root::handle_insert_root;
use commands::insert_intermediate::handle_insert_intermediate;
use commands::insert_user::handle_insert_user;
use statistics::print_blockchain_statistics;

fn main() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║     PKI BLOCKCHAIN CERTIFICATE MANAGEMENT SYSTEM           ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    
    // Step 1: Prompt for application PFX file
    print!("📁 Enter path to pki_chain_app.pfx: ");
    io::stdout().flush()?;
    let mut app_pfx_path = String::new();
    io::stdin().read_line(&mut app_pfx_path)?;
    let app_pfx_path = app_pfx_path.trim();
    
    // Step 2: Securely prompt for password
    let app_pfx_password = rpassword::prompt_password("🔑 Enter password for pki_chain_app.pfx: ")?;
    
    // Step 3: Load application key store
    println!("\n⏳ Loading application key store...");
    let app_key_store = Arc::new(
        AppKeyStore::load_from_pfx(app_pfx_path, &app_pfx_password)?
    );
    println!("✓ Application key store loaded successfully\n");
    
    // Step 4: Open blockchain databases
    println!("⏳ Opening blockchain databases...");
    let pfx_chain = BlockchainDb::open("../data/pfx")
        .expect("Failed to open PFX blockchain database");
    let certificate_chain = BlockchainDb::open("../data/certificates")
        .expect("Failed to open certificate blockchain database");
    println!("✓ Blockchain databases opened successfully\n");
    
    // Main loop
    loop {
        println!("\n┌────────────────────────────────────────────────────────────┐");
        println!("│ MAIN MENU                                                  │");
        println!("├────────────────────────────────────────────────────────────┤");
        println!("│ 1. Insert Certificate                                      │");
        println!("│ 2. View Statistics                                         │");
        println!("│ 3. Exit                                                    │");
        println!("└────────────────────────────────────────────────────────────┘");
        
        print!("\nSelect an option: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => {
                // Insert certificate workflow
                insert_certificate_workflow(&pfx_chain, &certificate_chain, &app_key_store)?;
            }
            "2" => {
                // View statistics
                print_blockchain_statistics(&pfx_chain, &certificate_chain)?;
            }
            "3" => {
                println!("\n👋 Goodbye!");
                break;
            }
            _ => {
                println!("\n❌ Invalid option. Please try again.");
            }
        }
    }
    
    Ok(())
}

fn insert_certificate_workflow(
    pfx_chain: &BlockchainDb,
    certificate_chain: &BlockchainDb,
    app_key_store: &AppKeyStore,
) -> Result<()> {
    // Step 1: Prompt for PFX file path
    print!("\n📁 Enter path to PFX file to insert: ");
    io::stdout().flush()?;
    let mut pfx_path = String::new();
    io::stdin().read_line(&mut pfx_path)?;
    let pfx_path = pfx_path.trim();
    
    // Step 2: Select certificate type
    println!("\n┌────────────────────────────────────────────────────────────┐");
    println!("│ SELECT CERTIFICATE TYPE                                    │");
    println!("├────────────────────────────────────────────────────────────┤");
    println!("│ 1. Root CA           (Creates genesis blocks)             │");
    println!("│ 2. Intermediate CA   (Requires Root CA exists)            │");
    println!("│ 3. User Certificate  (End-entity certificate)             │");
    println!("└────────────────────────────────────────────────────────────┘");
    
    print!("\nSelect certificate type: ");
    io::stdout().flush()?;
    let mut cert_type = String::new();
    io::stdin().read_line(&mut cert_type)?;
    
    match cert_type.trim() {
        "1" => {
            handle_insert_root(pfx_path, pfx_chain, certificate_chain, app_key_store)?;
        }
        "2" => {
            handle_insert_intermediate(pfx_path, pfx_chain, certificate_chain, app_key_store)?;
        }
        "3" => {
            handle_insert_user(pfx_path, pfx_chain, certificate_chain, app_key_store)?;
        }
        _ => {
            println!("\n❌ Invalid certificate type. Operation cancelled.");
        }
    }
    
    Ok(())
}
