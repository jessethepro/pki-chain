//! Terminal User Interface Module
//!
//! Provides a cursive-based TUI for managing the PKI Chain application.
//! This module implements an interactive terminal interface for certificate management,
//! blockchain validation, and system monitoring.
//!
//! # Features
//!
//! - **Main Menu Navigation**: User-friendly selection menu with arrow key navigation
//! - **Certificate Creation Forms**: Multi-field forms for Intermediate CA generation
//! - **Validation Views**: Display blockchain integrity check results
//! - **System Status Dashboard**: Real-time blockchain statistics and certificate tracking
//! - **Error Handling**: User-friendly error dialogs with contextual messages
//!
//! # Architecture
//!
//! The UI module uses the cursive library for terminal rendering and event handling:
//! - `SelectView`: Menu navigation with keyboard controls
//! - `EditView`: Text input fields with named access
//! - `Dialog`: Modal dialogs for forms and messages
//! - `LinearLayout`: Vertical/horizontal view composition
//! - `ScrollView`: Scrollable content for long text
//!
//! # Form Validation
//!
//! Certificate creation forms include comprehensive validation:
//! - Required field checking (all DN fields must be non-empty)
//! - Country code format validation (exactly 2 letters)
//! - Numeric validity period validation (positive integer)
//! - Duplicate subject name detection via storage HashMap lookup
//!
//! # Threading Model
//!
//! The UI runs on the main thread. Storage operations are performed synchronously
//! within UI callbacks. The `Arc<Storage>` allows safe sharing across the application
//! and potential future async operations.
//!
//! # Example Usage
//!
//! ```no_run
//! use pki_chain::storage::Storage;
//! use std::sync::Arc;
//!
//! // Initialize storage
//! let storage = Arc::new(Storage::new("key/app.key").unwrap());
//! storage.initialize().unwrap();
//!
//! // Launch TUI (blocks until user exits)
//! pki_chain::ui::run_ui(storage);
//! ```

use anyhow::Result;
use cursive::view::{Nameable, Resizable, Scrollable};
use cursive::views::{Dialog, EditView, LinearLayout, Panel, ScrollView, SelectView, TextView};
use cursive::{Cursive, CursiveExt};
use pki_chain::generate_intermediate_ca::RsaIntermediateCABuilder;
use pki_chain::storage::Storage;
use std::sync::Arc;

/// Initialize and run the TUI application
pub fn run_ui(storage: Arc<Storage>) {
    let mut siv = Cursive::default();

    // Store storage in user data
    siv.set_user_data(storage);

    // Build main menu
    build_main_menu(&mut siv);

    // Run the application
    siv.run();
}

fn build_main_menu(siv: &mut Cursive) {
    let mut select = SelectView::new();

    select.add_item("Create Intermediate Certificate", 1);
    select.add_item("Validate Blockchain", 2);
    select.add_item("View System Status", 3);
    select.add_item("Exit", 4);

    select.set_on_submit(|s, item: &usize| match item {
        1 => show_create_intermediate_form(s),
        2 => show_validation(s),
        3 => show_system_status(s),
        4 => s.quit(),
        _ => {}
    });

    let layout = LinearLayout::vertical()
        .child(TextView::new(
            "PKI Chain - Blockchain Certificate Authority",
        ))
        .child(TextView::new(""))
        .child(Panel::new(select.scrollable()).title("Main Menu"));

    siv.add_layer(Dialog::around(layout).title("PKI Chain Application"));
}

fn show_validation(siv: &mut Cursive) {
    let storage = match siv.user_data::<Arc<Storage>>() {
        Some(s) => Arc::clone(s),
        None => {
            show_error(siv, "Failed to access storage");
            return;
        }
    };

    let result = validate_blockchain(&storage);

    match result {
        Ok(msg) => {
            siv.add_layer(
                Dialog::around(ScrollView::new(TextView::new(msg)))
                    .title("Blockchain Validation")
                    .button("OK", |s| {
                        s.pop_layer();
                    }),
            );
        }
        Err(e) => show_error(siv, &format!("Validation failed: {}", e)),
    }
}

fn show_system_status(siv: &mut Cursive) {
    let storage = match siv.user_data::<Arc<Storage>>() {
        Some(s) => Arc::clone(s),
        None => {
            show_error(siv, "Failed to access storage");
            return;
        }
    };

    match get_system_status(&storage) {
        Ok(status) => {
            siv.add_layer(
                Dialog::around(ScrollView::new(TextView::new(status)))
                    .title("System Status")
                    .button("OK", |s| {
                        s.pop_layer();
                    }),
            );
        }
        Err(e) => show_error(siv, &format!("Failed to get status: {}", e)),
    }
}

fn show_error(siv: &mut Cursive, message: &str) {
    siv.add_layer(Dialog::text(message).title("Error").button("OK", |s| {
        s.pop_layer();
    }));
}

fn show_create_intermediate_form(siv: &mut Cursive) {
    let form = LinearLayout::vertical()
        .child(TextView::new("Enter Intermediate CA Details:"))
        .child(TextView::new(""))
        .child(TextView::new("Common Name (CN):"))
        .child(EditView::new().with_name("cn").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Organization (O):"))
        .child(EditView::new().with_name("org").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Organizational Unit (OU):"))
        .child(EditView::new().with_name("ou").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Locality (L):"))
        .child(EditView::new().with_name("locality").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("State/Province (ST):"))
        .child(EditView::new().with_name("state").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Country (C) - 2 letter code:"))
        .child(EditView::new().with_name("country").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Validity (days):"))
        .child(
            EditView::new()
                .content("1825")
                .with_name("validity")
                .fixed_width(40),
        );

    siv.add_layer(
        Dialog::around(form)
            .title("Create Intermediate CA Certificate")
            .button("Create", |s| {
                handle_create_intermediate(s);
            })
            .button("Cancel", |s| {
                s.pop_layer();
            }),
    );
}

fn handle_create_intermediate(siv: &mut Cursive) {
    // Extract form values
    let cn = siv
        .call_on_name("cn", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let org = siv
        .call_on_name("org", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let ou = siv
        .call_on_name("ou", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let locality = siv
        .call_on_name("locality", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let state = siv
        .call_on_name("state", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let country = siv
        .call_on_name("country", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let validity_str = siv
        .call_on_name("validity", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();

    // Validate inputs
    if cn.is_empty()
        || org.is_empty()
        || ou.is_empty()
        || locality.is_empty()
        || state.is_empty()
        || country.is_empty()
    {
        show_error(siv, "All fields are required!");
        return;
    }

    if country.len() != 2 {
        show_error(siv, "Country code must be exactly 2 letters!");
        return;
    }

    let validity_days = match validity_str.parse::<u32>() {
        Ok(days) if days > 0 => days,
        _ => {
            show_error(siv, "Validity must be a positive number!");
            return;
        }
    };

    // Get storage
    let storage = match siv.user_data::<Arc<Storage>>() {
        Some(s) => Arc::clone(s),
        None => {
            show_error(siv, "Failed to access storage");
            return;
        }
    };

    // Close the form dialog
    siv.pop_layer();

    // Create the certificate
    match create_intermediate_certificate(
        &storage,
        cn.clone(),
        org,
        ou,
        locality,
        state,
        country,
        validity_days,
    ) {
        Ok(height) => {
            siv.add_layer(
                Dialog::text(format!(
                    "✓ Intermediate CA Created Successfully!\n\n\
                     Common Name: {}\n\
                     Blockchain Height: {}\n\n\
                     The certificate has been stored in the blockchain.",
                    cn, height
                ))
                .title("Success")
                .button("OK", |s| {
                    s.pop_layer();
                }),
            );
        }
        Err(e) => {
            show_error(siv, &format!("Failed to create certificate: {}", e));
        }
    }
}

fn create_intermediate_certificate(
    storage: &Storage,
    cn: String,
    org: String,
    ou: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
) -> Result<u64> {
    // Get Root CA from blockchain (height 0)
    let root_block = storage.certificate_chain.get_block_by_height(0)?;
    let root_cert = openssl::x509::X509::from_pem(&root_block.block_data)?;

    let root_key_block = storage.private_chain.get_block_by_height(0)?;
    let root_key = openssl::pkey::PKey::private_key_from_der(&root_key_block.block_data)?;

    // Generate intermediate certificate
    let (int_key, int_cert) = RsaIntermediateCABuilder::new(root_key, root_cert)
        .subject_common_name(cn)
        .organization(org)
        .organizational_unit(ou)
        .locality(locality)
        .state(state)
        .country(country)
        .validity_days(validity_days)
        .build()?;

    // Store in blockchain
    let height = storage.store_key_certificate(&int_key, &int_cert)?;

    Ok(height)
}

fn validate_blockchain(storage: &Storage) -> Result<String> {
    if storage.is_empty()? {
        return Ok("Blockchain is empty. No data to validate.".to_string());
    }

    if storage.validate()? {
        let cert_count = storage.certificate_chain.block_count()?;
        let key_count = storage.private_chain.block_count()?;
        let subject_count = storage.subject_name_to_height.lock().unwrap().len();

        Ok(format!(
            "✓ Blockchain Validation Successful\n\n\
             Total Certificates: {}\n\
             Total Private Keys: {}\n\
             Tracked Subject Names: {}\n\n\
             All blocks verified and consistent.",
            cert_count, key_count, subject_count
        ))
    } else {
        Err(anyhow::anyhow!("Blockchain validation failed"))
    }
}

fn get_system_status(storage: &Storage) -> Result<String> {
    let cert_count = storage.certificate_chain.block_count()?;
    let key_count = storage.private_chain.block_count()?;
    let subject_count = storage.subject_name_to_height.lock().unwrap().len();
    let is_empty = storage.is_empty()?;
    let is_valid = if !is_empty { storage.validate()? } else { true };

    Ok(format!(
        "PKI Chain System Status\n\
         ═══════════════════════\n\n\
         Storage Status: {}\n\
         Blockchain Valid: {}\n\n\
         Certificates: {}\n\
         Private Keys: {}\n\
         Subject Names: {}\n\n\
         Socket Server: Disabled\n\
         Application Key: key/pki-chain-app.key",
        if is_empty { "Empty" } else { "Initialized" },
        if is_valid { "✓ Yes" } else { "✗ No" },
        cert_count,
        key_count,
        subject_count
    ))
}
