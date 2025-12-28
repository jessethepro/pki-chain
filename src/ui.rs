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
use openssl::nid::Nid;
use pki_chain::pki_generator::{CertificateData, CertificateDataType};
use pki_chain::protocol::{Protocol, Request, Response};
use pki_chain::storage::Storage;
use pki_chain::storage::ROOT_CA_SUBJECT_COMMON_NAME;

/// Initialize and run the TUI application
pub fn run_ui(storage: Storage) {
    let protocol = Protocol::new(storage);

    let mut siv = Cursive::default();

    // Store protocol in user data
    siv.set_user_data(protocol);

    // Build main menu
    build_main_menu(&mut siv);

    // Run the application
    siv.run();
}

fn build_main_menu(siv: &mut Cursive) {
    let mut select = SelectView::new();

    select.add_item("Create Intermediate Certificate", 1);
    select.add_item("Create User Certificate", 2);
    select.add_item("Validate Blockchain", 3);
    select.add_item("View System Status", 4);
    select.add_item("Exit", 5);

    select.set_on_submit(|s, item: &usize| match item {
        1 => show_create_intermediate_form(s),
        2 => show_create_user_form(s),
        3 => show_validation(s),
        4 => show_system_status(s),
        5 => s.quit(),
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
    let protocol = match siv.user_data::<Protocol>() {
        Some(p) => p,
        None => {
            show_error(siv, "Failed to access protocol");
            return;
        }
    };

    let result = validate_blockchain(&protocol);

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
    let protocol = match siv.user_data::<Protocol>() {
        Some(p) => p,
        None => {
            show_error(siv, "Failed to access protocol");
            return;
        }
    };

    match get_system_status(&protocol) {
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

    // Get protocol and clone data before mutably borrowing siv
    let (cn_copy, org_copy, ou_copy, locality_copy, state_copy, country_copy) = (
        cn.clone(),
        org.clone(),
        ou.clone(),
        locality.clone(),
        state.clone(),
        country.clone(),
    );

    let result = siv.user_data::<Protocol>().and_then(|protocol| {
        create_intermediate_certificate(
            protocol,
            cn_copy,
            org_copy,
            ou_copy,
            locality_copy,
            state_copy,
            country_copy,
            validity_days,
        )
        .ok()
    });

    // Close the form dialog
    siv.pop_layer();

    // Show result
    match result {
        Some(height) => {
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
        None => {
            show_error(siv, "Failed to create certificate or access protocol");
        }
    }
}

fn create_intermediate_certificate(
    protocol: &Protocol,
    cn: String,
    org: String,
    ou: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
) -> Result<u64> {
    let certificate_data = CertificateData {
        subject_common_name: cn,
        issuer_common_name: ROOT_CA_SUBJECT_COMMON_NAME.to_string(),
        organization: org,
        organizational_unit: ou,
        locality,
        state,
        country,
        validity_days,
        cert_type: CertificateDataType::IntermediateCA,
    };

    let request = Request::CreateIntermediate { certificate_data };

    match protocol.process_request(request)? {
        Response::CreateIntermediate { height, .. } => Ok(height),
        Response::Error { message } => Err(anyhow::anyhow!(message)),
        _ => Err(anyhow::anyhow!("Unexpected response type")),
    }
}

fn validate_blockchain(protocol: &Protocol) -> Result<String> {
    let request = Request::PKIStatus;

    match protocol.process_request(request)? {
        Response::PKIStatus {
            total_certificates,
            total_keys,
            tracked_subject_names,
            pki_chain_in_sync,
            ..
        } => {
            if pki_chain_in_sync {
                Ok(format!(
                    "✓ Blockchain Validation Successful\n\n\
                     Total Certificates: {}\n\
                     Total Private Keys: {}\n\
                     Tracked Subject Names: {}\n\n\
                     All blocks verified and consistent.",
                    total_certificates, total_keys, tracked_subject_names
                ))
            } else {
                Err(anyhow::anyhow!("Blockchain validation failed"))
            }
        }
        Response::Error { message } => Err(anyhow::anyhow!(message)),
        _ => Err(anyhow::anyhow!("Unexpected response type")),
    }
}

fn get_system_status(protocol: &Protocol) -> Result<String> {
    let request = Request::PKIStatus;

    match protocol.process_request(request)? {
        Response::PKIStatus {
            total_certificates,
            total_keys,
            tracked_subject_names,
            pki_chain_in_sync,
            ..
        } => {
            let is_empty = total_certificates == 0;
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
                if pki_chain_in_sync {
                    "✓ Yes"
                } else {
                    "✗ No"
                },
                total_certificates,
                total_keys,
                tracked_subject_names
            ))
        }
        Response::Error { message } => Err(anyhow::anyhow!(message)),
        _ => Err(anyhow::anyhow!("Unexpected response type")),
    }
}

fn show_create_user_form(siv: &mut Cursive) {
    let protocol = match siv.user_data::<Protocol>() {
        Some(p) => p,
        None => {
            show_error(siv, "Failed to access protocol");
            return;
        }
    };

    // Get list of intermediate CAs
    let intermediates = match get_intermediate_certificates(&protocol) {
        Ok(certs) => certs,
        Err(e) => {
            show_error(siv, &format!("Failed to list intermediate CAs: {}", e));
            return;
        }
    };

    if intermediates.is_empty() {
        show_error(
            siv,
            "No intermediate CAs found. Please create an Intermediate CA first.",
        );
        return;
    }

    // Create SelectView for intermediate CAs
    let mut issuer_select = SelectView::new();
    for (cn, height) in intermediates {
        issuer_select.add_item(format!("{} (Height: {})", cn, height), cn);
    }

    let form = LinearLayout::vertical()
        .child(TextView::new("Enter User Certificate Details:"))
        .child(TextView::new(""))
        .child(TextView::new("Select Issuer (Intermediate CA):"))
        .child(Panel::new(issuer_select.with_name("issuer").scrollable()).fixed_height(5))
        .child(TextView::new(""))
        .child(TextView::new("Common Name (CN):"))
        .child(EditView::new().with_name("user_cn").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Organization (O):"))
        .child(EditView::new().with_name("user_org").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Organizational Unit (OU):"))
        .child(EditView::new().with_name("user_ou").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Locality (L):"))
        .child(EditView::new().with_name("user_locality").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("State/Province (ST):"))
        .child(EditView::new().with_name("user_state").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Country (C) - 2 letter code:"))
        .child(EditView::new().with_name("user_country").fixed_width(40))
        .child(TextView::new(""))
        .child(TextView::new("Validity (days):"))
        .child(
            EditView::new()
                .content("365")
                .with_name("user_validity")
                .fixed_width(40),
        );

    siv.add_layer(
        Dialog::around(ScrollView::new(form))
            .title("Create User Certificate")
            .button("Create", |s| {
                handle_create_user(s);
            })
            .button("Cancel", |s| {
                s.pop_layer();
            }),
    );
}

fn get_intermediate_certificates(protocol: &Protocol) -> Result<Vec<(String, u64)>> {
    let request = Request::ListCertificates {
        filter: "Intermediate".to_string(),
    };

    match protocol.process_request(request)? {
        Response::ListCertificates { certificates, .. } => {
            // Get actual heights from the storage's subject_name_to_height map
            let mut intermediates = Vec::new();

            for cert in certificates {
                let subject_common_name = cert
                    .subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok())
                    .map(|data| data.to_string())
                    .unwrap_or_default();
                if let Some(height) = protocol
                    .storage
                    .subject_name_to_height
                    .lock()
                    .unwrap()
                    .get(&subject_common_name)
                {
                    intermediates.push((subject_common_name, *height));
                }
            }

            Ok(intermediates)
        }
        Response::Error { message } => Err(anyhow::anyhow!(message)),
        _ => Err(anyhow::anyhow!("Unexpected response type")),
    }
}

fn handle_create_user(siv: &mut Cursive) {
    // Extract issuer selection
    let issuer_cn = match siv.call_on_name(
        "issuer",
        |view: &mut SelectView<String>| -> Option<String> {
            view.selection().map(|rc| (*rc).clone())
        },
    ) {
        Some(Some(cn)) => cn,
        _ => {
            show_error(siv, "Please select an issuer CA");
            return;
        }
    };

    // Extract form values
    let cn = siv
        .call_on_name("user_cn", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let org = siv
        .call_on_name("user_org", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let ou = siv
        .call_on_name("user_ou", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let locality = siv
        .call_on_name("user_locality", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let state = siv
        .call_on_name("user_state", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let country = siv
        .call_on_name("user_country", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let validity_str = siv
        .call_on_name("user_validity", |view: &mut EditView| view.get_content())
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

    // Get protocol and clone data before mutably borrowing siv
    let (issuer_cn_copy, cn_copy, org_copy, ou_copy, locality_copy, state_copy, country_copy) = (
        issuer_cn.clone(),
        cn.clone(),
        org.clone(),
        ou.clone(),
        locality.clone(),
        state.clone(),
        country.clone(),
    );

    let result = siv.user_data::<Protocol>().and_then(|protocol| {
        create_user_certificate(
            protocol,
            issuer_cn_copy.clone(),
            cn_copy,
            org_copy,
            ou_copy,
            locality_copy,
            state_copy,
            country_copy,
            validity_days,
        )
        .ok()
    });

    // Close the form dialog
    siv.pop_layer();

    // Show result
    match result {
        Some(height) => {
            siv.add_layer(
                Dialog::text(format!(
                    "✓ User Certificate Created Successfully!\n\n\
                     Common Name: {}\n\
                     Issuer: {}\n\
                     Blockchain Height: {}\n\n\
                     The certificate has been stored in the blockchain.",
                    cn, issuer_cn, height
                ))
                .title("Success")
                .button("OK", |s| {
                    s.pop_layer();
                }),
            );
        }
        None => {
            show_error(siv, "Failed to create user certificate or access protocol");
        }
    }
}

fn create_user_certificate(
    protocol: &Protocol,
    issuer_cn: String,
    cn: String,
    org: String,
    ou: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
) -> Result<u64> {
    let certificate_data = CertificateData {
        subject_common_name: cn,
        issuer_common_name: issuer_cn,
        organization: org,
        organizational_unit: ou,
        locality,
        state,
        country,
        validity_days,
        cert_type: CertificateDataType::UserCert,
    };

    let request = Request::CreateUser { certificate_data };

    match protocol.process_request(request)? {
        Response::CreateUser { height, .. } => Ok(height),
        Response::Error { message } => Err(anyhow::anyhow!(message)),
        _ => Err(anyhow::anyhow!("Unexpected response type")),
    }
}
