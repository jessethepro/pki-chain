//! Maud HTML Templates for PKI Chain Web Interface
//!
//! This module contains all HTML rendering functions using the Maud templating engine.

use crate::configs::AppConfig;
use maud::{html, Markup, PreEscaped, DOCTYPE};

// ============================================================================
// Layout and Common Components
// ============================================================================

pub fn render_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style {
                    (PreEscaped(r#"
                        body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; background: rgb(46, 15, 92); color: #212529; }
                        .container { background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border: 1px solid #dee2e6; }
                        h1 { color: #000000; font-weight: 600; margin-bottom: 20px; }
                        h2 { color: #000000; font-weight: 600; margin-top: 30px; margin-bottom: 15px; }
                        h3 { color: #000000; font-weight: 600; }
                        form { margin: 20px 0; }
                        label { display: block; margin: 15px 0 5px; font-weight: 600; color: #000000; }
                        input, select { 
                            width: 100%; 
                            padding: 10px; 
                            margin: 5px 0; 
                            box-sizing: border-box; 
                            border: 2px solid #495057;
                            border-radius: 4px;
                            font-size: 14px;
                            background: #ffffff;
                            color: #000000;
                        }
                        input:focus, select:focus { 
                            outline: none; 
                            border-color: #0056b3; 
                            box-shadow: 0 0 0 3px rgba(0,86,179,0.1);
                        }
                        button { 
                            background: #0056b3; 
                            color: #ffffff; 
                            padding: 12px 24px; 
                            border: none; 
                            border-radius: 4px; 
                            cursor: pointer; 
                            margin: 10px 5px 0 0; 
                            font-weight: 600;
                            font-size: 15px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                        }
                        button:hover { 
                            background: #003d82; 
                            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
                        }
                        .success { 
                            background: #d4edda; 
                            color: #0f5132; 
                            padding: 15px; 
                            border-radius: 4px; 
                            margin: 20px 0; 
                            border: 2px solid #0f5132;
                            font-weight: 500;
                        }
                        .error { 
                            background: #f8d7da; 
                            color: #842029; 
                            padding: 15px; 
                            border-radius: 4px; 
                            margin: 20px 0; 
                            border: 2px solid #842029;
                            font-weight: 500;
                        }
                        .info { 
                            background: #cfe2ff; 
                            color: #084298; 
                            padding: 15px; 
                            border-radius: 4px; 
                            margin: 20px 0; 
                            border: 2px solid #084298;
                            font-weight: 500;
                        }
                        .config { 
                            background: #f8f9fa; 
                            padding: 15px; 
                            border-radius: 4px; 
                            margin: 10px 0; 
                            font-family: monospace; 
                            border: 2px solid #495057;
                            color: #000000;
                            font-size: 14px;
                        }
                        nav { margin: 20px 0; }
                        nav a { 
                            margin-right: 15px; 
                            color: #0056b3; 
                            text-decoration: none; 
                            font-weight: 600;
                        }
                        nav a:hover { 
                            text-decoration: underline; 
                            color: #003d82;
                        }
                        p { color: #212529; line-height: 1.6; }
                        ul { color: #212529; line-height: 1.8; }
                        li { margin: 8px 0; }
                    "#))
                }
            }
            body {
                div class="container" {
                    (content)
                }
            }
        }
    }
}

// ============================================================================
// Initialization Flow Templates
// ============================================================================

pub fn render_initialize_page() -> Markup {
    let config = AppConfig::load().unwrap_or_else(|_| panic!("Failed to load config"));

    render_layout(
        "Initialize PKI System",
        html! {
            h1 { "🔧 Initialize PKI Certificate Authority" }

            div class="info" {
                p { "The PKI system has not been initialized. Please review the configuration below and set a password for the Root CA private key." }
            }

            h2 { "Current Configuration" }
            div class="config" {
                p { "Root CA Common Name: " (config.root_ca_defaults.root_ca_common_name) }
                p { "Organization: " (config.root_ca_defaults.root_ca_organization) }
                p { "Organizational Unit: " (config.root_ca_defaults.root_ca_organizational_unit) }
                p { "Country: " (config.root_ca_defaults.root_ca_country) }
                p { "State: " (config.root_ca_defaults.root_ca_state) }
                p { "Locality: " (config.root_ca_defaults.root_ca_locality) }
                p { "Validity: " (config.root_ca_defaults.root_ca_validity_days) " days" }
            }

            form method="POST" action="/initialize" {
                label for="root_ca_password" { "Root CA Private Key Password:" }
                input type="password" id="root_ca_password" name="root_ca_password" required minlength="8" placeholder="Enter a strong password (min 8 characters)";

                button type="submit" { "Initialize PKI System" }
            }
        },
    )
}

pub fn render_create_admin_page() -> Markup {
    render_layout(
        "Create Admin User",
        html! {
            h1 { "👤 Create First Admin User" }

            div class="info" {
                p { "The Root CA has been created. Please create the first administrator account." }
                p { "This will automatically create an Intermediate CA for the admin user." }
            }

            form method="POST" action="/create-admin" {
                label for="common_name" { "Common Name (CN):" }
                input type="text" id="common_name" name="common_name" required placeholder="admin@example.com";

                label for="organization" { "Organization (O):" }
                input type="text" id="organization" name="organization" required placeholder="Example Corp";

                label for="organizational_unit" { "Organizational Unit (OU):" }
                input type="text" id="organizational_unit" name="organizational_unit" required placeholder="IT Department";

                label for="locality" { "Locality (L):" }
                input type="text" id="locality" name="locality" required placeholder="San Francisco";

                label for="state" { "State/Province (ST):" }
                input type="text" id="state" name="state" required placeholder="California";

                label for="country" { "Country (C - 2 letters):" }
                input type="text" id="country" name="country" required minlength="2" maxlength="2" placeholder="US";

                button type="submit" { "Create Admin User" }
            }
        },
    )
}

// ============================================================================
// Authentication Templates
// ============================================================================

pub fn render_login_page() -> Markup {
    render_layout(
        "Login",
        html! {
            h1 { "🔐 Certificate Authority Login" }

            div class="info" {
                p { "Please authenticate with your X.509 certificate, private key, and Root CA password." }
                p { small { "Upload the certificate (.crt) and private key (.key) files you downloaded during admin creation." } }
            }

            form method="POST" action="/login" enctype="multipart/form-data" {
                label for="certificate" { "X.509 Certificate (.crt):" }
                input type="file" id="certificate" name="certificate" accept=".crt,.pem" required;

                label for="private_key" { "Private Key (.key):" }
                input type="file" id="private_key" name="private_key" accept=".key,.pem" required;

                label for="root_ca_password" { "Root CA Password:" }
                input type="password" id="root_ca_password" name="root_ca_password" required;

                button type="submit" { "Authenticate" }
            }

            div class="info" style="margin-top: 20px;" {
                h3 { "🔒 Security Notes" }
                ul {
                    li { "Certificate and private key are validated cryptographically" }
                    li { "Challenge-response authentication proves key ownership" }
                    li { "Files are processed in memory and never stored on server" }
                    li { "Root CA password is required for admin operations" }
                }
            }
        },
    )
}

// ============================================================================
// Admin Dashboard Templates
// ============================================================================

pub fn render_admin_dashboard(user_cn: &str) -> Markup {
    render_layout(
        "Admin Dashboard",
        html! {
            h1 { "📊 Admin Dashboard" }

            div class="success" {
                p { "Welcome, " (user_cn) "!" }
            }

            nav {
                a href="/admin/create-user" { "Create User Certificate" }
                a href="/admin/create-intermediate" { "Create Intermediate CA" }
                a href="/admin/status" { "View Status" }
            }

            form method="POST" action="/logout" {
                button type="submit" { "Logout" }
            }

            h2 { "Quick Actions" }
            p { "Use the navigation links above to manage certificates and view system status." }
        },
    )
}

pub fn render_create_user_page() -> Markup {
    render_layout(
        "Create User Certificate",
        html! {
            h1 { "Create User Certificate" }
            p { "User certificate creation form will be implemented here." }
            p { a href="/admin/dashboard" { "Back to Dashboard" } }
        },
    )
}

pub fn render_create_intermediate_page() -> Markup {
    render_layout(
        "Create Intermediate CA",
        html! {
            h1 { "Create Intermediate CA" }
            p { "Intermediate CA creation form will be implemented here." }
            p { a href="/admin/dashboard" { "Back to Dashboard" } }
        },
    )
}

pub fn render_status_page() -> Markup {
    render_layout(
        "System Status",
        html! {
            h1 { "System Status" }
            p { "System status information will be displayed here." }
            p { a href="/admin/dashboard" { "Back to Dashboard" } }
        },
    )
}

// ============================================================================
// Utility Templates (Success/Error/Downloads)
// ============================================================================

pub fn render_success(message: &str) -> Markup {
    render_layout(
        "Success",
        html! {
            div class="success" {
                h2 { "✅ Success" }
                p { (message) }
            }
            p { a href="/" { "Continue" } }
        },
    )
}

pub fn render_admin_created_with_downloads(
    cert_filename: &str,
    key_filename: &str,
    cert_b64: &str,
    key_b64: &str,
) -> Markup {
    render_layout(
        "Admin User Created",
        html! {
            div class="success" {
                h2 { "✅ Admin User Created Successfully!" }
                p { "Your admin certificate and private key are ready for download." }
            }

            div class="info" {
                h3 { "⬇️ Download Your Credentials" }
                p { "Please download both files and store them securely. You will need them to login." }

                p {
                    a download=(cert_filename) href={"data:application/x-pem-file;base64," (cert_b64)} {
                        button { "📄 Download Certificate (.crt)" }
                    }
                }

                p {
                    a download=(key_filename) href={"data:application/x-pem-file;base64," (key_b64)} {
                        button { "🔑 Download Private Key (.key)" }
                    }
                }
            }

            div class="info" {
                h3 { "⚠️ Important Security Notes" }
                ul {
                    li { "Store your private key in a secure location" }
                    li { "Never share your private key with anyone" }
                    li { "You will need both files to login to the admin panel" }
                    li { "The private key is in PKCS#8 format (unencrypted)" }
                }
            }

            p style="margin-top: 30px;" {
                a href="/" { button { "Continue to Login" } }
            }
        },
    )
}

pub fn render_error(message: &str) -> Markup {
    render_layout(
        "Error",
        html! {
            div class="error" {
                h2 { "❌ Error" }
                p { (message) }
            }
            p { a href="/" { "Go Back" } }
        },
    )
}
