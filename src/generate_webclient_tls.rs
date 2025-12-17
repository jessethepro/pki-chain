//! TLS Server Certificate Generation Module for PKIWebClient
//!
//! This module generates TLS/HTTPS server certificates signed by an Intermediate CA,
//! which creates a complete certificate chain validated by the Root CA:
//!
//! **Certificate Chain**: Root CA → Intermediate CA → TLS Server Certificate
//!
//! The generated certificates are specifically for securing the PKIWebClient HTTPS server,
//! enabling encrypted communication between clients and the web interface.
//!
//! # X.509 Extensions
//! TLS server certificates include:
//! - **Key Usage**: `digitalSignature`, `keyEncipherment` (for TLS handshakes and RSA key exchange)
//! - **Extended Key Usage**: `serverAuth` (explicitly marks certificate for TLS server authentication)
//! - **Subject Alternative Name (SAN)**: Default entries for local development
//!   - DNS: `localhost` (for local hostname access)
//!   - IP: `127.0.0.1` (IPv4 loopback)
//!   - IP: `::1` (IPv6 loopback)
//!   - DNS: Common Name from certificate (as specified in builder)
//!
//! # Example
//! ```rust,no_run
//! # use anyhow::Result;
//! # use openssl::pkey::PKey;
//! # use openssl::x509::X509;
//! # fn example(intermediate_key: PKey<openssl::pkey::Private>, intermediate_cert: X509) -> Result<()> {
//! let (server_key, server_cert) = RsaHttpServerCABuilder::new(
//!     intermediate_key,
//!     intermediate_cert
//! )
//!     .subject_common_name("pki.example.com".to_string())
//!     .organization("Example Corp".to_string())
//!     .organizational_unit("IT Operations".to_string())
//!     .locality("San Francisco".to_string())
//!     .state("California".to_string())
//!     .country("US".to_string())
//!     .validity_days(365)
//!     .build()?;
//! # Ok(())
//! # }
//! ```

use anyhow::{anyhow, Result};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

// Add X.509v3 extensions
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};

const X509_VERSION_3: i32 = 2; // X509 version 3 is represented by 2
const RSA_KEY_SIZE_DEFAULT: u32 = 4096;
pub(crate) const WEBCLIENT_COMMON_NAME: &str = "webclient_cert.local";
pub(crate) const WEBCLIENT_INTERMEDIATE_COMMON_NAME: &str = "webclient_intermediate_tls_ca";

// ================= RSA TLS Server Certificate Builder =================

/// Builder for generating RSA key pairs and TLS server certificates signed by an Intermediate CA
///
/// Creates end-entity TLS/HTTPS server certificates for the PKIWebClient server. These certificates
/// are signed by an Intermediate CA, which forms a complete trust chain back to the Root CA.
///
/// # Certificate Chain
/// Root CA → Intermediate CA → **TLS Server Certificate** (this module)
///
/// # Required Fields
/// All distinguished name fields must be set before calling `build()`:
/// - `subject_common_name` - Server hostname/FQDN (e.g., "pki.example.com", "localhost")
/// - `organization` - Organization name
/// - `organizational_unit` - Department (e.g., "IT Operations", "Web Services")
/// - `locality` - City
/// - `state` - State or province
/// - `country` - Two-letter ISO country code
///
/// # Certificate Properties
/// TLS server certificates:
/// - Are signed by an Intermediate CA
/// - Have `CA=false` (end-entity certificate, cannot sign other certificates)
/// - Include Key Usage: `digitalSignature` and `keyEncipherment` for TLS
/// - Should have shorter validity periods (typically 1 year or less)
///
/// # Use Cases
/// - **HTTPS Server**: Secure web interface for PKIWebClient
/// - **TLS Authentication**: Enable encrypted client-server communication
/// - **Certificate Chain Validation**: Browsers can validate the full chain to Root CA
///
/// # Examples
/// ```rust,no_run
/// # use anyhow::Result;
/// # use openssl::pkey::PKey;
/// # use openssl::x509::X509;
/// # fn example(intermediate_key: PKey<openssl::pkey::Private>, intermediate_cert: X509) -> Result<()> {
///
/// let (server_private_key, server_cert) = RsaHttpServerCABuilder::new(
///     intermediate_key,
///     intermediate_cert
/// )
///     .subject_common_name("pki-webclient.example.com".to_string())
///     .organization("Example Corporation".to_string())
///     .organizational_unit("Web Operations".to_string())
///     .locality("Seattle".to_string())
///     .state("Washington".to_string())
///     .country("US".to_string())
///     .validity_days(365)  // 1 year
///     .build()?;
///
/// // Use server_key and server_cert to configure HTTPS server
/// # Ok(())
/// # }
/// ```
pub(crate) struct RsaHttpServerCABuilder {
    subject_common_name: String,
    organization: String,
    oganizational_unit: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
    signing_key: PKey<Private>,
    signing_cert: X509,
}

impl RsaHttpServerCABuilder {
    /// Create a new RSA TLS server certificate builder
    ///
    /// # Arguments
    /// * `intermediate_ca_key` - Intermediate CA's private key for signing the server certificate
    /// * `intermediate_ca_cert` - Intermediate CA's certificate (issuer information)
    pub(crate) fn new(intermediate_ca_key: PKey<Private>, intermediate_ca_cert: X509) -> Self {
        Self {
            subject_common_name: String::new(),
            organization: String::new(),
            oganizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            validity_days: 1825, // Default 5 years
            signing_key: intermediate_ca_key,
            signing_cert: intermediate_ca_cert,
        }
    }

    /// Set the common name (CN) for the TLS server certificate
    ///
    /// For TLS certificates, this should be the fully qualified domain name (FQDN) or hostname
    /// of the server where the PKIWebClient will run.
    ///
    /// # Arguments
    /// * `cn` - Server hostname (e.g., "pki.example.com", "localhost", "192.168.1.100")
    ///
    /// # Returns
    /// Self for method chaining
    pub(crate) fn subject_common_name(mut self, cn: String) -> Self {
        self.subject_common_name = cn;
        self
    }

    /// Set the organization (O) for the certificate
    pub(crate) fn organization(mut self, org: String) -> Self {
        self.organization = org;
        self
    }

    /// Set the organizational unit (OU) for the certificate
    pub(crate) fn organizational_unit(mut self, ou: String) -> Self {
        self.oganizational_unit = ou;
        self
    }

    /// Set the locality (L) for the certificate
    pub(crate) fn locality(mut self, locality: String) -> Self {
        self.locality = locality;
        self
    }

    /// Set the state/province (ST) for the certificate
    pub(crate) fn state(mut self, state: String) -> Self {
        self.state = state;
        self
    }

    /// Set the country (C) for the certificate (2-letter ISO code)
    pub(crate) fn country(mut self, country: String) -> Self {
        self.country = country;
        self
    }

    /// Set validity period in days
    ///
    /// # Arguments
    /// * `days` - Number of days the certificate will be valid (default: 1825 = 5 years)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Recommendations
    /// - Intermediate CAs: 1825-3650 days (5-10 years)
    /// - Should be shorter than root CA validity
    /// - Should be longer than end-entity certificate validity
    pub(crate) fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Build the RSA key pair and TLS server certificate signed by Intermediate CA
    ///
    /// Generates a new RSA-4096 key pair and creates an X.509v3 TLS server certificate
    /// for the PKIWebClient HTTPS server, signed by the Intermediate CA provided during
    /// builder construction. This creates the complete trust chain:
    /// **Root CA → Intermediate CA → TLS Server Certificate**
    ///
    /// # Certificate Properties
    /// - **Version**: X.509v3
    /// - **Key Size**: RSA 4096-bit
    /// - **Signature Algorithm**: SHA-256 with RSA
    /// - **Basic Constraints**: CA=false (end-entity certificate)
    /// - **Key Usage**: digitalSignature, keyEncipherment (critical, for TLS/HTTPS)
    /// - **Extended Key Usage**: serverAuth (TLS server authentication)
    /// - **Subject Alternative Name**: localhost, 127.0.0.1, ::1, plus CN (for local development)
    /// - **Serial Number**: Random 128-bit number
    /// # TLS Server Purpose
    /// This certificate is specifically designed for securing the PKIWebClient web interface
    /// with HTTPS. The X.509v3 extensions ensure proper TLS/SSL functionality:
    /// - **Key Usage**: `digitalSignature` (TLS handshakes), `keyEncipherment` (RSA key exchange)
    /// - **Extended Key Usage**: `serverAuth` (explicitly identifies TLS server authentication purpose)
    /// - **Subject Alternative Name**: Includes localhost, 127.0.0.1, ::1, and CN for local development access
    /// - `digitalSignature`: Required for TLS handshakes and server authentication
    /// - `keyEncipherment`: Required for RSA key exchange during TLS connection establishment
    ///
    /// # Returns
    /// * `Ok((PKey<Private>, X509))` - Tuple of (private key, signed certificate)
    /// * `Err(anyhow::Error)` - If certificate generation fails
    ///
    /// # Errors
    /// Returns error if:
    /// - RSA key generation fails
    /// - Any required certificate field is empty
    /// - Certificate signing fails
    /// - X.509 extension creation fails
    ///
    /// # Example
    /// ```rust,no_run
    /// # use libcertcrypto::RsaHttpServerCABuilder;
    /// # use anyhow::Result;
    /// # use openssl::pkey::PKey;
    /// # use openssl::x509::X509;
    /// # fn example(intermediate_key: PKey<openssl::pkey::Private>, intermediate_cert: X509) -> Result<()> {
    /// let (server_key, server_cert) = RsaHttpServerCABuilder::new(intermediate_key, intermediate_cert)
    ///     .subject_common_name("pki-webclient.example.com".to_string())
    ///     .organization("Example Corp".to_string())
    ///     .organizational_unit("Web Services".to_string())
    ///     .locality("Boston".to_string())
    ///     .state("Massachusetts".to_string())
    ///     .country("US".to_string())
    ///     .validity_days(365)
    ///     .build()?;
    ///
    /// // Use server_key and server_cert to configure PKIWebClient HTTPS server
    /// # Ok(())
    /// # }
    /// ```
    pub(crate) fn build(self) -> Result<(PKey<Private>, X509)> {
        // Generate RSA key pair for intermediate CA
        let rsa = openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT)
            .map_err(|e| anyhow!("Failed to generate RSA keypair: {}", e))?;

        let private_key =
            PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create private key: {}", e))?;

        // Build X509 certificate
        let mut builder =
            X509::builder().map_err(|e| anyhow!("Failed to create X509 builder: {}", e))?;

        builder
            .set_version(X509_VERSION_3)
            .map_err(|e| anyhow!("Failed to set version: {}", e))?;

        // Generate random 128-bit (16-byte) serial number
        let mut serial = BigNum::new()?;
        serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
        let asn1_serial = serial.to_asn1_integer()?;
        builder.set_serial_number(&asn1_serial)?;

        // Build subject name for intermediate CA
        let mut name_builder = openssl::x509::X509Name::builder()
            .map_err(|e| anyhow!("Failed to create name builder: {}", e))?;
        name_builder
            .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &self.subject_common_name)
            .map_err(|e| anyhow!("Failed to set CN: {}", e))?;

        name_builder
            .append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, &self.organization)
            .map_err(|e| anyhow!("Failed to set organization: {}", e))?;

        name_builder
            .append_entry_by_nid(
                openssl::nid::Nid::ORGANIZATIONALUNITNAME,
                &self.oganizational_unit,
            )
            .map_err(|e| anyhow!("Failed to set organizational unit: {}", e))?;

        name_builder
            .append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, &self.locality)
            .map_err(|e| anyhow!("Failed to set locality: {}", e))?;

        name_builder
            .append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, &self.state)
            .map_err(|e| anyhow!("Failed to set state/province: {}", e))?;

        name_builder
            .append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, &self.country)
            .map_err(|e| anyhow!("Failed to set country: {}", e))?;

        let subject_name = name_builder.build();

        // Set subject to intermediate CA name
        builder
            .set_subject_name(&subject_name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;

        // Set issuer to root CA's subject (from signing_cert)
        builder
            .set_issuer_name(self.signing_cert.subject_name())
            .map_err(|e| anyhow!("Failed to set issuer from root CA: {}", e))?;

        let not_before = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| anyhow!("Failed to create not_before: {}", e))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| anyhow!("Failed to set not_before: {}", e))?;

        let not_after = openssl::asn1::Asn1Time::days_from_now(self.validity_days)
            .map_err(|e| anyhow!("Failed to create not_after: {}", e))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| anyhow!("Failed to set not_after: {}", e))?;

        // Set public key (extracted from private_key automatically)
        builder
            .set_pubkey(&private_key)
            .map_err(|e| anyhow!("Failed to set public key: {}", e))?;

        // Add Basic Constraints: CA=false (end-entity TLS server certificate)
        let bc = BasicConstraints::new()
            .critical()
            .build()
            .map_err(|e| anyhow!("Failed to build BasicConstraints: {}", e))?;
        builder
            .append_extension(bc)
            .map_err(|e| anyhow!("Failed to add BasicConstraints: {}", e))?;

        // Add Key Usage extension for TLS/HTTPS server certificate
        let ku = KeyUsage::new()
            .critical()
            .digital_signature() // For TLS handshakes and signatures
            .key_encipherment() // For RSA key exchange in TLS
            .build()
            .map_err(|e| anyhow!("Failed to build KeyUsage: {}", e))?;
        builder
            .append_extension(ku)
            .map_err(|e| anyhow!("Failed to add KeyUsage: {}", e))?;

        // Add Extended Key Usage: serverAuth (required for TLS/HTTPS servers)
        let eku = ExtendedKeyUsage::new()
            .server_auth() // Explicitly mark as TLS server certificate
            .build()
            .map_err(|e| anyhow!("Failed to build ExtendedKeyUsage: {}", e))?;
        builder
            .append_extension(eku)
            .map_err(|e| anyhow!("Failed to add ExtendedKeyUsage: {}", e))?;

        // Add Subject Alternative Name (SAN) - required by modern browsers
        // Default SAN entries for local development: localhost, 127.0.0.1, and ::1
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .ip("127.0.0.1")
            .ip("::1")
            .dns(&self.subject_common_name) // Also include the CN
            .build(&builder.x509v3_context(Some(&self.signing_cert), None))
            .map_err(|e| anyhow!("Failed to build SubjectAlternativeName: {}", e))?;
        builder
            .append_extension(san)
            .map_err(|e| anyhow!("Failed to add SubjectAlternativeName: {}", e))?;

        // Sign with intermediate CA's private key
        builder
            .sign(&self.signing_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;

        let x509 = builder.build();

        Ok((private_key, x509))
    }
}
