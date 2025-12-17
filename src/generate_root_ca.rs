//! Root CA Certificate Generation Module
//!
//! This module provides functionality for generating self-signed root CA certificates,
//! which form the trust anchor at the top of a PKI hierarchy.
//!
//! # PKI Hierarchy Position
//! ```text
//! Root CA (self-signed) ← This module
//!   └── Intermediate CA (signed by Root)
//!       └── User Certificate (signed by Intermediate)
//! ```
//!
//! # Certificate Properties
//! - **Self-signed**: Issuer and subject are the same
//! - **Key Usage**: keyCertSign, cRLSign, digitalSignature
//! - **Basic Constraints**: CA=true, pathlen=1 (can sign intermediate CAs)
//! - **Default Key Size**: RSA 4096-bit
//! - **Default Validity**: 365 days (configurable to 10+ years for production)
//! - **Version**: X.509v3 with extensions
//!
//! # Security Considerations
//! - Root CA private keys should be kept offline and highly secured
//! - Root certificates should have long validity periods (10-20 years)
//! - Root CA should only sign intermediate CA certificates, not end-entity certs
//!
//! # Example
//! ```rust,no_run
//! # use anyhow::Result;
//! # fn example() -> Result<()> {
//!
//! // Generate self-signed root CA certificate
//! let (root_key, root_cert) = RsaRootCABuilder::new()
//!     .subject_common_name("Example Root CA".to_string())
//!     .organization("Example Corporation".to_string())
//!     .organizational_unit("Security".to_string())
//!     .locality("San Francisco".to_string())
//!     .state("California".to_string())
//!     .country("US".to_string())
//!     .validity_days(3650)  // 10 years
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
use openssl::x509::extension::{BasicConstraints, KeyUsage};

const X509_VERSION_3: i32 = 2; // X509 version 3 is represented by 2
const RSA_KEY_SIZE_DEFAULT: u32 = 4096;
const ROOT_CA_PATH_LENGTH: u32 = 1;

// ================= RSA Key and Certificate Builder =================

/// Builder for generating RSA key pairs and self-signed root CA certificates
///
/// Creates the trust anchor for a PKI hierarchy. Root CAs are self-signed and
/// should be carefully secured as they form the basis of trust for all certificates
/// in the chain.
///
/// # Required Fields
/// All distinguished name fields must be set before calling `build()`:
/// - `subject_common_name` - CA name (e.g., "Example Root CA")
/// - `organization` - Organization name
/// - `organizational_unit` - Department (typically "Security" or "PKI")
/// - `locality` - City
/// - `state` - State or province
/// - `country` - Two-letter ISO country code
///
/// # Certificate Chain
/// Root CA certificates are self-signed, meaning the issuer and subject are identical.
/// They have `pathlen=1` allowing them to sign intermediate CAs, which in turn sign
/// end-entity certificates.
///
/// # Best Practices
/// - Use long validity periods (10-20 years)
/// - Keep private key offline (air-gapped)
/// - Use strong key sizes (4096-bit RSA minimum)
/// - Limit signing to intermediate CAs only
///
/// # Examples
/// ```rust,no_run
/// use libcertcrypto::RsaRootCABuilder;
/// # use anyhow::Result;
/// # fn example() -> Result<()> {
///
/// let (private_key, certificate) = RsaRootCABuilder::new()
///     .subject_common_name("ACME Root CA 2025".to_string())
///     .organization("ACME Corporation".to_string())
///     .organizational_unit("Certificate Authority".to_string())
///     .locality("New York".to_string())
///     .state("New York".to_string())
///     .country("US".to_string())
///     .validity_days(7300)  // 20 years
///     .build()?;
///
/// // Store the private key securely (offline storage recommended)
/// # Ok(())
/// # }
/// ```
pub(crate) struct RsaRootCABuilder {
    subject_common_name: String,
    organization: String,
    oganizational_unit: String,
    locality: String,
    state: String,
    country: String,
    validity_days: u32,
}

impl RsaRootCABuilder {
    /// Create a new RSA key and certificate builder with default values
    pub(crate) fn new() -> Self {
        Self {
            subject_common_name: String::new(),
            organization: String::new(),
            oganizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            validity_days: 365,
        }
    }

    /// Set the common name (CN) for the certificate
    ///
    /// For root CAs, this should clearly identify the CA's purpose and organization.
    ///
    /// # Arguments
    /// * `cn` - Common name (e.g., "Example Root CA 2025", "ACME Certificate Authority")
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
    pub(crate) fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Build the RSA key pair and self-signed root CA certificate
    ///
    /// Generates a new RSA-4096 key pair and creates a self-signed X.509v3 certificate
    /// with CA capabilities.
    ///
    /// # Certificate Properties
    /// - **Version**: X.509v3
    /// - **Key Size**: RSA 4096-bit
    /// - **Signature Algorithm**: SHA-256 with RSA
    /// - **Basic Constraints**: CA=true, pathlen=1, critical
    /// - **Key Usage**: keyCertSign, cRLSign, digitalSignature
    /// - **Serial Number**: Random 128-bit number
    /// - **Issuer**: Same as subject (self-signed)
    ///
    /// # Returns
    /// * `Ok((PKey<Private>, X509))` - Tuple of (private key, self-signed certificate)
    /// * `Err(anyhow::Error)` - If certificate generation fails
    ///
    /// # Errors
    /// Returns error if:
    /// - RSA key generation fails
    /// - Any required certificate field is empty
    /// - X.509 extension creation fails
    /// - Certificate signing fails
    ///
    /// # Security Warning
    /// The returned private key must be stored securely. For production root CAs,
    /// consider using hardware security modules (HSMs) or air-gapped systems.
    pub(crate) fn build(self) -> Result<(PKey<Private>, X509)> {
        // Generate RSA key pair
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

        // Build subject/issuer name
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

        let name = name_builder.build();

        builder
            .set_subject_name(&name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;

        builder
            .set_issuer_name(&name)
            .map_err(|e| anyhow!("Failed to set issuer: {}", e))?;

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

        let mut bc = BasicConstraints::new();
        bc.critical().ca();

        bc.pathlen(ROOT_CA_PATH_LENGTH);

        let extension = bc
            .build()
            .map_err(|e| anyhow!("Failed to build BasicConstraints: {}", e))?;
        builder
            .append_extension(extension)
            .map_err(|e| anyhow!("Failed to add BasicConstraints: {}", e))?;
        // Add Key Usage extension
        let mut ku = KeyUsage::new();
        ku.critical();
        ku.key_cert_sign();
        ku.crl_sign();
        ku.digital_signature();
        let ku_extension = ku
            .build()
            .map_err(|e| anyhow!("Failed to build KeyUsage: {}", e))?;
        builder
            .append_extension(ku_extension)
            .map_err(|e| anyhow!("Failed to add KeyUsage: {}", e))?;
        builder
            .sign(&private_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;
        let x509 = builder.build();
        Ok((private_key, x509))
    }
}
