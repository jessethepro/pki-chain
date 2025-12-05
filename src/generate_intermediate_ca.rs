//! Intermediate CA Certificate Generation Module
//!
//! This module provides functionality for generating intermediate CA certificates
//! signed by a root CA. Intermediate CAs act as a bridge between the root CA and
//! end-entity certificates, allowing the root CA to remain offline while still
//! enabling certificate issuance.
//!
//! # PKI Hierarchy Position
//! ```text
//! Root CA (self-signed)
//!   └── Intermediate CA (signed by Root) ← This module
//!       └── User Certificate (signed by Intermediate)
//! ```
//!
//! # Certificate Properties
//! - **Signed by**: Root CA
//! - **Key Usage**: keyCertSign, cRLSign, digitalSignature
//! - **Basic Constraints**: CA=true, pathlen=0 (can only sign end-entity certs)
//! - **Default Key Size**: RSA 4096-bit
//! - **Default Validity**: 1825 days (5 years)
//! - **Version**: X.509v3 with extensions
//!
//! # Purpose
//! - Allows root CA to remain offline for security
//! - Can be revoked without affecting root CA trust
//! - Enables operational flexibility (multiple intermediates for different purposes)
//! - Pathlen=0 prevents further CA delegation (only signs user certs)
//!
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
const INTERMEDIATE_CA_PATH_LENGTH: u32 = 0; // Can only sign end-entity certs, not other CAs

// ================= RSA Intermediate CA Builder =================

/// Builder for generating RSA key pairs and intermediate CA certificates signed by a root CA
///
/// Creates intermediate CA certificates that sit between the root CA and end-entity
/// certificates. This allows the root CA to remain offline while still enabling
/// certificate issuance operations.
///
/// # Required Fields
/// All distinguished name fields must be set before calling `build()`:
/// - `subject_common_name` - Intermediate CA name (e.g., "Example Intermediate CA")
/// - `organization` - Organization name
/// - `organizational_unit` - Department (typically "Operations" or "Issuing CA")
/// - `locality` - City
/// - `state` - State or province
/// - `country` - Two-letter ISO country code
///
/// # Certificate Chain
/// Intermediate CA certificates:
/// - Are signed by the root CA
/// - Have `pathlen=0`, meaning they can only sign end-entity certificates
/// - Cannot sign other intermediate or root CAs
/// - Should have shorter validity periods than root CAs (typically 3-5 years)
///
/// # Use Cases
/// - **Operational Security**: Keep root CA offline, use intermediate for daily operations
/// - **Purpose Separation**: Different intermediates for TLS, email, code signing
/// - **Geographic Distribution**: Regional intermediate CAs
/// - **Revocation Strategy**: Revoke intermediate without compromising root
///
/// # Examples
/// ```rust,no_run
/// # use anyhow::Result;
/// # use openssl::pkey::PKey;
/// # use openssl::x509::X509;
/// # fn example(root_key: PKey<openssl::pkey::Private>, root_cert: X509) -> Result<()> {
///
/// let (intermediate_private_key, intermediate_cert) = RsaIntermediateCABuilder::new(
///     root_key,
///     root_cert
/// )
///     .subject_common_name("ACME Issuing CA 2025".to_string())
///     .organization("ACME Corporation".to_string())
///     .organizational_unit("Certificate Operations".to_string())
///     .locality("Seattle".to_string())
///     .state("Washington".to_string())
///     .country("US".to_string())
///     .validity_days(1825)  // 5 years
///     .build()?;
///
/// // Use intermediate_key to sign user certificates
/// # Ok(())
/// # }
/// ```
pub struct RsaIntermediateCABuilder {
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

impl RsaIntermediateCABuilder {
    /// Create a new RSA intermediate CA builder
    ///
    /// # Arguments
    /// * `ca_key` - Root CA's private key for signing
    /// * `ca_cert` - Root CA's certificate (issuer information)
    pub fn new(ca_key: PKey<Private>, ca_cert: X509) -> Self {
        Self {
            subject_common_name: String::new(),
            organization: String::new(),
            oganizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            validity_days: 1825, // Default 5 years
            signing_key: ca_key,
            signing_cert: ca_cert,
        }
    }

    /// Set the common name (CN) for the certificate
    ///
    /// For intermediate CAs, this should clearly identify the CA's role and purpose.
    ///
    /// # Arguments
    /// * `cn` - Common name (e.g., "Example Issuing CA", "ACME TLS Intermediate CA")
    ///
    /// # Returns
    /// Self for method chaining
    pub fn subject_common_name(mut self, cn: String) -> Self {
        self.subject_common_name = cn;
        self
    }

    /// Set the organization (O) for the certificate
    pub fn organization(mut self, org: String) -> Self {
        self.organization = org;
        self
    }

    /// Set the organizational unit (OU) for the certificate
    pub fn organizational_unit(mut self, ou: String) -> Self {
        self.oganizational_unit = ou;
        self
    }

    /// Set the locality (L) for the certificate
    pub fn locality(mut self, locality: String) -> Self {
        self.locality = locality;
        self
    }

    /// Set the state/province (ST) for the certificate
    pub fn state(mut self, state: String) -> Self {
        self.state = state;
        self
    }

    /// Set the country (C) for the certificate (2-letter ISO code)
    pub fn country(mut self, country: String) -> Self {
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
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Build the RSA key pair and intermediate CA certificate signed by root CA
    ///
    /// Generates a new RSA-4096 key pair and creates an X.509v3 certificate
    /// signed by the root CA provided during builder construction.
    ///
    /// # Certificate Properties
    /// - **Version**: X.509v3
    /// - **Key Size**: RSA 4096-bit
    /// - **Signature Algorithm**: SHA-256 with RSA
    /// - **Basic Constraints**: CA=true, pathlen=0, critical
    /// - **Key Usage**: keyCertSign, cRLSign, digitalSignature
    /// - **Serial Number**: Random 128-bit number
    /// - **Issuer**: Root CA (from signing_cert)
    ///
    /// # Path Length Constraint
    /// The `pathlen=0` constraint means this intermediate CA can only sign
    /// end-entity certificates, not other CAs. This prevents unauthorized
    /// CA hierarchy extension.
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
    /// # use libcertcrypto::RsaIntermediateCABuilder;
    /// # use anyhow::Result;
    /// # use openssl::pkey::PKey;
    /// # use openssl::x509::X509;
    /// # fn example(root_key: PKey<openssl::pkey::Private>, root_cert: X509) -> Result<()> {
    /// let (private_key, certificate) = RsaIntermediateCABuilder::new(root_key, root_cert)
    ///     .subject_common_name("Intermediate CA".to_string())
    ///     .organization("Example Corp".to_string())
    ///     .organizational_unit("PKI Operations".to_string())
    ///     .locality("Boston".to_string())
    ///     .state("Massachusetts".to_string())
    ///     .country("US".to_string())
    ///     .build()?;
    ///
    /// // Use private_key to sign user certificates
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<(PKey<Private>, X509)> {
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

        // Add Basic Constraints: CA=true, pathlen=0 (can only sign end-entity certs)
        let mut bc = BasicConstraints::new();
        bc.critical().ca();
        bc.pathlen(INTERMEDIATE_CA_PATH_LENGTH); // 0 = can only sign user certs, not other CAs

        let extension = bc
            .build()
            .map_err(|e| anyhow!("Failed to build BasicConstraints: {}", e))?;
        builder
            .append_extension(extension)
            .map_err(|e| anyhow!("Failed to add BasicConstraints: {}", e))?;

        // Add Key Usage extension for intermediate CA
        let mut ku = KeyUsage::new();
        ku.critical();
        ku.key_cert_sign(); // Can sign certificates
        ku.crl_sign(); // Can sign CRLs
        ku.digital_signature();

        let ku_extension = ku
            .build()
            .map_err(|e| anyhow!("Failed to build KeyUsage: {}", e))?;
        builder
            .append_extension(ku_extension)
            .map_err(|e| anyhow!("Failed to add KeyUsage: {}", e))?;

        // Sign with root CA's private key
        builder
            .sign(&self.signing_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;

        let x509 = builder.build();

        Ok((private_key, x509))
    }
}
