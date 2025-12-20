//! User Certificate Generation Module
//!
//! This module provides functionality for generating end-entity user certificates
//! signed by an intermediate CA. User certificates are the leaf nodes in a PKI
//! hierarchy and are used for:
//! - Digital signatures (signing documents, code, emails)
//! - Encryption (TLS client authentication, email encryption)
//! - Non-repudiation (proving origin of signed data)
//!
//! # PKI Hierarchy Position
//! ```text
//! Root CA (self-signed)
//!   └── Intermediate CA (signed by Root)
//!       └── User Certificate (signed by Intermediate) ← This module
//! ```
//!
//! # Certificate Properties
//! - **Key Usage**: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
//! - **Basic Constraints**: CA=false (cannot sign other certificates)
//! - **Default Key Size**: RSA 4096-bit
//! - **Default Validity**: 365 days (1 year)
//! - **Version**: X.509v3 with extensions
//! # Example
//! ```rust,no_run
//! # use anyhow::Result;
//! # fn example() -> Result<()> {
//! // Generate user certificate signed by intermediate CA
//! let (user_key, user_cert) = RsaUserKeyPairBuilder::new(ca_key, ca_cert)
//!     .subject_common_name("user@example.com".to_string())
//!     .organization("Example Corp".to_string())
//!     .organizational_unit("Engineering".to_string())
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
use openssl::x509::extension::{BasicConstraints, KeyUsage};

const X509_VERSION_3: i32 = 2; // X509 version 3 is represented by 2
const RSA_KEY_SIZE_DEFAULT: u32 = 4096;

// ================= RSA User Key Pair Builder =================

/// Builder for generating RSA key pairs and user certificates signed by an intermediate CA
///
/// This builder creates end-entity certificates for users, devices, or applications.
/// User certificates cannot sign other certificates (CA=false) and are typically used for:
/// - Signing documents, code, or emails
/// - TLS client authentication
/// - Email encryption (S/MIME)
/// - Code signing
///
/// # Required Fields
/// All distinguished name fields must be set before calling `build()`:
/// - `subject_common_name` - User identifier (email, username, etc.)
/// - `organization` - Organization name
/// - `organizational_unit` - Department or division
/// - `locality` - City
/// - `state` - State or province
/// - `country` - Two-letter ISO country code
///
/// # Certificate Chain
/// User certificates must be signed by an intermediate CA. The signing CA's
/// private key and certificate must be provided when creating the builder.
///
/// # Examples
/// ```rust,no_run
/// use libcertcrypto::RsaUserKeyPairBuilder;
/// # use anyhow::Result;
/// # use openssl::pkey::PKey;
/// # use openssl::x509::X509;
/// # fn example(intermediate_key: PKey<openssl::pkey::Private>, intermediate_cert: X509) -> Result<()> {
///
/// let (user_private_key, user_cert) = RsaUserKeyPairBuilder::new(
///     intermediate_key,
///     intermediate_cert
/// )
///     .subject_common_name("alice@example.com".to_string())
///     .organization("Example Corporation".to_string())
///     .organizational_unit("IT Department".to_string())
///     .locality("New York".to_string())
///     .state("New York".to_string())
///     .country("US".to_string())
///     .validity_days(730)  // 2 years
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct RsaUserKeyPairBuilder {
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

impl RsaUserKeyPairBuilder {
    /// Create a new RSA user key pair builder
    ///
    /// # Arguments
    /// * `ca_key` - Intermediate CA's private key for signing
    /// * `ca_cert` - Intermediate CA's certificate (issuer information)
    pub fn new(ca_key: PKey<Private>, ca_cert: X509) -> Self {
        Self {
            subject_common_name: String::new(),
            organization: String::new(),
            oganizational_unit: String::new(),
            locality: String::new(),
            state: String::new(),
            country: String::new(),
            validity_days: 365, // Default 1 year
            signing_key: ca_key,
            signing_cert: ca_cert,
        }
    }

    /// Set the common name (CN) for the certificate - typically user's email or name
    ///
    /// The common name is the primary identifier for the certificate holder.
    /// For user certificates, this is typically:
    /// - Email address (user@example.com)
    /// - Full name (Alice Smith)
    /// - Username (alice.smith)
    ///
    /// # Arguments
    /// * `cn` - Common name string
    ///
    /// # Returns
    /// Self for method chaining
    pub fn subject_common_name(mut self, cn: String) -> Self {
        self.subject_common_name = cn;
        self
    }

    /// Set the organization (O) for the certificate
    ///
    /// # Arguments
    /// * `org` - Organization name (e.g., "Example Corporation")
    ///
    /// # Returns
    /// Self for method chaining
    pub fn organization(mut self, org: String) -> Self {
        self.organization = org;
        self
    }

    /// Set the organizational unit (OU) for the certificate
    ///
    /// # Arguments
    /// * `ou` - Department or division name (e.g., "Engineering", "Sales")
    ///
    /// # Returns
    /// Self for method chaining
    pub fn organizational_unit(mut self, ou: String) -> Self {
        self.oganizational_unit = ou;
        self
    }

    /// Set the locality (L) for the certificate
    ///
    /// # Arguments
    /// * `locality` - City or locality name (e.g., "San Francisco", "London")
    ///
    /// # Returns
    /// Self for method chaining
    pub fn locality(mut self, locality: String) -> Self {
        self.locality = locality;
        self
    }

    /// Set the state/province (ST) for the certificate
    ///
    /// # Arguments
    /// * `state` - State or province name (e.g., "California", "Ontario")
    ///
    /// # Returns
    /// Self for method chaining
    pub fn state(mut self, state: String) -> Self {
        self.state = state;
        self
    }

    /// Set the country (C) for the certificate (2-letter ISO code)
    ///
    /// # Arguments
    /// * `country` - Two-letter ISO 3166-1 country code (e.g., "US", "GB", "CA")
    ///
    /// # Returns
    /// Self for method chaining
    pub fn country(mut self, country: String) -> Self {
        self.country = country;
        self
    }

    /// Set validity period in days
    ///
    /// # Arguments
    /// * `days` - Number of days the certificate will be valid (default: 365)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Recommendations
    /// - User certificates: 365-730 days (1-2 years)
    /// - Device certificates: 730-1095 days (2-3 years)
    /// - Short-lived certificates: 30-90 days
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Build the RSA key pair and user certificate signed by intermediate CA
    ///
    /// Generates a new RSA-4096 key pair and creates an X.509v3 certificate
    /// signed by the intermediate CA provided during builder construction.
    ///
    /// # Certificate Properties
    /// - **Version**: X.509v3
    /// - **Key Size**: RSA 4096-bit
    /// - **Signature Algorithm**: SHA-256 with RSA
    /// - **Basic Constraints**: CA=false, critical
    /// - **Key Usage**: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    /// - **Serial Number**: Random 128-bit number
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
    /// # use libcertcrypto::RsaUserKeyPairBuilder;
    /// # use anyhow::Result;
    /// # use openssl::pkey::PKey;
    /// # use openssl::x509::X509;
    /// # fn example(ca_key: PKey<openssl::pkey::Private>, ca_cert: X509) -> Result<()> {
    /// let (private_key, certificate) = RsaUserKeyPairBuilder::new(ca_key, ca_cert)
    ///     .subject_common_name("user@example.com".to_string())
    ///     .organization("Example Corp".to_string())
    ///     .organizational_unit("IT".to_string())
    ///     .locality("Boston".to_string())
    ///     .state("Massachusetts".to_string())
    ///     .country("US".to_string())
    ///     .build()?;
    ///
    /// // Use the certificate for signing, encryption, etc.
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<(PKey<Private>, X509)> {
        // Generate RSA key pair for user
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

        // Build subject name for user
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

        // Set subject to user's name
        builder
            .set_subject_name(&subject_name)
            .map_err(|e| anyhow!("Failed to set subject: {}", e))?;

        // Set issuer to intermediate CA's subject (from signing_cert)
        builder
            .set_issuer_name(self.signing_cert.subject_name())
            .map_err(|e| anyhow!("Failed to set issuer from intermediate CA: {}", e))?;

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

        // Add Basic Constraints: CA=false (this is NOT a CA certificate)
        let mut bc = BasicConstraints::new();
        bc.critical();
        // No .ca() call - this is an end-entity certificate

        let extension = bc
            .build()
            .map_err(|e| anyhow!("Failed to build BasicConstraints: {}", e))?;
        builder
            .append_extension(extension)
            .map_err(|e| anyhow!("Failed to add BasicConstraints: {}", e))?;

        // Add Key Usage extension for user certificate
        // digitalSignature - for signing data
        // nonRepudiation - for non-repudiation (contentCommitment)
        // keyEncipherment - for encrypting keys (TLS, email encryption)
        // dataEncipherment - for encrypting data
        let mut ku = KeyUsage::new();
        ku.critical();
        ku.digital_signature(); // For digital signatures
        ku.non_repudiation(); // For non-repudiation
        ku.key_encipherment(); // For encrypting symmetric keys
        ku.data_encipherment(); // For encrypting data directly

        let ku_extension = ku
            .build()
            .map_err(|e| anyhow!("Failed to build KeyUsage: {}", e))?;
        builder
            .append_extension(ku_extension)
            .map_err(|e| anyhow!("Failed to add KeyUsage: {}", e))?;

        // Sign with intermediate CA's private key
        builder
            .sign(&self.signing_key, MessageDigest::sha256())
            .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;

        let x509 = builder.build();

        Ok((private_key, x509))
    }
}
