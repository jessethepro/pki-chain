use anyhow::{anyhow, Result};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::ExtendedKeyUsage;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::X509;

const INTERMEDIATE_CA_PATH_LENGTH: u32 = 0;
const X509_VERSION_3: i32 = 2; // X509 version 3 is represented by 2
const RSA_KEY_SIZE_DEFAULT: u32 = 4096;
const ROOT_CA_PATH_LENGTH: u32 = 1;

#[derive(Debug, Clone)]
pub enum CertificateDataType {
    RootCA,
    IntermediateCA,
    UserCert,
    TlsCert,
}

/// Certificate data structure
#[derive(Debug, Clone)]
pub struct CertificateData {
    pub subject_common_name: String,
    pub issuer_common_name: String,
    pub organization: String,
    pub organizational_unit: String,
    pub locality: String,
    pub state: String,
    pub country: String,
    pub validity_days: u32,
    pub cert_type: CertificateDataType,
}

pub fn generate_root_ca(cert_data: CertificateData) -> Result<(PKey<Private>, X509)> {
    // Generate RSA key pair
    let rsa = openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT)
        .map_err(|e| anyhow!("Failed to generate RSA keypair: {}", e))?;
    let private_key =
        PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create private key: {}", e))?;

    generate_key_pair(cert_data, &private_key)
}

pub fn generate_key_pair(
    cert_data: CertificateData,
    signing_key: &PKey<Private>,
) -> Result<(PKey<Private>, X509)> {
    let private_key = match cert_data.cert_type {
        CertificateDataType::RootCA => signing_key.clone(), // Self signed. Private key is the signing key
        _ => {
            // Generate RSA key pair
            let rsa = openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT)
                .map_err(|e| anyhow!("Failed to generate RSA keypair: {}", e))?;
            PKey::from_rsa(rsa).map_err(|e| anyhow!("Failed to create private key: {}", e))?
        }
    };
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
        .append_entry_by_nid(
            openssl::nid::Nid::COMMONNAME,
            &cert_data.subject_common_name,
        )
        .map_err(|e| anyhow!("Failed to set CN: {}", e))?;

    name_builder
        .append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, &cert_data.organization)
        .map_err(|e| anyhow!("Failed to set organization: {}", e))?;

    name_builder
        .append_entry_by_nid(
            openssl::nid::Nid::ORGANIZATIONALUNITNAME,
            &cert_data.organizational_unit,
        )
        .map_err(|e| anyhow!("Failed to set organizational unit: {}", e))?;

    name_builder
        .append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, &cert_data.locality)
        .map_err(|e| anyhow!("Failed to set locality: {}", e))?;

    name_builder
        .append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, &cert_data.state)
        .map_err(|e| anyhow!("Failed to set state/province: {}", e))?;

    name_builder
        .append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, &cert_data.country)
        .map_err(|e| anyhow!("Failed to set country: {}", e))?;

    let name = name_builder.build();

    builder
        .set_subject_name(&name)
        .map_err(|e| anyhow!("Failed to set subject: {}", e))?;
    // Set issuer name
    builder
        .set_issuer_name(&name)
        .map_err(|e| anyhow!("Failed to set issuer: {}", e))?;
    // Set validity period
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)
        .map_err(|e| anyhow!("Failed to create not_before: {}", e))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| anyhow!("Failed to set not_before: {}", e))?;

    let not_after = openssl::asn1::Asn1Time::days_from_now(cert_data.validity_days)
        .map_err(|e| anyhow!("Failed to create not_after: {}", e))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| anyhow!("Failed to set not_after: {}", e))?;

    // Set public key (extracted from private_key automatically)
    builder
        .set_pubkey(&private_key)
        .map_err(|e| anyhow!("Failed to set public key: {}", e))?;

    // Add Basic Constraints extension
    match cert_data.cert_type {
        CertificateDataType::RootCA | CertificateDataType::IntermediateCA => {
            let mut bc = BasicConstraints::new();
            bc.critical().ca();
            match cert_data.cert_type {
                CertificateDataType::RootCA => {
                    bc.pathlen(ROOT_CA_PATH_LENGTH);
                }
                CertificateDataType::IntermediateCA => {
                    bc.pathlen(INTERMEDIATE_CA_PATH_LENGTH);
                }
                _ => {}
            }
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
                .sign(&signing_key, MessageDigest::sha256())
                .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;
        }
        CertificateDataType::UserCert => {
            let mut bc = BasicConstraints::new();
            bc.critical();
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
            builder
                .sign(&signing_key, MessageDigest::sha256())
                .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;
        }
        CertificateDataType::TlsCert => {
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

            // Sign with intermediate CA's private key
            builder
                .sign(&signing_key, MessageDigest::sha256())
                .map_err(|e| anyhow!("Failed to sign certificate: {}", e))?;
        }
    }
    let x509_certificate = builder.build();
    Ok((private_key, x509_certificate))
}
