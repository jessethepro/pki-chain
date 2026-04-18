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

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateDataType {
    RootCA,
    IntermediateCA,
    UserCert,
    TlsCert,
}

#[derive(Debug, Clone, serde::Deserialize)]
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
    pub is_admin: bool,
}

pub fn parse_certificate_data_from_json(
    request_json: serde_json::Value,
) -> anyhow::Result<CertificateData> {
    let admin_cert_data = || -> anyhow::Result<CertificateData> {
        let subject_common_name = match request_json
            .get("subject_common_name")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "AddFirstAdmin -> request missing required field: subject_common_name"
                );
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: subject_common_name"
                ));
            }
        };
        let issuer_common_name = match request_json
            .get("issuer_common_name")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "AddFirstAdmin -> request missing required field: issuer_common_name"
                );
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: issuer_common_name"
                ));
            }
        };
        let organization = match request_json.get("organization").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("AddFirstAdmin -> request missing required field: organization");
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: organization"
                ));
            }
        };
        let organizational_unit = match request_json
            .get("organizational_unit")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "AddFirstAdmin -> request missing required field: organizational_unit"
                );
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: organizational_unit"
                ));
            }
        };
        let locality = match request_json.get("locality").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("AddFirstAdmin -> request missing required field: locality");
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: locality"
                ));
            }
        };
        let state = match request_json.get("state").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("AddFirstAdmin -> request missing required field: state");
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: state"
                ));
            }
        };
        let country = match request_json.get("country").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("AddFirstAdmin -> request missing required field: country");
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: country"
                ));
            }
        };
        let validity_days = match request_json.get("validity_days").and_then(|v| v.as_u64()) {
            Some(vd) => vd as u32,
            None => {
                tracing::error!("AddFirstAdmin -> request missing required field: validity_days");
                return Err(anyhow::anyhow!(
                    "AddFirstAdmin -> request missing required field: validity_days"
                ));
            }
        };
        Ok(CertificateData {
            subject_common_name,
            issuer_common_name,
            organization,
            organizational_unit,
            locality,
            state,
            country,
            validity_days,
            cert_type: CertificateDataType::UserCert,
            is_admin: true,
        })
    }();
    match admin_cert_data {
        Ok(data) => Ok(data),
        Err(e) => {
            tracing::error!(error = %e, "AddFirstAdmin -> Failed to parse certificate data from JSON");
            Err(anyhow!(
                "AddFirstAdmin -> Failed to parse certificate data from JSON: {}",
                e
            ))
        }
    }
}

pub fn generate_root_ca(cert_data: CertificateData) -> Result<(PKey<Private>, X509)> {
    // Generate RSA key pair
    let rsa = match openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to generate RSA keypair");
            return Err(anyhow!(
                "generate_root_ca -> Failed to generate RSA keypair: {}",
                e
            ));
        }
    };
    let private_key = match PKey::from_rsa(rsa) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to create private key");
            return Err(anyhow!(
                "generate_root_ca -> Failed to create private key: {}",
                e
            ));
        }
    };

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
            let rsa = match openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to generate RSA keypair");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to generate RSA keypair: {}",
                        e
                    ));
                }
            };
            match PKey::from_rsa(rsa) {
                Ok(pk) => pk,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to create private key");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to create private key: {}",
                        e
                    ));
                }
            }
        }
    };
    // Build X509 certificate
    let mut builder = match X509::builder() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to create X509 builder");
            return Err(anyhow!(
                "generate_key_pair -> Failed to create X509 builder: {}",
                e
            ));
        }
    };

    match builder.set_version(X509_VERSION_3) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set version");
            return Err(anyhow!("generate_key_pair -> Failed to set version: {}", e));
        }
    }

    // Generate random 128-bit (16-byte) serial number
    let mut serial = match BigNum::new() {
        Ok(bn) => bn,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to create BigNum");
            return Err(anyhow!(
                "generate_key_pair -> Failed to create BigNum: {}",
                e
            ));
        }
    };
    if let Err(e) = serial.rand(128, MsbOption::MAYBE_ZERO, false) {
        tracing::error!(error = %e, "generate_key_pair -> Failed to generate random serial number");
        return Err(anyhow!(
            "generate_key_pair -> Failed to generate random serial number: {}",
            e
        ));
    }
    let asn1_serial = match serial.to_asn1_integer() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to convert serial number to ASN1 integer");
            return Err(anyhow!(
                "generate_key_pair -> Failed to convert serial number to ASN1 integer: {}",
                e
            ));
        }
    };
    if let Err(e) = builder.set_serial_number(&asn1_serial) {
        tracing::error!(error = %e, "generate_key_pair -> Failed to set serial number");
        return Err(anyhow!(
            "generate_key_pair -> Failed to set serial number: {}",
            e
        ));
    }

    // Build subject/issuer name
    let mut name_builder = match openssl::x509::X509Name::builder() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to create name builder");
            return Err(anyhow!(
                "generate_key_pair -> Failed to create name builder: {}",
                e
            ));
        }
    };
    match name_builder.append_entry_by_nid(
        openssl::nid::Nid::COMMONNAME,
        &cert_data.subject_common_name,
    ) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set common name");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set common name: {}",
                e
            ));
        }
    }
    match name_builder
        .append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, &cert_data.organization)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set organization");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set organization: {}",
                e
            ));
        }
    }
    match name_builder.append_entry_by_nid(
        openssl::nid::Nid::ORGANIZATIONALUNITNAME,
        &cert_data.organizational_unit,
    ) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set organizational unit");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set organizational unit: {}",
                e
            ));
        }
    }

    match name_builder.append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, &cert_data.locality) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set locality");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set locality: {}",
                e
            ));
        }
    }
    match name_builder.append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, &cert_data.state)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set state/province");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set state/province: {}",
                e
            ));
        }
    }
    match name_builder.append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, &cert_data.country) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set country");
            return Err(anyhow!("generate_key_pair -> Failed to set country: {}", e));
        }
    }

    let subject_name = name_builder.build();

    builder
        .set_subject_name(&subject_name)
        .map_err(|e| anyhow!("AddFirstAdmin -> Failed to set subject: {}", e))?;

    // Build issuer name (different from subject unless self-signed)
    let mut issuer_name_builder = match openssl::x509::X509Name::builder() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to create issuer name builder");
            return Err(anyhow!(
                "generate_key_pair -> Failed to create issuer name builder: {}",
                e
            ));
        }
    };
    match issuer_name_builder
        .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &cert_data.issuer_common_name)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer CN");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer CN: {}",
                e
            ));
        }
    }
    match issuer_name_builder
        .append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, &cert_data.organization)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer organization");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer organization: {}",
                e
            ));
        }
    }
    match issuer_name_builder.append_entry_by_nid(
        openssl::nid::Nid::ORGANIZATIONALUNITNAME,
        &cert_data.organizational_unit,
    ) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer organizational unit");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer organizational unit: {}",
                e
            ));
        }
    }
    match issuer_name_builder
        .append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, &cert_data.locality)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer locality");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer locality: {}",
                e
            ));
        }
    }
    match issuer_name_builder
        .append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, &cert_data.state)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer state/province");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer state/province: {}",
                e
            ));
        }
    }
    match issuer_name_builder
        .append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, &cert_data.country)
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer country");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer country: {}",
                e
            ));
        }
    }
    let issuer_name = issuer_name_builder.build();
    match builder.set_issuer_name(&issuer_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set issuer name");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set issuer name: {}",
                e
            ));
        }
    }

    // Set validity period
    let not_before = match openssl::asn1::Asn1Time::days_from_now(0) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to create not_before");
            return Err(anyhow!(
                "generate_key_pair -> Failed to create not_before: {}",
                e
            ));
        }
    };
    match builder.set_not_before(&not_before) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set not_before");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set not_before: {}",
                e
            ));
        }
    }

    let not_after = match openssl::asn1::Asn1Time::days_from_now(cert_data.validity_days) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to create not_after");
            return Err(anyhow!(
                "generate_key_pair -> Failed to create not_after: {}",
                e
            ));
        }
    };
    match builder.set_not_after(&not_after) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set not_after");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set not_after: {}",
                e
            ));
        }
    }

    // Set public key (extracted from private_key automatically)
    match builder.set_pubkey(&private_key) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to set public key");
            return Err(anyhow!(
                "generate_key_pair -> Failed to set public key: {}",
                e
            ));
        }
    }

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
            let extension = match bc.build() {
                Ok(ext) => ext,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to build BasicConstraints");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to build BasicConstraints: {}",
                        e
                    ));
                }
            };
            match builder.append_extension(extension) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to add BasicConstraints");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to add BasicConstraints: {}",
                        e
                    ));
                }
            }
            // Add Key Usage extension
            let mut ku = KeyUsage::new();
            ku.critical();
            ku.key_cert_sign();
            ku.crl_sign();
            ku.digital_signature();
            let ku_extension = match ku.build() {
                Ok(ext) => ext,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to build KeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to build KeyUsage: {}",
                        e
                    ));
                }
            };
            match builder.append_extension(ku_extension) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to add KeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to add KeyUsage: {}",
                        e
                    ));
                }
            }
            match builder.sign(&signing_key, MessageDigest::sha256()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to sign certificate");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to sign certificate: {}",
                        e
                    ));
                }
            }
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
            let ku_extension = match ku.build() {
                Ok(ext) => ext,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to build KeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to build KeyUsage: {}",
                        e
                    ));
                }
            };
            match builder.append_extension(ku_extension) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to add KeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to add KeyUsage: {}",
                        e
                    ));
                }
            }

            // Admin status is encoded in the OU field during certificate creation
            // Admin certificates have " Admin" suffix in their OU field
            // This is checked during login in webserver.rs

            match builder.sign(&signing_key, MessageDigest::sha256()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to sign certificate");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to sign certificate: {}",
                        e
                    ));
                }
            }
        }
        CertificateDataType::TlsCert => {
            // Add Key Usage extension for TLS/HTTPS server certificate
            let ku = match KeyUsage::new()
                .critical()
                .digital_signature() // For TLS handshakes and signatures
                .key_encipherment() // For RSA key exchange in TLS
                .build()
            {
                Ok(ext) => ext,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to build KeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to build KeyUsage: {}",
                        e
                    ));
                }
            };
            match builder.append_extension(ku) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to add KeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to add KeyUsage: {}",
                        e
                    ));
                }
            }

            // Add Extended Key Usage: serverAuth (required for TLS/HTTPS servers)
            let eku = match ExtendedKeyUsage::new()
                .server_auth() // Explicitly mark as TLS server certificate
                .build()
            {
                Ok(ext) => ext,
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to build ExtendedKeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to build ExtendedKeyUsage: {}",
                        e
                    ));
                }
            };
            match builder.append_extension(eku) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to add ExtendedKeyUsage");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to add ExtendedKeyUsage: {}",
                        e
                    ));
                }
            }

            // Sign with intermediate CA's private key
            match builder.sign(&signing_key, MessageDigest::sha256()) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "generate_key_pair -> Failed to sign certificate");
                    return Err(anyhow!(
                        "generate_key_pair -> Failed to sign certificate: {}",
                        e
                    ));
                }
            }
        }
    }
    let x509_certificate = builder.build();
    Ok((private_key, x509_certificate))
}
