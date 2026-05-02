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

fn build_subject_name(cert_data: &CertificateData) -> anyhow::Result<openssl::x509::X509Name> {
    let mut name_builder = openssl::x509::X509Name::builder()?;
    name_builder.append_entry_by_nid(
        openssl::nid::Nid::COMMONNAME,
        &cert_data.subject_common_name,
    )?;
    name_builder
        .append_entry_by_nid(openssl::nid::Nid::ORGANIZATIONNAME, &cert_data.organization)?;
    name_builder.append_entry_by_nid(
        openssl::nid::Nid::ORGANIZATIONALUNITNAME,
        &cert_data.organizational_unit,
    )?;
    name_builder.append_entry_by_nid(openssl::nid::Nid::LOCALITYNAME, &cert_data.locality)?;
    name_builder.append_entry_by_nid(openssl::nid::Nid::STATEORPROVINCENAME, &cert_data.state)?;
    name_builder.append_entry_by_nid(openssl::nid::Nid::COUNTRYNAME, &cert_data.country)?;
    Ok(name_builder.build())
}

fn get_subject_name_from_signing_cert(
    issuer_cert: &openssl::x509::X509,
) -> anyhow::Result<openssl::x509::X509Name> {
    Ok(issuer_cert.subject_name().to_owned()?)
}

pub fn parse_certificate_data_from_json(
    request_json: &serde_json::Value,
    request_id: &String,
) -> anyhow::Result<CertificateData> {
    let cert_data = || -> anyhow::Result<CertificateData> {
        let subject_common_name = match request_json
            .pointer("/request/data/certificate_data/subject_common_name")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_certificate_data_from_json -> Request missing required field: subject_common_name. Request ID: {}", request_id);
                return Err(anyhow::anyhow!(
                "parse_certificate_data_from_json -> Request missing required field: subject_common_name. Request ID: {}", request_id
            ));
            }
        };
        let issuer_common_name = match request_json
            .pointer("/request/data/certificate_data/issuer_common_name")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::info!(
                    "parse_certificate_data_from_json -> request missing required field: issuer_common_name"
                );
                "None".to_string() // Default to "None" for issuer CN if not provided. It will be set outside this function based on the CA certificate's common name during certificate generation.
            }
        };
        let organization = match request_json
            .pointer("/request/data/certificate_data/organization")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("parse_certificate_data_from_json -> request missing required field: organization");
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: organization"
                ));
            }
        };
        let organizational_unit = match request_json
            .pointer("/request/data/certificate_data/organizational_unit")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "parse_certificate_data_from_json -> request missing required field: organizational_unit"
                );
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: organizational_unit"
                ));
            }
        };
        let locality = match request_json
            .pointer("/request/data/certificate_data/locality")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "parse_certificate_data_from_json -> request missing required field: locality"
                );
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: locality"
                ));
            }
        };
        let state = match request_json
            .pointer("/request/data/certificate_data/state")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "parse_certificate_data_from_json -> request missing required field: state"
                );
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: state"
                ));
            }
        };
        let country = match request_json
            .pointer("/request/data/certificate_data/country")
            .and_then(|v| v.as_str())
        {
            Some(s) => s.to_string(),
            None => {
                tracing::error!(
                    "parse_certificate_data_from_json -> request missing required field: country"
                );
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: country"
                ));
            }
        };
        let validity_days = match request_json
            .pointer("/request/data/certificate_data/validity_days")
            .and_then(|v| v.as_u64())
        {
            Some(vd) => vd as u32,
            None => {
                tracing::error!("parse_certificate_data_from_json -> request missing required field: validity_days");
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: validity_days"
                ));
            }
        };
        let cert_type = match request_json
            .pointer("/request/data/certificate_data/cert_type")
            .and_then(|v| v.as_str())
        {
            Some(s) => match s {
                "intermediate_ca" => CertificateDataType::IntermediateCA,
                "user_cert" => CertificateDataType::UserCert,
                "tls_cert" => CertificateDataType::TlsCert,
                _ => {
                    tracing::error!("parse_certificate_data_from_json -> Invalid cert_type value: {}. Must be one of: root_ca, intermediate_ca, user_cert, tls_cert", s);
                    return Err(anyhow::anyhow!(
                        "parse_certificate_data_from_json -> Invalid cert_type value: {}. Must be one of: root_ca, intermediate_ca, user_cert, tls_cert",
                        s
                    ));
                }
            },
            None => {
                tracing::error!(
                    "parse_certificate_data_from_json -> request missing required field: cert_type"
                );
                return Err(anyhow::anyhow!(
                    "parse_certificate_data_from_json -> request missing required field: cert_type"
                ));
            }
        };
        let is_admin = match request_json
            .pointer("/request/data/certificate_data/is_admin")
            .and_then(|v| v.as_bool())
        {
            Some(b) => b,
            None => {
                tracing::info!(
                    "parse_certificate_data_from_json -> request missing optional field: is_admin. Defaulting to true."
                );
                true // Default to true if not provided
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
            cert_type,
            is_admin,
        })
    }();
    match cert_data {
        Ok(data) => Ok(data),
        Err(e) => {
            tracing::error!(error = %e, "parse_certificate_data_from_json -> Failed to parse certificate data from JSON");
            Err(anyhow::anyhow!(
                "parse_certificate_data_from_json -> Failed to parse certificate data from JSON: {}",
                e
            ))
        }
    }
}

pub fn generate_root_ca(
    cert_data: CertificateData,
) -> anyhow::Result<(
    openssl::pkey::PKey<openssl::pkey::Private>,
    openssl::x509::X509,
)> {
    // Generate RSA key pair
    let rsa = match openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to generate RSA keypair");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to generate RSA keypair: {}",
                e
            ));
        }
    };
    let private_key = match openssl::pkey::PKey::from_rsa(rsa) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to create private key");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to create private key: {}",
                e
            ));
        }
    };
    // Build X509 certificate
    let mut builder = match openssl::x509::X509::builder() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to create X509 builder");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to create X509 builder: {}",
                e
            ));
        }
    };
    match builder.set_version(X509_VERSION_3) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to set version");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to set version: {}",
                e
            ));
        }
    }
    let subject_name = match build_subject_name(&cert_data) {
        Ok(name) => name,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to build subject name");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to build subject name: {}",
                e
            ));
        }
    };
    match builder.set_subject_name(&subject_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to set subject name");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to set subject name: {}",
                e
            ));
        }
    }
    // For root CA, issuer name is the same as subject name (self-signed)
    match builder.set_issuer_name(&subject_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to set issuer name");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to set issuer name: {}",
                e
            ));
        }
    }
    // Generate random 128-bit (16-byte) serial number
    let mut serial = match openssl::bn::BigNum::new() {
        Ok(bn) => bn,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to create BigNum");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to create BigNum: {}",
                e
            ));
        }
    };
    if let Err(e) = serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false) {
        tracing::error!(error = %e, "generate_root_ca -> Failed to generate random serial number");
        return Err(anyhow::anyhow!(
            "generate_root_ca -> Failed to generate random serial number: {}",
            e
        ));
    }
    let asn1_serial = match serial.to_asn1_integer() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to convert serial number to ASN1 integer");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to convert serial number to ASN1 integer: {}",
                e
            ));
        }
    };
    if let Err(e) = builder.set_serial_number(&asn1_serial) {
        tracing::error!(error = %e, "generate_root_ca -> Failed to set serial number");
        return Err(anyhow::anyhow!(
            "generate_root_ca -> Failed to set serial number: {}",
            e
        ));
    }
    // Set validity period
    let not_before = match openssl::asn1::Asn1Time::days_from_now(0) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to create not_before");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to create not_before: {}",
                e
            ));
        }
    };
    let not_after = match openssl::asn1::Asn1Time::days_from_now(cert_data.validity_days) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to create not_after");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to create not_after: {}",
                e
            ));
        }
    };
    match builder.set_not_before(&not_before) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to set not_before");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to set not_before: {}",
                e
            ));
        }
    }
    match builder.set_not_after(&not_after) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to set not_after");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to set not_after: {}",
                e
            ));
        }
    }
    match builder.set_pubkey(&private_key) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to set public key");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to set public key: {}",
                e
            ));
        }
    }
    let mut bc = openssl::x509::extension::BasicConstraints::new();
    bc.critical().ca();
    bc.pathlen(ROOT_CA_PATH_LENGTH);
    let extension = match bc.build() {
        Ok(ext) => ext,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to build BasicConstraints");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to build BasicConstraints: {}",
                e
            ));
        }
    };
    match builder.append_extension(extension) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to add BasicConstraints");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to add BasicConstraints: {}",
                e
            ));
        }
    }
    // Add Key Usage extension
    let mut ku = openssl::x509::extension::KeyUsage::new();
    ku.critical();
    ku.key_cert_sign();
    ku.crl_sign();
    ku.digital_signature();
    let ku_extension = match ku.build() {
        Ok(ext) => ext,
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to build KeyUsage");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to build KeyUsage: {}",
                e
            ));
        }
    };
    match builder.append_extension(ku_extension) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to add KeyUsage");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to add KeyUsage: {}",
                e
            ));
        }
    }
    match builder.sign(&private_key, openssl::hash::MessageDigest::sha256()) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_root_ca -> Failed to sign certificate");
            return Err(anyhow::anyhow!(
                "generate_root_ca -> Failed to sign certificate: {}",
                e
            ));
        }
    }

    let certificate = builder.build();
    Ok((private_key, certificate))
}

pub fn generate_intermediate_ca(
    cert_data: CertificateData,
    signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    signing_cert: &openssl::x509::X509,
) -> anyhow::Result<(
    openssl::pkey::PKey<openssl::pkey::Private>,
    openssl::x509::X509,
)> {
    let private_key = match openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT) {
        Ok(r) => match openssl::pkey::PKey::from_rsa(r) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create private key");
                return Err(anyhow::anyhow!(
                    "generate_intermediate_ca -> Failed to create private key: {}",
                    e
                ));
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to generate RSA keypair");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to generate RSA keypair: {}",
                e
            ));
        }
    };
    // Build X509 certificate
    let mut builder = match openssl::x509::X509::builder() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create X509 builder");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to create X509 builder: {}",
                e
            ));
        }
    };
    match builder.set_version(X509_VERSION_3) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set version");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set version: {}",
                e
            ));
        }
    }
    let subject_name = match build_subject_name(&cert_data) {
        Ok(name) => name,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to build subject name");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to build subject name: {}",
                e
            ));
        }
    };
    match builder.set_subject_name(&subject_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set subject name");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set subject name: {}",
                e
            ));
        }
    }
    // For intermediate CA, issuer name is taken from root certificate's subject name
    let issuer_name = get_subject_name_from_signing_cert(signing_cert)?;
    match builder.set_issuer_name(&issuer_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set issuer name");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set issuer name: {}",
                e
            ));
        }
    }
    // Set validity period
    let not_before = match openssl::asn1::Asn1Time::days_from_now(0) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create not_before");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to create not_before: {}",
                e
            ));
        }
    };
    let not_after = match openssl::asn1::Asn1Time::days_from_now(cert_data.validity_days) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create not_after");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to create not_after: {}",
                e
            ));
        }
    };
    match builder.set_not_before(&not_before) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set not_before");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set not_before: {}",
                e
            ));
        }
    }
    match builder.set_not_after(&not_after) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set not_after");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set not_after: {}",
                e
            ));
        }
    }
    match builder.set_pubkey(&private_key) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set public key");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set public key: {}",
                e
            ));
        }
    }
    let mut bc = openssl::x509::extension::BasicConstraints::new();
    bc.critical().ca();
    bc.pathlen(INTERMEDIATE_CA_PATH_LENGTH);
    let extension = match bc.build() {
        Ok(ext) => ext,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to build BasicConstraints");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to build BasicConstraints: {}",
                e
            ));
        }
    };
    match builder.append_extension(extension) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to add BasicConstraints");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to add BasicConstraints: {}",
                e
            ));
        }
    }
    // Add Key Usage extension
    let mut ku = openssl::x509::extension::KeyUsage::new();
    ku.critical();
    ku.key_cert_sign();
    ku.crl_sign();
    ku.digital_signature();
    let ku_extension = match ku.build() {
        Ok(ext) => ext,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to build KeyUsage");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to build KeyUsage: {}",
                e
            ));
        }
    };
    match builder.append_extension(ku_extension) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to add KeyUsage");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to add KeyUsage: {}",
                e
            ));
        }
    }
    match builder.sign(&signing_key, openssl::hash::MessageDigest::sha256()) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to sign certificate");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to sign certificate: {}",
                e
            ));
        }
    }
    let certificate = builder.build();
    Ok((private_key, certificate))
}

pub fn generate_user_cert_and_private_key(
    cert_data: CertificateData,
    signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    signing_cert: &openssl::x509::X509,
) -> anyhow::Result<(
    openssl::pkey::PKey<openssl::pkey::Private>,
    openssl::x509::X509,
)> {
    // For user certs, we generate a new key pair and sign with the provided signing key/cert
    let private_key = match openssl::rsa::Rsa::generate(RSA_KEY_SIZE_DEFAULT) {
        Ok(r) => match openssl::pkey::PKey::from_rsa(r) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create private key");
                return Err(anyhow::anyhow!(
                    "generate_intermediate_ca -> Failed to create private key: {}",
                    e
                ));
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to generate RSA keypair");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to generate RSA keypair: {}",
                e
            ));
        }
    };
    // Build X509 certificate
    let mut builder = match openssl::x509::X509::builder() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create X509 builder");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to create X509 builder: {}",
                e
            ));
        }
    };
    match builder.set_version(X509_VERSION_3) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set version");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set version: {}",
                e
            ));
        }
    }
    let subject_name = match build_subject_name(&cert_data) {
        Ok(name) => name,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to build subject name");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to build subject name: {}",
                e
            ));
        }
    };
    match builder.set_subject_name(&subject_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set subject name");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set subject name: {}",
                e
            ));
        }
    }
    // For user certificates, issuer name is taken from intermediate certificate's subject name
    let issuer_name = get_subject_name_from_signing_cert(signing_cert)?;
    match builder.set_issuer_name(&issuer_name) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set issuer name");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set issuer name: {}",
                e
            ));
        }
    }
    // Set validity period
    let not_before = match openssl::asn1::Asn1Time::days_from_now(0) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create not_before");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to create not_before: {}",
                e
            ));
        }
    };
    let not_after = match openssl::asn1::Asn1Time::days_from_now(cert_data.validity_days) {
        Ok(time) => time,
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to create not_after");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to create not_after: {}",
                e
            ));
        }
    };
    match builder.set_not_before(&not_before) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set not_before");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set not_before: {}",
                e
            ));
        }
    }
    match builder.set_not_after(&not_after) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set not_after");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set not_after: {}",
                e
            ));
        }
    }
    match builder.set_pubkey(&private_key) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_intermediate_ca -> Failed to set public key");
            return Err(anyhow::anyhow!(
                "generate_intermediate_ca -> Failed to set public key: {}",
                e
            ));
        }
    }
    let mut bc = openssl::x509::extension::BasicConstraints::new();
    bc.critical();
    let mut ku = openssl::x509::extension::KeyUsage::new();
    ku.critical();
    ku.digital_signature(); // For digital signatures
    ku.non_repudiation(); // For non-repudiation
    ku.key_encipherment(); // For encrypting symmetric keys
    ku.data_encipherment(); // For encrypting data directly
    let ku_extension = match ku.build() {
        Ok(ext) => ext,
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to build KeyUsage");
            return Err(anyhow::anyhow!(
                "generate_key_pair -> Failed to build KeyUsage: {}",
                e
            ));
        }
    };
    match builder.append_extension(ku_extension) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to add KeyUsage");
            return Err(anyhow::anyhow!(
                "generate_key_pair -> Failed to add KeyUsage: {}",
                e
            ));
        }
    }

    // Admin status is derived from the user cert being signed by the admin intermediate CA.
    // The admin intermediate CA is created by the service upon startup and has a specific common name (e.g. "Admin Intermediate CA").
    match builder.sign(&signing_key, openssl::hash::MessageDigest::sha256()) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "generate_key_pair -> Failed to sign certificate");
            return Err(anyhow::anyhow!(
                "generate_key_pair -> Failed to sign certificate: {}",
                e
            ));
        }
    }
    let certificate = builder.build();
    Ok((private_key, certificate))
}
