macro_rules! impl_app_key_funcs {
    ($state:ty) => {
        impl Storage<$state> {
            fn get_app_public_key(
                &self,
            ) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Public>> {
                let public_key_pem = std::fs::read(&self.app_config.key_exports.app_cert_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read public key PEM file: {}", e))?;
                let public_key = openssl::pkey::PKey::public_key_from_pem(
                    public_key_pem.as_slice(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to load public key from PEM: {}", e))?;
                Ok(public_key)
            }

            fn get_app_private_key(
                &self,
            ) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                let private_key_pem = std::fs::read(&self.app_config.key_exports.app_key_path)
                    .map_err(|e| anyhow::anyhow!("Failed to read private key PEM file: {}", e))?;
                let private_key = openssl::pkey::PKey::private_key_from_pem(
                    private_key_pem.as_slice(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to load private key from PEM: {}", e))?;
                Ok(private_key)
            }
        }
    };
}

macro_rules! impl_root_key_funcs {
    ($state: ty) => {
        impl Storage<$state> {
            fn get_root_private_key(
                &self,
            ) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                let block_count = self.state.private_key_chain.block_count()?;
                if block_count == 0 {
                    anyhow::bail!("No private keys found in the chain");
                }
                let encrypted_root_key_block =
                    self.state.private_key_chain.get_block_by_height(0)?;
                let app_private_key =
                    || -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                        let key_pem =
                            std::fs::read(self.app_config.key_exports.app_key_path.clone())?;
                        Ok(openssl::pkey::PKey::private_key_from_pem(&key_pem)?)
                    }()?;
                let decrypted_root_key_der = crate::encryption::decrypt_data(
                    encrypted_root_key_block.block_data().as_slice(),
                    app_private_key,
                )?;
                Ok(openssl::pkey::PKey::private_key_from_der(
                    &decrypted_root_key_der,
                )?)
            }

            fn get_root_public_key(
                &self,
            ) -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Public>> {
                let block_count = self.state.certificate_chain.block_count()?;
                if block_count == 0 {
                    anyhow::bail!("No certificates found in the chain");
                }
                let encrypted_root_cert_block =
                    self.state.certificate_chain.get_block_by_height(0)?;
                let app_private_key =
                    || -> anyhow::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                        let key_pem =
                            std::fs::read(self.app_config.key_exports.app_key_path.clone())?;
                        Ok(openssl::pkey::PKey::private_key_from_pem(&key_pem)?)
                    }()?;
                let decrypted_root_cert_der = crate::encryption::decrypt_data(
                    encrypted_root_cert_block.block_data().as_slice(),
                    app_private_key,
                )?;
                let root_cert = openssl::x509::X509::from_der(&decrypted_root_cert_der)?;
                Ok(root_cert.public_key()?)
            }
        }
    };
}

impl_app_key_funcs!(Initialized);
impl_app_key_funcs!(Created);
impl_root_key_funcs!(Initialized);

pub struct Storage<State> {
    pub state: State,
    pub app_config: crate::configs::AppConfig,
}

pub struct Empty {}

impl Storage<Empty> {
    pub fn create_storage(self) -> Storage<Created> {
        let certificate_chain = match libblockchain::blockchain::open_read_write_chain(
            self.app_config
                .blockchains
                .certificate_path
                .to_str()
                .expect("Failed to parse certificate path from app_config"),
        ) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Empty>: Failed to open certificate chain.");
                std::process::exit(1);
            }
        };
        let private_key_chain = match libblockchain::blockchain::open_read_write_chain(
            self.app_config
                .blockchains
                .private_key_path
                .to_str()
                .expect("Failed to parse private key path from app_config"),
        ) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Empty>: Failed to open private key chain.");
                std::process::exit(1);
            }
        };
        let crl_chain = match libblockchain::blockchain::open_read_write_chain(
            self.app_config
                .blockchains
                .crl_path
                .to_str()
                .expect("Failed to parse CRL path from app_config"),
        ) {
            Ok(chain) => chain,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Empty>: Failed to open CRL chain.");
                std::process::exit(1);
            }
        };
        Storage {
            state: Created {
                certificate_chain,
                private_key_chain,
                crl_chain,
            },
            app_config: self.app_config,
        }
    }
}

pub struct Created {
    certificate_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    private_key_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    crl_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
}

impl Storage<Created> {
    pub fn initialize_storage(self) -> Storage<Initialized> {
        let (private_key, cert) = || -> (openssl::pkey::PKey<openssl::pkey::Private>, openssl::x509::X509) {
            let validity_days = 365 * 5;
            let cert_data = crate::pki_generator::CertificateData {
                subject_common_name: self.app_config.root_ca_defaults.root_ca_common_name.clone(),
                issuer_common_name: self.app_config.root_ca_defaults.root_ca_common_name.clone(),
                organization: self
                    .app_config
                    .root_ca_defaults
                    .root_ca_organization
                    .clone(),
                organizational_unit: self
                    .app_config
                    .root_ca_defaults
                    .root_ca_organizational_unit
                    .clone(),
                locality: self.app_config.root_ca_defaults.root_ca_locality.clone(),
                state: self.app_config.root_ca_defaults.root_ca_state.clone(),
                country: self.app_config.root_ca_defaults.root_ca_country.clone(),
                validity_days,
                cert_type: crate::pki_generator::CertificateDataType::RootCA,
                is_admin: false,
            };
            match crate::pki_generator::generate_root_ca(cert_data) {
                Ok((private_key, cert)) => (private_key, cert),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Created>: Failed to generate root CA.");
                    std::process::exit(1);
                }
            }
        }();
        let app_public_key = match self.get_app_public_key() {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Created>: Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let encrypted_private_key = match crate::encryption::encrypt_data(
            match &private_key.private_key_to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Created>: Failed to convert root private key to DER.");
                    std::process::exit(1);
                }
            },
            app_public_key.clone(),
        ) {
            Ok(encrypted_key) => encrypted_key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Created>: Failed to encrypt root private key.");
                std::process::exit(1);
            }
        };
        let encrypted_cert = match crate::encryption::encrypt_data(
            &match cert.to_der() {
                Ok(der) => der,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Created>: Failed to convert root certificate to DER.");
                    std::process::exit(1);
                }
            },
            app_public_key,
        ) {
            Ok(encrypted_cert) => encrypted_cert,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Created>: Failed to encrypt root certificate.");
                std::process::exit(1);
            }
        };

        let cert_height = match self.state.certificate_chain.put_block(encrypted_cert) {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Created>: Failed to put root certificate block.");
                std::process::exit(1);
            }
        };

        let key_height = match self
            .state
            .private_key_chain
            .put_block(encrypted_private_key)
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Created>: Failed to put root private key block.");
                std::process::exit(1);
            }
        };

        if key_height != cert_height {
            match self.state.certificate_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Created>: Failed to delete last certificate block.");
                    std::process::exit(1);
                }
            }
            match self.state.private_key_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Created>: Failed to delete last private key block.");
                    std::process::exit(1);
                }
            }
        }
        Storage {
            state: Initialized {
                certificate_chain: self.state.certificate_chain,
                private_key_chain: self.state.private_key_chain,
                crl_chain: self.state.crl_chain,
            },
            app_config: self.app_config,
        }
    }
}

pub struct Initialized {
    pub certificate_chain:
        libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    pub private_key_chain:
        libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    pub crl_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
}

impl Storage<Initialized> {
    pub fn add_admin_user(
        &self,
        admin_user_certificate_data: crate::pki_generator::CertificateData,
    ) -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let root_private_key = match self.get_root_private_key() {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to get root private key.");
                std::process::exit(1);
            }
        };
        let admin_intermediate_certificate_data = crate::pki_generator::CertificateData {
            subject_common_name: "Admin Intermediate CA".to_string(),
            issuer_common_name: self.app_config.root_ca_defaults.root_ca_common_name.clone(),
            organization: self
                .app_config
                .root_ca_defaults
                .root_ca_organization
                .clone(),
            organizational_unit: self
                .app_config
                .root_ca_defaults
                .root_ca_organizational_unit
                .clone(),
            locality: self.app_config.root_ca_defaults.root_ca_locality.clone(),
            state: self.app_config.root_ca_defaults.root_ca_state.clone(),
            country: self.app_config.root_ca_defaults.root_ca_country.clone(),
            validity_days: 365 * 3,
            cert_type: crate::pki_generator::CertificateDataType::IntermediateCA,
            is_admin: false,
        };
        let (admin_intermediate_key, admin_intermediate_cert) =
            match crate::pki_generator::generate_key_pair(
                admin_intermediate_certificate_data,
                &root_private_key,
            ) {
                Ok((key, cert)) => (key, cert),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to generate admin intermediate key pair.");
                    std::process::exit(1);
                }
            };
        let app_pub_key = match self.get_app_public_key() {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to get app public key.");
                std::process::exit(1);
            }
        };
        let encrypted_admin_intermdiate_cert = match crate::encryption::encrypt_data(
            &match admin_intermediate_cert.to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin intermediate certificate to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin intermediate certificate.");
                std::process::exit(1);
            }
        };
        let cert_height = match self
            .state
            .certificate_chain
            .put_block(encrypted_admin_intermdiate_cert)
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin intermediate certificate to chain.");
                std::process::exit(1);
            }
        };
        let encrypted_admin_intermediate_key = match crate::encryption::encrypt_data(
            &match admin_intermediate_key.private_key_to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin intermediate private key to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin intermediate private key.");
                std::process::exit(1);
            }
        };
        let key_height = match self
            .state
            .private_key_chain
            .put_block(encrypted_admin_intermediate_key)
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin intermediate private key to chain.");
                std::process::exit(1);
            }
        };
        if key_height != cert_height {
            match self.state.certificate_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from certificate chain.");
                    std::process::exit(1);
                }
            }
            match self.state.private_key_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from private key chain.");
                    std::process::exit(1);
                }
            }
        }
        let (admin_user_key, admin_user_cert) = match crate::pki_generator::generate_key_pair(
            admin_user_certificate_data,
            &admin_intermediate_key,
        ) {
            Ok((key, cert)) => (key, cert),
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to generate admin user key pair.");
                std::process::exit(1);
            }
        };
        let encrypted_admin_user_cert = match crate::encryption::encrypt_data(
            &match admin_user_cert.to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin user certificate to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin user certificate.");
                std::process::exit(1);
            }
        };
        let encrypted_admin_user_key = match crate::encryption::encrypt_data(
            &match admin_user_key.private_key_to_der() {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to convert admin user private key to DER.");
                    std::process::exit(1);
                }
            },
            app_pub_key.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to encrypt admin user private key.");
                std::process::exit(1);
            }
        };
        let cert_height = match self
            .state
            .certificate_chain
            .put_block(encrypted_admin_user_cert)
        {
            Ok(height) => height,
            Err(e) => {
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin user certificate to chain.");
                std::process::exit(1);
            }
        };
        let key_height = match self
            .state
            .private_key_chain
            .put_block(encrypted_admin_user_key)
        {
            Ok(height) => height,
            Err(e) => {
                match self.state.certificate_chain.delete_last_block() {
                    Ok(_) => (),
                    Err(e) => {
                        tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from certificate chain.");
                        std::process::exit(1);
                    }
                }
                tracing::error!(error = %e, "Storage<Initialized>: Failed to add admin user private key to chain.");
                std::process::exit(1);
            }
        };
        if key_height != cert_height {
            match self.state.certificate_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from certificate chain.");
                    std::process::exit(1);
                }
            }
            match self.state.private_key_chain.delete_last_block() {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(error = %e, "Storage<Initialized>: Failed to delete last block from private key chain.");
                    std::process::exit(1);
                }
            }
        }
        (admin_user_cert, admin_user_key)
    }
}

pub struct Ready {
    certificate_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    private_key_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    crl_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
}

pub struct API {
    certificate_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadOnly>,
    private_key_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadOnly>,
    crl_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadOnly>,
}

impl_app_key_funcs!(API);

impl Storage<API> {
    pub fn get_certificate_by_serial(
        &self,
        cert_serial: openssl::bn::BigNum,
    ) -> anyhow::Result<(openssl::x509::X509, u64)> {
        let app_key = self.get_app_private_key()?;
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 1..block_count {
            let cert_block = self.state.certificate_chain.get_block_by_height(i)?;
            let decrypted_cert_der = crate::encryption::decrypt_data(
                cert_block.block_data().as_slice(),
                app_key.clone(),
            )?;
            let cert = openssl::x509::X509::from_der(&decrypted_cert_der)?;
            if cert.serial_number().to_bn()? == cert_serial {
                return Ok((cert, i));
            }
        }
        Err(anyhow::anyhow!(
            "Certificate with serial number {} not found",
            cert_serial.to_dec_str()?
        ))
    }

    pub fn get_certificate_by_common_name(
        &self,
        common_name: &str,
    ) -> anyhow::Result<(openssl::x509::X509, u64)> {
        let app_key = self.get_app_private_key()?;
        let block_count = self.state.certificate_chain.block_count()?;
        for i in 1..block_count {
            let cert_block = self.state.certificate_chain.get_block_by_height(i)?;
            let decrypted_cert_der = crate::encryption::decrypt_data(
                cert_block.block_data().as_slice(),
                app_key.clone(),
            )?;
            let cert = openssl::x509::X509::from_der(&decrypted_cert_der)?;
            if cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .any(|entry| {
                    entry
                        .data()
                        .as_utf8()
                        .map_or(false, |data| data.to_string() == common_name)
                })
            {
                return Ok((cert, i));
            }
        }
        Err(anyhow::anyhow!(
            "Certificate with common name '{}' not found",
            common_name
        ))
    }
}

pub struct Admin {
    certificate_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    private_key_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    crl_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
}

impl Storage<Admin> {
    pub fn open(self, storage: Storage<Ready>) -> anyhow::Result<Storage<Admin>> {
        Ok(Storage {
            state: Admin {
                certificate_chain: storage.state.certificate_chain,
                private_key_chain: storage.state.private_key_chain,
                crl_chain: storage.state.crl_chain,
            },
            app_config: self.app_config,
        })
    }
    pub fn close(self) -> anyhow::Result<Storage<Ready>> {
        Ok(Storage {
            state: Ready {
                certificate_chain: self.state.certificate_chain,
                private_key_chain: self.state.private_key_chain,
                crl_chain: self.state.crl_chain,
            },
            app_config: self.app_config,
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum StorageState {
    NotFound,
    Empty,
    Created,
    Initialized,
    Ready,
    Inconsistent,
}

fn validate_blockchain_store(path: &std::path::Path) -> anyhow::Result<StorageState> {
    match path.exists() {
        true => match path.is_dir() {
            true => {
                let mut entries = std::fs::read_dir(path)?.peekable();
                if entries.peek().is_some() {
                    Ok(StorageState::Created)
                } else {
                    Ok(StorageState::Empty)
                }
            }
            false => Ok(StorageState::NotFound),
        },
        false => Ok(StorageState::NotFound),
    }
}

pub fn get_storage_state(app_config: &crate::configs::AppConfig) -> anyhow::Result<StorageState> {
    let cert_store_state = validate_blockchain_store(&app_config.blockchains.certificate_path)?;
    let key_store_state = validate_blockchain_store(&app_config.blockchains.private_key_path)?;
    let crl_store_state = validate_blockchain_store(&app_config.blockchains.crl_path)?;
    if cert_store_state == key_store_state && key_store_state == crl_store_state {
        match cert_store_state {
            StorageState::NotFound => Ok(StorageState::NotFound),
            StorageState::Empty => Ok(StorageState::Empty),
            StorageState::Created => {
                let cert_chain = libblockchain::blockchain::BlockChain::open_read_only(
                    match app_config.blockchains.certificate_path.to_str() {
                        Some(path) => path,
                        None => anyhow::bail!("Invalid certificate chain path"),
                    },
                )?;
                let private_key_chain = libblockchain::blockchain::BlockChain::open_read_only(
                    match app_config.blockchains.private_key_path.to_str() {
                        Some(path) => path,
                        None => anyhow::bail!("Invalid private key chain path"),
                    },
                )?;
                let crl_chain = libblockchain::blockchain::BlockChain::open_read_only(
                    match app_config.blockchains.crl_path.to_str() {
                        Some(path) => path,
                        None => anyhow::bail!("Invalid CRL chain path"),
                    },
                )?;
                let cert_count = cert_chain.block_count()?;
                let private_key_count = private_key_chain.block_count()?;
                let crl_count = crl_chain.block_count()?;
                if cert_count == 0 && private_key_count == 0 && crl_count >= 0 {
                    Ok(StorageState::Empty)
                } else if cert_count == 1 && private_key_count == 1 && crl_count >= 0 {
                    Ok(StorageState::Initialized)
                } else if cert_count == private_key_count && crl_count >= 0 {
                    Ok(StorageState::Ready)
                } else {
                    Ok(StorageState::Inconsistent)
                }
            }
            _ => Ok(StorageState::Inconsistent), // Should never happen since all three states are the same
        }
    } else {
        Ok(StorageState::Inconsistent)
    }
}

pub fn get_api_storage(app_config: crate::configs::AppConfig) -> anyhow::Result<Storage<API>> {
    match get_storage_state(&app_config)? {
        StorageState::NotFound => anyhow::bail!("Storage not found"),
        StorageState::Empty => anyhow::bail!("Storage is empty, initialization required"),
        StorageState::Created => anyhow::bail!("Storage created but not initialized"),
        StorageState::Initialized => anyhow::bail!("Storage initialized but not ready"),
        StorageState::Inconsistent => anyhow::bail!("Storage is in an inconsistent state"),
        StorageState::Ready => (),
    }
    Ok(Storage {
        state: API {
            certificate_chain: libblockchain::blockchain::open_read_only_chain(
                match app_config.blockchains.certificate_path.to_str() {
                    Some(path) => path,
                    None => anyhow::bail!("Invalid certificate chain path"),
                },
            )?,
            private_key_chain: libblockchain::blockchain::open_read_only_chain(
                match app_config.blockchains.private_key_path.to_str() {
                    Some(path) => path,
                    None => anyhow::bail!("Invalid private key chain path"),
                },
            )?,
            crl_chain: libblockchain::blockchain::open_read_only_chain(
                match app_config.blockchains.crl_path.to_str() {
                    Some(path) => path,
                    None => anyhow::bail!("Invalid CRL chain path"),
                },
            )?,
        },
        app_config,
    })
}

pub fn get_storage_empty(app_config: crate::configs::AppConfig) -> anyhow::Result<Storage<Empty>> {
    match get_storage_state(&app_config) {
        Ok(StorageState::NotFound) | Ok(StorageState::Empty) => (),
        Ok(StorageState::Created) | Ok(StorageState::Initialized) | Ok(StorageState::Ready) => {
            anyhow::bail!("Storage already exists, cannot create new storage")
        }
        Ok(StorageState::Inconsistent) => {
            anyhow::bail!("Storage is in an inconsistent state, manual intervention required")
        }
        Err(e) => {
            anyhow::bail!("Failed to determine storage state: {}", e);
        }
    }
    Ok(Storage {
        state: Empty {},
        app_config,
    })
}

pub fn get_storage_created(
    app_config: crate::configs::AppConfig,
) -> anyhow::Result<Storage<Created>> {
    match get_storage_state(&app_config) {
        Ok(StorageState::NotFound) | Ok(StorageState::Empty) => {
            anyhow::bail!("Storage not found or empty, cannot open existing storage")
        }
        Ok(StorageState::Created) => (),
        Ok(StorageState::Initialized) | Ok(StorageState::Ready) => {
            anyhow::bail!("Storage already initialized, cannot open in created state")
        }
        Ok(StorageState::Inconsistent) => {
            anyhow::bail!("Storage is in an inconsistent state, manual intervention required")
        }
        Err(e) => {
            anyhow::bail!("Failed to determine storage state: {}", e);
        }
    }
    Ok(Storage {
        state: Created {
            certificate_chain: libblockchain::blockchain::open_read_write_chain(match app_config
                .blockchains
                .certificate_path
                .to_str()
            {
                Some(path) => path,
                None => anyhow::bail!("Invalid certificate chain path"),
            })?,
            private_key_chain: libblockchain::blockchain::open_read_write_chain(match app_config
                .blockchains
                .private_key_path
                .to_str()
            {
                Some(path) => path,
                None => anyhow::bail!("Invalid private key chain path"),
            })?,
            crl_chain: libblockchain::blockchain::open_read_write_chain(
                match app_config.blockchains.crl_path.to_str() {
                    Some(path) => path,
                    None => anyhow::bail!("Invalid CRL chain path"),
                },
            )?,
        },
        app_config,
    })
}

pub fn get_storage_initialized(
    app_config: crate::configs::AppConfig,
) -> anyhow::Result<Storage<Initialized>> {
    match get_storage_state(&app_config) {
        Ok(StorageState::NotFound) | Ok(StorageState::Empty) | Ok(StorageState::Created) => {
            anyhow::bail!(
                "Storage not found, empty, or not initialized, cannot open in initialized state"
            )
        }
        Ok(StorageState::Initialized) => (),
        Ok(StorageState::Ready) => {
            anyhow::bail!("Storage already ready, cannot open in initialized state")
        }
        Ok(StorageState::Inconsistent) => {
            anyhow::bail!("Storage is in an inconsistent state, manual intervention required")
        }
        Err(e) => {
            anyhow::bail!("Failed to determine storage state: {}", e);
        }
    }
    Ok(Storage {
        state: Initialized {
            certificate_chain: libblockchain::blockchain::open_read_write_chain(match app_config
                .blockchains
                .certificate_path
                .to_str()
            {
                Some(path) => path,
                None => anyhow::bail!("Invalid certificate chain path"),
            })?,
            private_key_chain: libblockchain::blockchain::open_read_write_chain(match app_config
                .blockchains
                .private_key_path
                .to_str()
            {
                Some(path) => path,
                None => anyhow::bail!("Invalid private key chain path"),
            })?,
            crl_chain: libblockchain::blockchain::open_read_write_chain(
                match app_config.blockchains.crl_path.to_str() {
                    Some(path) => path,
                    None => anyhow::bail!("Invalid CRL chain path"),
                },
            )?,
        },
        app_config,
    })
}
