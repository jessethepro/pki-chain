use keyutils::keytypes::encrypted;
use openssl::encrypt;

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
    pub fn create_storage(self) -> anyhow::Result<Storage<Created>> {
        let certificate_chain = libblockchain::blockchain::open_read_write_chain(
            match self.app_config.blockchains.certificate_path.to_str() {
                Some(path) => path,
                None => anyhow::bail!("Invalid certificate chain path"),
            },
        )?;
        let private_key_chain = libblockchain::blockchain::open_read_write_chain(
            match self.app_config.blockchains.private_key_path.to_str() {
                Some(path) => path,
                None => anyhow::bail!("Invalid private key chain path"),
            },
        )?;
        let crl_chain = libblockchain::blockchain::open_read_write_chain(
            match self.app_config.blockchains.crl_path.to_str() {
                Some(path) => path,
                None => anyhow::bail!("Invalid CRL chain path"),
            },
        )?;
        Ok(Storage {
            state: Created {
                certificate_chain,
                private_key_chain,
                crl_chain,
            },
            app_config: self.app_config,
        })
    }
}

pub struct Created {
    certificate_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    private_key_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
    crl_chain: libblockchain::blockchain::BlockChain<libblockchain::blockchain::ReadWrite>,
}

impl Storage<Created> {
    pub fn initialize_storage(self) -> anyhow::Result<Storage<Initialized>> {
        let (private_key, cert) = || -> anyhow::Result<(openssl::pkey::PKey<openssl::pkey::Private>, openssl::x509::X509)> {
            use crate::pki_generator::{generate_root_ca, CertificateData, CertificateDataType};
            let validity_days = 365 * 5;
            let cert_data = CertificateData {
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
                cert_type: CertificateDataType::RootCA,
                is_admin: false,
            };
            Ok(generate_root_ca(cert_data)?)
        }()?;
        let app_public_key = self.get_app_public_key()?;
        let encrypted_private_key = crate::encryption::encrypt_data(
            &private_key.private_key_to_der()?,
            app_public_key.clone(),
        )?;
        let encrypted_cert = crate::encryption::encrypt_data(&cert.to_der()?, app_public_key)?;

        let cert_height = self
            .state
            .certificate_chain
            .put_block(encrypted_cert)
            .or_else(|err| {
                self.state.private_key_chain.delete_last_block()?;
                Err(anyhow::anyhow!(err))
            })?;

        let key_height = self
            .state
            .private_key_chain
            .put_block(encrypted_private_key)
            .or_else(|err| {
                self.state.certificate_chain.delete_last_block()?;
                Err(anyhow::anyhow!(err))
            })?;
        if key_height != cert_height {
            self.state.certificate_chain.delete_last_block()?;
            self.state.private_key_chain.delete_last_block()?;
            anyhow::bail!("Failed to initialize storage: height mismatch");
        } else {
            Ok(Storage {
                state: Initialized {
                    certificate_chain: self.state.certificate_chain,
                    private_key_chain: self.state.private_key_chain,
                    crl_chain: self.state.crl_chain,
                },
                app_config: self.app_config,
            })
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
        self,
        admin_user_certificate_data: crate::pki_generator::CertificateData,
    ) -> anyhow::Result<Storage<Ready>> {
        let root_private_key = self.get_root_private_key()?;
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
            crate::pki_generator::generate_key_pair(
                admin_intermediate_certificate_data,
                &root_private_key,
            )?;
        let app_pub_key = self.get_app_public_key()?;
        let encrypted_admin_intermdiate_cert = crate::encryption::encrypt_data(
            &admin_intermediate_cert.to_der()?,
            app_pub_key.clone(),
        )?;
        let cert_height = self
            .state
            .certificate_chain
            .put_block(encrypted_admin_intermdiate_cert)?;
        let encrypted_admin_intermediate_key = crate::encryption::encrypt_data(
            &admin_intermediate_key.private_key_to_der()?,
            app_pub_key.clone(),
        )?;
        let key_height = self
            .state
            .private_key_chain
            .put_block(encrypted_admin_intermediate_key)
            .or_else(|err| {
                self.state.certificate_chain.delete_last_block()?;
                Err(anyhow::anyhow!(err))
            })?;
        if key_height != cert_height {
            self.state.certificate_chain.delete_last_block()?;
            self.state.private_key_chain.delete_last_block()?;
            return Err(anyhow::anyhow!(
                "Failed to add admin certificate and key: height mismatch"
            ));
        }
        let (admin_user_key, admin_user_cert) = crate::pki_generator::generate_key_pair(
            admin_user_certificate_data,
            &admin_intermediate_key,
        )?;
        let encrypted_admin_user_cert =
            crate::encryption::encrypt_data(&admin_user_cert.to_der()?, app_pub_key.clone())?;
        let encrypted_admin_user_key = crate::encryption::encrypt_data(
            &admin_user_key.private_key_to_der()?,
            app_pub_key.clone(),
        )?;
        let cert_height = self
            .state
            .certificate_chain
            .put_block(encrypted_admin_user_cert)?;
        let key_height = self
            .state
            .private_key_chain
            .put_block(encrypted_admin_user_key)
            .or_else(|err| {
                self.state.certificate_chain.delete_last_block()?;
                Err(anyhow::anyhow!(err))
            })?;
        if key_height != cert_height {
            self.state.certificate_chain.delete_last_block()?;
            self.state.private_key_chain.delete_last_block()?;
            return Err(anyhow::anyhow!(
                "Failed to add admin user certificate and key: height mismatch"
            ));
        } else {
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
    pub fn add_admin(
        &self,
        admin_cert: &openssl::x509::X509,
        admin_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> anyhow::Result<()> {
        let root_private_key = self.get_root_private_key()?;
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
            crate::pki_generator::generate_key_pair(
                admin_intermediate_certificate_data,
                &root_private_key,
            )?;
        let app_pub_key = self.get_app_public_key()?;
        let encrypted_admin_intermdiate_cert = crate::encryption::encrypt_data(
            &admin_intermediate_cert.to_der()?,
            app_pub_key.clone(),
        )?;
        let cert_height = self
            .state
            .certificate_chain
            .put_block(encrypted_admin_intermdiate_cert)?;
        let encrypted_admin_intermediate_key = crate::encryption::encrypt_data(
            &admin_intermediate_key.private_key_to_der()?,
            app_pub_key.clone(),
        )?;
        let encrypted_admin_intermediate_key = crate::encryption::encrypt_data(
            &admin_intermediate_key.private_key_to_der()?,
            app_pub_key.clone(),
        )?;
        let key_height = self
            .state
            .private_key_chain
            .put_block(encrypted_admin_intermediate_key)
            .or_else(|err| {
                self.state.certificate_chain.delete_last_block()?;
                Err(anyhow::anyhow!(err))
            })?;
        if key_height != cert_height {
            self.state.certificate_chain.delete_last_block()?;
            self.state.private_key_chain.delete_last_block()?;
            return Err(anyhow::anyhow!(
                "Failed to add admin certificate and key: height mismatch"
            ));
        }
        let encrypted_admin_cert =
            crate::encryption::encrypt_data(&admin_cert.to_der()?, app_pub_key.clone())?;
        let cert_height = self
            .state
            .certificate_chain
            .put_block(encrypted_admin_cert)?;
        let encrypted_admin_key =
            crate::encryption::encrypt_data(&admin_key.private_key_to_der()?, app_pub_key)?;
        let key_height = self
            .state
            .private_key_chain
            .put_block(encrypted_admin_key)
            .or_else(|err| {
                self.state.certificate_chain.delete_last_block()?;
                Err(anyhow::anyhow!(err))
            })?;
        if key_height != cert_height {
            self.state.certificate_chain.delete_last_block()?;
            self.state.private_key_chain.delete_last_block()?;
            return Err(anyhow::anyhow!(
                "Failed to add admin certificate and key: height mismatch"
            ));
        }
        Ok(())
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
