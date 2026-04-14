pub struct Admin {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
}

impl crate::storage::Storage<Admin> {
    pub fn open(
        self,
        storage: crate::storage::Storage<crate::storage_ready::Ready>,
    ) -> anyhow::Result<crate::storage::Storage<Admin>> {
        Ok(crate::storage::Storage {
            state: Admin {
                certificate_chain: storage.state.certificate_chain,
                private_key_chain: storage.state.private_key_chain,
                crl_chain: storage.state.crl_chain,
            },
            app_config: self.app_config,
        })
    }
    pub fn close(self) -> anyhow::Result<crate::storage::Storage<crate::storage_ready::Ready>> {
        Ok(crate::storage::Storage {
            state: crate::storage_ready::Ready {
                certificate_chain: self.state.certificate_chain,
                private_key_chain: self.state.private_key_chain,
                crl_chain: self.state.crl_chain,
            },
            app_config: self.app_config,
        })
    }
}
