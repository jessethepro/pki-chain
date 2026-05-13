pub struct Admin {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: std::sync::Arc<openssl::x509::store::X509Store>,
    pub auth_chain: openssl::stack::Stack<openssl::x509::X509>,
}

impl crate::storage::Storage<Admin> {
    pub fn close(self) -> anyhow::Result<crate::storage::Storage<crate::storage_ready::Ready>> {
        Ok(crate::storage::Storage {
            state: crate::storage_ready::Ready {
                certificate_chain: self.state.certificate_chain,
                private_key_chain: self.state.private_key_chain,
                crl_chain: self.state.crl_chain,
                auth_store: self.state.auth_store,
            },
            app_config: self.app_config,
        })
    }
}
