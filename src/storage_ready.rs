pub struct Ready {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: std::sync::Arc<openssl::x509::store::X509Store>,
}
