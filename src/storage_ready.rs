pub struct Ready {
    pub certificate_chain: libblockchain::blockchain::BlockChain,
    pub private_key_chain: libblockchain::blockchain::BlockChain,
    pub crl_chain: libblockchain::blockchain::BlockChain,
    pub auth_store: openssl::x509::store::X509Store,
    pub auth_chain: openssl::stack::Stack<openssl::x509::X509>,
}
