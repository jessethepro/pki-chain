use libblockchainstor::BlockchainDb;

mod pfx_key;

fn main() {
    let certificate_chain = BlockchainDb::open("../data/certificates")
        .expect("Failed to open blockchain database");
    let pfx_chain = BlockchainDb::open("../data/pfx")
        .expect("Failed to open blockchain database");
    println!("Hello, world!");
}
