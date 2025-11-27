use libcertcrypto::{PfxContainer, CertificateUsageType};
use std::path::Path;
use anyhow::Result;

/// Load a PFX file and return a PfxContainer
pub fn load_pfx<P: AsRef<Path>>(
    path: P,
    password: &str,
    usage_type: CertificateUsageType,
) -> Result<PfxContainer> {
    PfxContainer::load_from_file(path, password, usage_type)
}

/// Save a PfxContainer to a file
pub fn save_pfx<P: AsRef<Path>>(
    container: &PfxContainer,
    path: P,
    password: &str,
) -> Result<()> {
    container.save_to_file(path, password)
}
