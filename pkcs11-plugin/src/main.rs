use anyhow::ensure;
use ic_auth_plugin_types::{Greeting, SelectMode};
use ic_identity_hsm::HardwareIdentity;

fn main() -> anyhow::Result<()> {
    ensure!(
        std::env::args()
            .next()
            .is_some_and(|arg| arg == "--ic-auth-plugin"),
        "This program is an auth plugin and should not be run directly."
    );
    let ident = HardwareIdentity::new("/usr/local/lib/opensc-pkcs11.so", 0, "", || )
    println!("{}", serde_json::to_string(&Greeting { v: vec![1], select: SelectMode::Unsupported })?);
    Ok(())
}
