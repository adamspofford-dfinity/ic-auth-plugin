use anyhow::Result;
use ic_auth_plugin_client::Plugin;
use ic_auth_plugin_types::AuthnMode;

#[tokio::main]
async fn main() -> Result<()> {
    let mut client = Plugin::open("target/debug/pkcs11-ic-auth-plugin").await?;
    println!("a");
    client
        .authenticate(Some(AuthnMode::Password), Some("1234".to_string()))
        .await?;
    println!("b");
    let sig = client.sign_arbitrary(b"garbage!").await?;
    Ok(())
}
