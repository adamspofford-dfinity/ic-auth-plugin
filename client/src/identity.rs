use std::{slice, sync::Mutex};

use futures::executor::block_on;
use ic_agent::{Identity, Signature};
use ic_principal::Principal;
use ic_transport_types::{Delegation, EnvelopeContent};

use crate::Plugin;

pub struct PluginIdentity {
    plugin: Mutex<Plugin>,
}

impl PluginIdentity {
    pub(crate) fn new(plugin: Plugin) -> Self {
        Self {
            plugin: Mutex::new(plugin),
        }
    }

    fn pubkey(&self) -> Result<Vec<u8>, String> {
        block_on(self.plugin.lock().unwrap().public_key()).map_err(|e| format!("{e}"))
    }

    pub fn with_plugin<T>(&self, f: impl FnOnce(&mut Plugin) -> T) -> T {
        f(&mut self.plugin.lock().unwrap())
    }
}

impl Identity for PluginIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.pubkey()?))
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        self.pubkey().ok()
    }
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        let mut sigs = block_on(
            self.plugin
                .lock()
                .unwrap()
                .sign_envelopes(slice::from_ref(content)),
        )
        .map_err(|e| format!("{e}"))?;
        Ok(Signature {
            public_key: Some(self.pubkey()?),
            signature: Some(sigs.remove(0)),
            delegations: None,
        })
    }
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let sig = block_on(self.plugin.lock().unwrap().sign_arbitrary(content))
            .map_err(|e| format!("{e}"))?;
        Ok(Signature {
            public_key: Some(self.pubkey()?),
            signature: Some(sig),
            delegations: None,
        })
    }
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        let (sig, expiry) = block_on(self.plugin.lock().unwrap().sign_delegation(
            &content.pubkey,
            content.expiration as u128,
            content.targets.as_deref(),
        ))
        .map_err(|e| format!("{e}"))?;
        if expiry != content.expiration as u128 {
            return Err("variable expiry not supported".to_string()); //todo
        }
        Ok(Signature {
            public_key: Some(self.pubkey()?),
            signature: Some(sig),
            delegations: None,
        })
    }
}
