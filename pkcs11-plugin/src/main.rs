use std::{
    borrow::Cow,
    io::{BufRead, Write, stdin, stdout},
};

use anyhow::{Context, bail, ensure};
use ic_agent::{Identity, identity::Delegation};
use ic_auth_plugin_types::{
    AuthenticateError, AuthenticateResponse, AuthenticateResult, AuthnMode,
    DescribeAuthnModeResponse, DescribeAuthnModeResult, GetPublicKeyError, GetPublicKeyResponse,
    GetPublicKeyResult, Greeting, KeySelectError, KeySelectResult, ListSelectableKeysError,
    ListSelectableKeysResult, Request, SelectMode, SignArbitraryDataError,
    SignArbitraryDataResponse, SignArbitraryDataResult, SignDelegationError,
    SignDelegationResponse, SignDelegationResult, SignEnvelopesError, SignEnvelopesResponse,
    SignEnvelopesResult,
};
use ic_identity_hsm::{HardwareIdentity, HardwareIdentityError};
use pkcs11::types::{CKR_PIN_INCORRECT, CKR_PIN_INVALID};

fn main() -> anyhow::Result<()> {
    ensure!(
        std::env::args()
            .nth(1)
            .is_some_and(|arg| arg == "--ic-auth-plugin"),
        "This program is an auth plugin and should not be run directly."
    );

    let mut stdin = stdin().lock();
    let mut stdout = stdout().lock();
    writeln!(
        stdout,
        "{}",
        serde_json::to_string(&Greeting {
            v: vec![1],
            select: SelectMode::Unsupported
        })?
    )?;
    let mut msg_buf = String::new();
    let zero_auth_attempt =
        match HardwareIdentity::new("/opt/homebrew/lib/softhsm/libsofthsm2.so", 0, "01", || {
            Err(String::new())
        }) {
            Ok(ident) => Some(ident),
            Err(HardwareIdentityError::UserPinRequired(_)) => None,
            Err(e) => return Err(e.into()),
        };
    let ident = loop {
        msg_buf.clear();
        stdin.read_line(&mut msg_buf)?;
        let req = serde_json::from_str::<Request>(&msg_buf)?;
        match req {
            Request::ListSelectableKeys(_) => writeln!(
                stdout,
                "{}",
                serde_json::to_string(&ListSelectableKeysResult::Err(
                    ListSelectableKeysError::Unsupported
                ))?
            )?,
            Request::KeySelect(_) => writeln!(
                stdout,
                "{}",
                serde_json::to_string(&KeySelectResult::Err(KeySelectError::Unsupported))?
            )?,
            Request::GetPublicKey(_) => writeln!(
                stdout,
                "{}",
                serde_json::to_string(&GetPublicKeyResult::Err(GetPublicKeyError::RequiresAuthn))?
            )?,
            Request::DescribeAuthnMode(_) => writeln!(
                stdout,
                "{}",
                serde_json::to_string(&DescribeAuthnModeResult::Ok(DescribeAuthnModeResponse {
                    mode: if zero_auth_attempt.is_some() {
                        AuthnMode::Automatic
                    } else {
                        AuthnMode::Password
                    },
                    value: None
                }))?
            )?,
            Request::Authenticate(auth) => {
                if let Some(ident) = zero_auth_attempt {
                    writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string(&AuthenticateResult::Ok(AuthenticateResponse {}))?
                    )?;
                    break ident;
                }
                match auth.integrated {
                    Some(mode) => {
                        if mode != AuthnMode::Password {
                            writeln!(
                                stdout,
                                "{}",
                                serde_json::to_string(&AuthenticateResult::Err(
                                    AuthenticateError::BadMode
                                ))?
                            )?;
                        } else {
                            let password = auth
                                .value
                                .context("integrated password missing")?
                                .into_owned();
                            match HardwareIdentity::new(
                                "/opt/homebrew/lib/softhsm/libsofthsm2.so",
                                0,
                                "01",
                                || Ok(password),
                            ) {
                                Ok(ident) => {
                                    writeln!(
                                        stdout,
                                        "{}",
                                        serde_json::to_string(&AuthenticateResult::Ok(
                                            AuthenticateResponse {}
                                        ))?
                                    )?;
                                    break ident;
                                }
                                Err(HardwareIdentityError::PKCS11(
                                    pkcs11::errors::Error::Pkcs11(
                                        CKR_PIN_INCORRECT | CKR_PIN_INVALID,
                                    ),
                                )) => writeln!(
                                    stdout,
                                    "{}",
                                    serde_json::to_string(&AuthenticateResult::Err(
                                        AuthenticateError::BadAuthn {
                                            message: "Incorrect PIN".into()
                                        }
                                    ))?
                                )?,
                                Err(e) => writeln!(
                                    stdout,
                                    "{}",
                                    serde_json::to_string(&AuthenticateResult::Err(
                                        AuthenticateError::Custom {
                                            message: format!("{e}")
                                        }
                                    ))?
                                )?,
                            }
                        }
                    }
                    None => todo!(),
                }
            }
            _ => bail!("handshake process violated"),
        }
    };
    loop {
        msg_buf.clear();
        stdin.read_line(&mut msg_buf)?;
        let req = serde_json::from_str::<Request>(&msg_buf)?;
        match req {
            Request::GetPublicKey(_) => writeln!(
                stdout,
                "{}",
                serde_json::to_string(&GetPublicKeyResult::Ok(GetPublicKeyResponse {
                    public_key_der: ident.public_key().unwrap()
                }))?
            )?,
            Request::SignEnvelopes(req) => {
                let signatures: Result<Vec<_>, _> = req
                    .contents
                    .iter()
                    .map(|envelope| {
                        ident
                            .sign(envelope)
                            .map(|sig| Cow::from(sig.signature.unwrap()))
                    })
                    .collect();
                let res: SignEnvelopesResult = match signatures {
                    Ok(signatures) => Ok(SignEnvelopesResponse {
                        signatures: signatures.into(),
                    }),
                    Err(err) => Err(SignEnvelopesError::Custom { message: err }),
                };
                writeln!(stdout, "{}", serde_json::to_string(&res)?)?;
            }
            Request::SignArbitraryData(req) => {
                let res: SignArbitraryDataResult = match ident.sign_arbitrary(&req.data) {
                    Ok(signature) => Ok(SignArbitraryDataResponse {
                        signature: signature.signature.unwrap().into(),
                    }),
                    Err(err) => Err(SignArbitraryDataError::Custom { message: err }),
                };
                writeln!(stdout, "{}", serde_json::to_string(&res)?)?;
            }
            Request::SignDelegation(req) => {
                let res: SignDelegationResult = match ident.sign_delegation(&Delegation {
                    expiration: req.desired_expiry.try_into().unwrap(),
                    targets: req.desired_canisters.map(Cow::into_owned),
                    pubkey: req.public_key_der.into_owned(),
                }) {
                    Ok(signature) => Ok(SignDelegationResponse {
                        expiry: req.desired_expiry,
                        signature: signature.signature.unwrap().into(),
                    }),
                    Err(err) => Err(SignDelegationError::Custom { message: err }),
                };
                writeln!(stdout, "{}", serde_json::to_string(&res)?)?;
            }
            _ => bail!("handshake messages repeated"),
        }
    }
}
