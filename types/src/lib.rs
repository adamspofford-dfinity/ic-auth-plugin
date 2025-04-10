use std::{
    borrow::Cow,
    fmt::{Display, Write},
};

use ic_principal::Principal;
use ic_transport_types::EnvelopeContent;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod b64;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Greeting {
    pub v: Vec<u32>,
    pub select: SelectMode,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SelectMode {
    Required,
    Supported,
    Unsupported,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Request<'a> {
    KeySelect(KeySelectRequest<'a>),
    ListSelectableKeys(ListSelectableKeysRequest),
    GetPublicKey(GetPublicKeyRequest),
    DescribeAuthnMode(DescribeAuthnModeRequest),
    Authenticate(AuthenticateRequest<'a>),
    SignDelegation(SignDelegationRequest<'a>),
    SignEnvelopes(SignEnvelopesRequest<'a>),
    SignArbitraryData(SignArbitraryDataRequest<'a>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct KeySelectRequest<'a> {
    pub v: u32,
    pub key: Cow<'a, str>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub struct KeySelectResponse {}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind"
)]
pub enum KeySelectError {
    #[error("auth plugin does not support key selection")]
    Unsupported,
    #[error("invalid key name{}", opt_prefix(": ", .message))]
    InvalidKey { message: Option<String> },
    #[error("{message}")]
    Custom { message: String },
}

pub type KeySelectResult = Result<KeySelectResponse, KeySelectError>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub struct ListSelectableKeysRequest {
    pub v: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ListSelectableKeysResponse {
    pub keys: Vec<String>,
    pub exhaustive: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum ListSelectableKeysError {
    #[error("auth plugin does not support listing keys")]
    Unsupported,
    #[error("{message}")]
    Custom { message: String },
}

pub type ListSelectableKeysResult = Result<ListSelectableKeysResponse, ListSelectableKeysError>;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DescribeAuthnModeRequest {
    pub v: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct DescribeAuthnModeResponse {
    pub mode: AuthnMode,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthnMode {
    Password,
    Url,
    Message,
    Window,
    Automatic,
}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum DescribeAuthnModeError {
    #[error("{message}")]
    Custom { message: String },
}

pub type DescribeAuthnModeResult = Result<DescribeAuthnModeResponse, DescribeAuthnModeError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct AuthenticateRequest<'a> {
    pub v: u32,
    pub integrated: Option<AuthnMode>,
    pub value: Option<Cow<'a, str>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub struct AuthenticateResponse {}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum AuthenticateError {
    #[error("host provided the wrong integrated mode")]
    BadMode,
    #[error("authentication failed: {message}")]
    BadAuthn { message: String },
    #[error("{message}")]
    Custom { message: String },
}

pub type AuthenticateResult = Result<AuthenticateResponse, AuthenticateError>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyRequest {
    pub v: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyResponse {
    #[serde(with = "b64")]
    pub public_key_der: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum GetPublicKeyError {
    #[error("plugin requires authentication before providing public key")]
    RequiresAuthn,
    #[error("{message}")]
    Custom { message: String },
}

pub type GetPublicKeyResult = Result<GetPublicKeyResponse, GetPublicKeyError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SignDelegationRequest<'a> {
    pub v: u32,
    #[serde(with = "b64")]
    pub public_key_der: Cow<'a, [u8]>,
    pub desired_expiry: u128,
    pub desired_canisters: Option<Cow<'a, [Principal]>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SignDelegationResponse<'a> {
    #[serde(with = "b64")]
    pub signature: Cow<'a, [u8]>,
    pub expiry: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignDelegationError {
    #[error("plugin does not support signing delegations")]
    Unsupported,
    #[error("plugin does not support signing wildcard delegations")]
    NeedsCanisterScoping,
    #[error("plugin does not support canister(s) {}{}", list(.principals), opt_prefix(": ", .message))]
    UnsupportedCanister {
        principals: Vec<Principal>,
        message: Option<String>,
    },
    #[error("user refused to authorize delegation")]
    Refused,
    #[error("{message}")]
    Custom { message: String },
}

pub type SignDelegationResult<'a> = Result<SignDelegationResponse<'a>, SignDelegationError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SignEnvelopesRequest<'a> {
    pub v: u32,
    pub contents: Cow<'a, [EnvelopeContent]>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SignEnvelopesResponse<'a> {
    #[serde(with = "b64::list")]
    pub signatures: Cow<'a, [Cow<'a, [u8]>]>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignEnvelopesError {
    #[error("user refused to authorize message")]
    Refused,
    #[error("plugin does not support message(s) {}{}", list(.pos), opt_prefix(": ", .message))]
    UnsupportedContent {
        pos: Vec<usize>,
        message: Option<String>,
    },
    #[error("{message}")]
    Custom { message: String },
}

pub type SignEnvelopesResult<'a> = Result<SignEnvelopesResponse<'a>, SignEnvelopesError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SignArbitraryDataRequest<'a> {
    pub v: u32,
    #[serde(with = "b64")]
    pub data: Cow<'a, [u8]>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct SignArbitraryDataResponse<'a> {
    #[serde(with = "b64")]
    pub signature: Cow<'a, [u8]>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignArbitraryDataError {
    #[error("plugin does not support signing arbitrary data")]
    Unsupported,
    #[error("user refused to authorize signature")]
    Refused,
    #[error("{message}")]
    Custom { message: String },
}

pub type SignArbitraryDataResult<'a> =
    Result<SignArbitraryDataResponse<'a>, SignArbitraryDataError>;

fn list<T: Display>(items: &[T]) -> String {
    let mut s = String::with_capacity(items.len() * 30);
    for (n, item) in items.iter().enumerate() {
        if n != 0 {
            s.push_str(", ")
        }
        write!(s, "{}", *item).unwrap();
    }
    s
}

fn opt_prefix<T: Display>(prefix: &str, opt: &Option<T>) -> String {
    match opt {
        Some(t) => format!("{prefix}{t}"),
        None => String::new(),
    }
}
