use std::borrow::Cow;

use ic_principal::Principal;
use ic_transport_types::EnvelopeContent;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind"
)]
pub enum KeySelectError {
    Unsupported,
    InvalidKey { message: Option<String> },
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum ListSelectableKeysError {
    Unsupported,
    Custom { message: String },
}

pub type ListSelectableKeysResult = Result<ListSelectableKeysResponse, ListSelectableKeysError>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyRequest {
    pub v: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyResponse {
    #[serde(with = "b64")]
    public_key_der: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum GetPublicKeyError {
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignDelegationError {
    Unsupported,
    NeedsCanisterScoping,
    UnsupportedCanister {
        principals: Vec<Principal>,
        message: Option<String>,
    },
    Refused,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignEnvelopesError {
    Refused,
    UnsupportedContent {
        pos: Vec<usize>,
        message: Option<String>,
    },
    Custom {
        message: String,
    },
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignArbitraryDataError {
    Unsupported,
    Custom { message: String },
}

pub type SignArbitraryDataResult<'a> =
    Result<SignArbitraryDataResponse<'a>, SignArbitraryDataError>;
