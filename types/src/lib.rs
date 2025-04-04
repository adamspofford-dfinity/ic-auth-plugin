use ic_principal::Principal;
use ic_transport_types::EnvelopeContent;
use serde::{Deserialize, Serialize};

mod b64;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Greeting {
    pub v: Vec<u32>,
    pub select: SelectMode,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectMode {
    Required,
    Supported,
    Unsupported,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Request {
    KeySelect(KeySelectRequest),
    ListSelectableKeys(ListSelectableKeysRequest),
    SignDelegation(SignDelegationRequest),
    SignEnvelopes(SignEnvelopesRequest),
    SignArbitraryData(SignArbitraryDataRequest),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct KeySelectRequest {
    pub v: u32,
    pub key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct KeySelectResponse {}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ListSelectableKeysRequest;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ListSelectableKeysResponse {
    keys: Vec<String>,
    exhaustive: bool,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyRequest;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyResponse {
    #[serde(with = "b64")]
    public_key_der: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum GetPublicKeyError {
    Custom { message: String },
}

pub type GetPublicKeyResult = Result<GetPublicKeyResponse, GetPublicKeyError>;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignDelegationRequest {
    #[serde(with = "b64")]
    pub public_key_der: Vec<u8>,
    pub desired_expiry: u128,
    pub desired_canisters: Option<Vec<Principal>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignDelegationResponse {
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
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

pub type SignDelegationResult = Result<SignDelegationResponse, SignDelegationError>;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignEnvelopesRequest {
    pub contents: Vec<EnvelopeContent>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignEnvelopesResponse {
    #[serde(with = "b64::list")]
    pub signatures: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
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

pub type SignEnvelopesResult = Result<SignEnvelopesResponse, SignEnvelopesError>;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignArbitraryDataRequest {
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SignArbitraryDataResponse {
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum SignArbitraryDataError {
    Unsupported,
    Custom { message: String },
}

pub type SignArbitraryDataResult = Result<SignArbitraryDataResponse, SignArbitraryDataError>;
