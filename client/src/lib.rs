use std::borrow::Cow;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::io::{self, Error as IoError, ErrorKind, IoSlice};
use std::process::Stdio;

use ic_auth_plugin_types::{
    AuthenticateError, AuthenticateRequest, AuthenticateResult, AuthnMode, DescribeAuthnModeError,
    DescribeAuthnModeRequest, DescribeAuthnModeResult, Greeting, KeySelectError, KeySelectRequest,
    KeySelectResult, ListSelectableKeysError, ListSelectableKeysRequest,
    ListSelectableKeysResponse, ListSelectableKeysResult, Request, SelectMode,
    SignArbitraryDataError, SignArbitraryDataRequest, SignArbitraryDataResult, SignDelegationError,
    SignDelegationRequest, SignDelegationResult, SignEnvelopesError, SignEnvelopesRequest,
    SignEnvelopesResult,
};
use ic_principal::Principal;
use ic_transport_types::EnvelopeContent;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, Lines};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

pub struct Plugin {
    stdin: BufWriter<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    stderr: Option<ChildStderr>,
    select_mode: SelectMode,
}

#[derive(Error, Debug)]
pub enum PluginError<E> {
    #[error("plugin I/O error: {0}")]
    Io(#[from] IoError),
    #[error("plugin encoding error: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("plugin was incompatible")]
    Incompatible,
    #[error("plugin error: {0}")]
    Plugin(E),
}

impl Plugin {
    pub async fn open(program: impl AsRef<OsStr>) -> Result<Self, PluginError<Infallible>> {
        Self::open_with_stderr(program, Stdio::inherit()).await
    }

    pub async fn open_with_stderr(
        program: impl AsRef<OsStr>,
        stderr: impl Into<Stdio>,
    ) -> Result<Self, PluginError<Infallible>> {
        let mut child = Command::new(program)
            .arg("--ic-auth-plugin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()?;
        let stdin = BufWriter::new(child.stdin.take().unwrap());
        let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let Some(greeting) = stdout.next_line().await? else {
            return Err(PluginError::Io(IoError::from(ErrorKind::UnexpectedEof)));
        };
        let greeting: Greeting = serde_json::from_str(&greeting)?;
        if !greeting.v.contains(&1) {
            return Err(PluginError::Incompatible);
        }
        Ok(Self {
            select_mode: greeting.select,
            stdin,
            stdout,
            stderr: child.stderr.take(),
        })
    }

    pub fn select_mode(&self) -> SelectMode {
        self.select_mode
    }

    pub async fn key_names(
        &mut self,
    ) -> Result<Option<ListSelectableKeysResponse>, PluginError<ListSelectableKeysError>> {
        let req = serde_json::to_string(&Request::ListSelectableKeys(ListSelectableKeysRequest {
            v: 1,
        }))?;
        self.writeln(&req).await?;
        let resp = self.readln().await?;
        let resp: ListSelectableKeysResult = serde_json::from_str(&resp)?;
        match resp {
            Ok(keys) => Ok(Some(keys)),
            Err(ListSelectableKeysError::Unsupported) => Ok(None),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub async fn select_key(&mut self, key: &str) -> Result<(), PluginError<KeySelectError>> {
        let req = serde_json::to_string(&Request::KeySelect(KeySelectRequest {
            v: 1,
            key: key.into(),
        }))?;
        self.writeln(&req).await?;

        let resp = self.readln().await?;
        let resp: KeySelectResult = serde_json::from_str(&resp)?;
        match resp {
            Ok(_) => Ok(()),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub async fn authn_mode(
        &mut self,
    ) -> Result<(AuthnMode, Option<String>), PluginError<DescribeAuthnModeError>> {
        let req = serde_json::to_string(&Request::DescribeAuthnMode(DescribeAuthnModeRequest {
            v: 1,
        }))?;
        self.writeln(&req).await?;
        let resp = self.readln().await?;
        let resp: DescribeAuthnModeResult = serde_json::from_str(&resp)?;
        match resp {
            Ok(mode) => Ok((mode.mode, mode.value)),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub async fn authenticate(
        &mut self,
        integrated_mode: Option<AuthnMode>,
        integrated_value: Option<String>,
    ) -> Result<(), PluginError<AuthenticateError>> {
        let req = serde_json::to_string(&Request::Authenticate(AuthenticateRequest {
            integrated: integrated_mode,
            value: integrated_value.map(Cow::from),
            v: 1,
        }))?;
        self.writeln(&req).await?;
        let resp = self.readln().await?;
        let resp: AuthenticateResult = serde_json::from_str(&resp)?;
        match resp {
            Ok(_) => Ok(()),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub async fn sign_envelopes(
        &mut self,
        envelopes: &[EnvelopeContent],
    ) -> Result<Vec<Vec<u8>>, PluginError<SignEnvelopesError>> {
        let req = serde_json::to_string(&Request::SignEnvelopes(SignEnvelopesRequest {
            v: 1,
            contents: envelopes.into(),
        }))?;
        self.writeln(&req).await?;
        let resp = self.readln().await?;
        let resp: SignEnvelopesResult = serde_json::from_str(&resp)?;
        match resp {
            #[allow(clippy::unnecessary_to_owned)] // false positive, the first into_owned is no-op
            Ok(o) => Ok(o
                .signatures
                .into_owned()
                .into_iter()
                .map(|s| s.into_owned())
                .collect()),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub async fn sign_delegation(
        &mut self,
        public_key_der: &[u8],
        desired_expiry: u128,
        desired_canisters: Option<&[Principal]>,
    ) -> Result<Vec<u8>, PluginError<SignDelegationError>> {
        let req = serde_json::to_string(&Request::SignDelegation(SignDelegationRequest {
            v: 1,
            public_key_der: public_key_der.into(),
            desired_expiry,
            desired_canisters: desired_canisters.map(Into::into),
        }))?;
        self.writeln(&req).await?;
        let resp = self.readln().await?;
        let resp: SignDelegationResult = serde_json::from_str(&resp)?;
        match resp {
            Ok(o) => Ok(o.signature.into_owned()),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub async fn sign_arbitrary(
        &mut self,
        data: &[u8],
    ) -> Result<Vec<u8>, PluginError<SignArbitraryDataError>> {
        let req = serde_json::to_string(&Request::SignArbitraryData(SignArbitraryDataRequest {
            v: 1,
            data: data.into(),
        }))?;
        self.writeln(&req).await?;
        let resp = self.readln().await?;
        let resp: SignArbitraryDataResult = serde_json::from_str(&resp)?;
        match resp {
            Ok(o) => Ok(o.signature.into_owned()),
            Err(e) => Err(PluginError::Plugin(e)),
        }
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }

    async fn writeln(&mut self, line: &str) -> io::Result<()> {
        let bufs = [IoSlice::new(line.as_bytes()), IoSlice::new(b"\n")];
        let mut len = line.len() + 1;
        while len != 0 {
            len -= self.stdin.write_vectored(&bufs).await?;
        }
        self.stdin.flush().await?;
        Ok(())
    }

    async fn readln(&mut self) -> io::Result<String> {
        self.stdout
            .next_line()
            .await?
            .ok_or_else(|| IoError::from(ErrorKind::UnexpectedEof))
    }
}
