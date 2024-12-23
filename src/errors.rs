use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignInfrastructureError {
    #[error("Input/Output error")]
    IoError(#[from] io::Error),
    #[error("Invalid structure")]
    InvalidStruct,
    #[error("(de)serialyzation error")]
    Serde(#[from] serde_json::Error),
    #[error("unknown crypto error")]
    Crypto,
    #[error("Invalid key error")]
    InvalidKey,
    #[error("unknown error")]
    Unknown,
    #[error("Archive error")]
    ArchiveError,
}

impl From<ring::error::KeyRejected> for SignInfrastructureError {
    fn from(_: ring::error::KeyRejected) -> Self {
        SignInfrastructureError::InvalidKey
    }
}

impl From<ring::error::Unspecified> for SignInfrastructureError {
    fn from(_: ring::error::Unspecified) -> Self {
        SignInfrastructureError::Crypto
    }
}

