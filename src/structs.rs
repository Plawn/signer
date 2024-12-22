use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct TimestampedData {
    // bae
    pub data: StringBytes,
    pub signature: StringBytes,
}

/// Base 64 encoded byte array
#[derive(Deserialize, Serialize, Debug)]
pub struct StringBytes(String);

impl StringBytes {
    pub fn to_vec(&self) -> Option<Vec<u8>> {
        let result = URL_SAFE.decode(&self.0).ok();
        return result;
    }
}

impl From<Vec<u8>> for StringBytes {
    fn from(value: Vec<u8>) -> Self {
        let result = URL_SAFE.encode(value);
        return Self(result);
    }
}

impl TimestampedData {
    pub fn new() -> Self {
        Self {
            data: StringBytes::from(vec![1, 2, 3]),
            signature: StringBytes::from(vec![1, 2, 3]),
        }
    }
}
#[derive(Deserialize, Serialize)]
pub struct SignedData {
    // base64 encoded signature
    signature: StringBytes,
}

impl SignedData {
    pub fn new() -> Self {
        Self {
            signature: StringBytes::from(vec![1, 2, 3]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// In order to be on the wire or stored
pub struct SignRequestSerialyzed {
    data: StringBytes,
}

#[derive(Debug, Clone)]
/// Struct to be used when processed
/// Only has data field for now, but all the metadata can then be added later on
pub struct SignRequest {
    pub data: Vec<u8>,
}

impl From<SignRequest> for SignRequestSerialyzed {
    fn from(value: SignRequest) -> Self {
        Self {
            data: StringBytes::from(value.data),
        }
    }
}
pub struct InvalidSignRequestSerialyzed;

impl TryFrom<SignRequestSerialyzed> for SignRequest {
    type Error = InvalidSignRequestSerialyzed;

    fn try_from(value: SignRequestSerialyzed) -> Result<Self, Self::Error> {
        match value.data.to_vec() {
            Some(data) => Ok(Self { data }),
            None => Err(InvalidSignRequestSerialyzed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignAlgorithm {
    ED25519
}

#[derive(Serialize, Debug, Deserialize)]
pub struct Signature {
    pub algorithm: SignAlgorithm, 
    pub value: Vec<u8>
}

#[derive(Serialize, Debug, Deserialize)]
pub struct SignatureSerialyzed {
    pub algorithm: SignAlgorithm, 
    pub value: StringBytes,
}

pub struct SignedSignRequest {
    pub sign_request: SignRequest,
    pub signature: Signature,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct SignedSignRequestSerialyzed {
    sign_request: SignRequestSerialyzed,
    signature: SignatureSerialyzed,
}

impl From<Signature> for SignatureSerialyzed {
    fn from(value: Signature) -> Self {
        Self {
            value: StringBytes::from(value.value),
            algorithm: value.algorithm,
        }
    }
} 

#[derive(Debug)]
pub struct InvalidSignatureSerialyzed;

impl TryFrom<SignatureSerialyzed> for Signature {
    type Error = InvalidSignatureSerialyzed;

    fn try_from(value: SignatureSerialyzed) -> Result<Self, Self::Error> {
       Ok(Self {
            // TODO: fix expect
            value: value.value.to_vec().expect("failed to parse value"),
            algorithm: value.algorithm,
        })
    }
}

impl From<SignedSignRequest> for SignedSignRequestSerialyzed {
    fn from(value: SignedSignRequest) -> Self {
        Self {
            sign_request: value.sign_request.into(),
            signature: value.signature.into(),
        }
    }
}

pub struct InvalidSignedSignRequestSerialyzed;

impl TryFrom<SignedSignRequestSerialyzed> for SignedSignRequest {
    type Error = InvalidSignedSignRequestSerialyzed;

    fn try_from(value: SignedSignRequestSerialyzed) -> Result<Self, Self::Error> {
        let s: SignRequest = value.sign_request.try_into().map_err(|_| InvalidSignedSignRequestSerialyzed)?;
        // TODO: remove unwrap
        let v: Signature = value.signature.try_into().unwrap();
        Ok(Self {
            sign_request: s,
            signature: v,
        })
    }
}

impl SignRequest {
    pub fn create(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl SignedSignRequest {
    pub fn create(sign_request: SignRequest, signature: Signature) -> Self {
        Self {
            sign_request,
            signature,
        }
    }
}
