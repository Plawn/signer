use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::errors::SignInfrastructureError;

/// Base 64 encoded byte array
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StringBytes(String);

impl StringBytes {
    pub fn to_vec(&self) -> Option<Vec<u8>> {
        URL_SAFE.decode(&self.0).ok()
    }
}

impl From<Vec<u8>> for StringBytes {
    fn from(value: Vec<u8>) -> Self {
        let result = URL_SAFE.encode(value);
        Self(result)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Serializer {
    JSON,
}

impl Serializer {
    pub fn serialyze<T: Serialize>(&self, data: &T) -> Result<Vec<u8>, SignInfrastructureError> {
        match self {
            Serializer::JSON => Ok(serde_json::to_vec(data)?),
        }
    }

    pub fn deserialize<T: DeserializeOwned>(&self, data: &Vec<u8>) -> Result<T, SignInfrastructureError> {
        match self {
            Serializer::JSON => Ok(serde_json::from_slice(data)?),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// In order to be on the wire or stored
pub struct SignRequestSerialyzed {
    pub data: StringBytes,
    serialyzer: Serializer,
}

/// Struct to be used when processed
/// Only has data field for now, but all the metadata can then be added later on
#[derive(Debug, Clone)]
pub struct SignRequest {
    pub data: Vec<u8>,
    pub serialyzer: Serializer,
}

impl From<SignRequest> for SignRequestSerialyzed {
    fn from(value: SignRequest) -> Self {
        Self {
            data: StringBytes::from(value.data),
            serialyzer: value.serialyzer,
        }
    }
}

impl TryFrom<SignRequestSerialyzed> for SignRequest {
    type Error = crate::errors::SignInfrastructureError;

    fn try_from(value: SignRequestSerialyzed) -> Result<Self, Self::Error> {
        match value.data.to_vec() {
            Some(data) => Ok(Self {
                data,
                serialyzer: value.serialyzer,
            }),
            None => Err(crate::errors::SignInfrastructureError::InvalidStruct),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignAlgorithm {
    ED25519,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct Signature {
    pub algorithm: SignAlgorithm,
    pub value: Vec<u8>,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct SignatureSerialyzed {
    pub algorithm: SignAlgorithm,
    pub value: StringBytes,
}

pub struct SignedSignRequest {
    pub sign_request: SignRequest,
    pub signature: Signature,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct SignedSignRequestSerialyzed {
    pub sign_request: SignRequestSerialyzed,
    signature: SignatureSerialyzed,
}

impl TryFrom<&Vec<u8>> for SignedSignRequestSerialyzed {
    type Error = crate::errors::SignInfrastructureError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        match DEFAULT_SERIALYZER.deserialize(&value) {
            Ok(r) => Ok(r),
            Err(_) => Err(crate::errors::SignInfrastructureError::InvalidStruct),
        }
    }
}

impl From<Signature> for SignatureSerialyzed {
    fn from(value: Signature) -> Self {
        Self {
            value: StringBytes::from(value.value),
            algorithm: value.algorithm,
        }
    }
}

impl TryFrom<SignatureSerialyzed> for Signature {
    type Error = crate::errors::SignInfrastructureError;

    fn try_from(value: SignatureSerialyzed) -> Result<Self, Self::Error> {
        match value.value.to_vec() {
            Some(v) => Ok(Self {
                value: v,
                algorithm: value.algorithm,
            }),
            None => Err(crate::errors::SignInfrastructureError::InvalidStruct),
        }
    }
}

impl TryFrom<Vec<u8>> for SignatureSerialyzed {
    type Error = crate::errors::SignInfrastructureError;
    
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match DEFAULT_SERIALYZER.deserialize(&value) {
            Ok(s) => Ok(s),
            Err(_) => Err(crate::errors::SignInfrastructureError::InvalidStruct),
        }
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

impl TryFrom<SignedSignRequestSerialyzed> for SignedSignRequest {
    type Error = crate::errors::SignInfrastructureError;

    fn try_from(value: SignedSignRequestSerialyzed) -> Result<Self, Self::Error> {
        let s: SignRequest = value.sign_request.try_into()?;
        // TODO: remove unwrap
        let v: Signature = value.signature.try_into()?;
        Ok(Self {
            sign_request: s,
            signature: v,
        })
    }
}

pub const DEFAULT_SERIALYZER: Serializer = Serializer::JSON;

impl SignRequest {
    pub fn create(data: Vec<u8>, serialyzer: Serializer) -> Self {
        Self { data, serialyzer }
    }

    pub fn get_sign_image(self) -> Result<Vec<u8>, SignInfrastructureError> {
        let for_storage: SignRequestSerialyzed = self.into();
        let j = DEFAULT_SERIALYZER.serialyze(&for_storage)?;
        Ok(j)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, SignInfrastructureError> {
        let d: SignRequestSerialyzed = DEFAULT_SERIALYZER.deserialize(&data)?;
        let res: Self = d.try_into()?;
        Ok(res)
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

#[derive(Debug, Serialize, Deserialize)]
pub struct StampedItem {
    pub request: SignedSignRequestSerialyzed,
    pub response: SignedSignRequestSerialyzed,
}
