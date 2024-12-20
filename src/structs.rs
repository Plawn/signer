use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct TimestampedData {
    // bae
    pub data: StringBytes,
    pub signature: StringBytes,
}

/// Base 64 encoded byte array
#[derive(Deserialize, Serialize)]
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
