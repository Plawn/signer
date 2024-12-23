use ring::signature;

use crate::structs::Signature;

pub struct Checker {
    key: signature::UnparsedPublicKey<Vec<u8>>,
}

impl Checker {
    pub fn new(pub_key: signature::UnparsedPublicKey<Vec<u8>>) -> Self {
        Self { key: pub_key }
    }

    pub fn check(&self, data: &Vec<u8>, signature: &Signature) -> Option<bool> {
        match self.key.verify(data, &signature.value) {
            Ok(_) => Some(true),
            Err(_) => None,
        }
    }
}
