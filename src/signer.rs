use ring::signature::Ed25519KeyPair;

use crate::{errors::SignInfrastructureError, structs::{SignAlgorithm, SignRequest, Signature, SignedSignRequest}};

pub struct Signer {
    key: Ed25519KeyPair,
}

impl Signer {
    pub fn new(key: Ed25519KeyPair) -> Self {
        Self { key }
    }

    pub fn sign_request(&self, req: SignRequest) -> Result<SignedSignRequest, SignInfrastructureError> {
        let bytes = req.clone().get_sign_image()?;
        let signature = self.key.sign(&bytes);
        let s = signature.as_ref();
        Ok(SignedSignRequest::create(
            req,
            Signature {
                value: s.to_vec(),
                algorithm: SignAlgorithm::ED25519,
            },
        ))
    }

    pub fn sign(&self, bytes: &Vec<u8>) -> Signature {
        let signature = self.key.sign(bytes);
        Signature {
            algorithm: SignAlgorithm::ED25519,
            value: signature.as_ref().to_vec(),
        }
    }
}
