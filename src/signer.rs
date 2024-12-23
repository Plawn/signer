use ring::signature::Ed25519KeyPair;

use crate::{
    errors::SignInfrastructureError,
    structs::{SignAlgorithm, SignRequest, Signature, SignedSignRequest},
};

/// Checker is used to easely sign data
/// For now it handles only local ED... key
/// We need to handle more pkcs11 support in the future
pub struct Signer {
    key: Ed25519KeyPair,
}

impl Signer {
    pub fn new(key: Ed25519KeyPair) -> Self {
        Self { key }
    }

    pub fn sign_request(
        &self,
        req: SignRequest,
    ) -> Result<SignedSignRequest, SignInfrastructureError> {
        let bytes = req.clone().get_sign_image()?;
        let signature = self.sign(&bytes);
        Ok(SignedSignRequest::create(req, signature))
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        let signature = self.key.sign(bytes);
        Signature {
            algorithm: SignAlgorithm::ED25519,
            value: signature.as_ref().to_vec(),
        }
    }
}
