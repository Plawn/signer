use ring::signature::Ed25519KeyPair;

use crate::structs::{SignAlgorithm, SignRequest, Signature, SignedSignRequest};

pub struct Signer {
    key: Ed25519KeyPair,
}

impl Signer {
    pub fn new(key: Ed25519KeyPair) -> Self {
        Self { key }
    }

    pub fn sign(&self, req: SignRequest) -> Result<SignedSignRequest, anyhow::Error> {
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
}
// fn sign_sign_request(
//     req: SignRequest,
//     private_key: Ed25519KeyPair,
// ) -> Result<SignedSignRequest, anyhow::Error> {
//     let bytes = req.clone().get_sign_image()?;
//     let signature = private_key.sign(&bytes);
//     let s = signature.as_ref();
//     Ok(SignedSignRequest::create(
//         req,
//         Signature {
//             value: s.to_vec(),
//             algorithm: ata42::structs::SignAlgorithm::ED25519,
//         },
//     ))
// }
