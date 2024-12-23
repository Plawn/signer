use std::{fs::File, io::Write, path::PathBuf};

use anyhow::anyhow;
use ata42::{
    checker::Checker,
    errors::SignInfrastructureError,
    signer::Signer,
    structs::{
        Serializer, SignRequest, SignRequestSerialyzed, Signature, SignatureSerialyzed,
        SignedSignRequest, SignedSignRequestSerialyzed,
    },
    utils::{read_file, read_private_key, read_public_key},
};
use clap::{Parser, Subcommand};
use ring::{
    rand,
    signature::{self, KeyPair},
};

fn generate_keys(
    path_private: PathBuf,
    path_public: PathBuf,
) -> Result<(), SignInfrastructureError> {
    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;

    let private_key_bytes = pkcs8_bytes.as_ref();
    let mut file = File::create(path_private)?;
    file.write_all(private_key_bytes)?;

    let peer_public_key_bytes = key_pair.public_key().as_ref();
    let mut file = File::create(path_public)?;
    file.write_all(peer_public_key_bytes)?;
    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a key pair for app usage
    GenerateKeys {
        /// Path for the created private key
        private: PathBuf,
        /// Path for the created public key
        public: PathBuf,
    },
    /// Make a sign request for the given data
    MakeSignRequest {
        /// Path for the data to be signed
        data: PathBuf,
        /// Export path
        out: PathBuf,
    },
    /// Sign the sign request with the given private key
    SignSignRequest {
        /// Path the to private key to sign
        key: PathBuf,
        /// Path to the sign request
        sign_request_path: PathBuf,
        /// Export path
        out: PathBuf,
    },
    /// Check if the [SignedSignRequest] is valid
    CheckSignRequest {
        /// Path to the public key
        key: PathBuf,
        /// Path to the signed sign request
        sign_request_path: PathBuf,
    },
    Sign {
        /// Path to user private key
        key: PathBuf,
        /// Path to data to be signed
        data: PathBuf,
        /// Adress of the front server
        #[arg(long, default_value = "http://localhost:4000")]
        at: String,
    },
    CheckResult {
        /// Path to signature
        signature: PathBuf,
        /// Path to data to be signed
        to_be_signed: PathBuf,
        /// Path to public key server
        pub_key: PathBuf,
    },
}

pub struct SignClient {
    client: reqwest::Client,
    key: signature::Ed25519KeyPair,
    at: String,
}

impl SignClient {
    pub async fn sign(self, data: Vec<u8>) -> Result<SignatureSerialyzed, SignInfrastructureError> {
        let req = SignRequest::create(data, Serializer::JSON);
        let signer = Signer::new(self.key);
        let result = signer.sign_request(req)?;
        let for_storage: SignedSignRequestSerialyzed = result.into();
        let res: SignatureSerialyzed = self
            .client
            // addr should be option
            .post(format!("{}/sign", &self.at))
            .json(&for_storage)
            .send()
            .await?
            .json()
            .await?;
        Ok(res)
    }

    pub fn new(at: String, private_key: signature::Ed25519KeyPair) -> Self {
        Self {
            client: reqwest::Client::new(),
            key: private_key,
            at,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { private, public } => {
            generate_keys(private, public)?;
        }
        Commands::MakeSignRequest { data, out } => {
            let req = SignRequest::create(read_file(&data)?, Serializer::JSON);
            let for_storage: SignRequestSerialyzed = req.into();
            let output = File::create(out)?;
            serde_json::to_writer_pretty(output, &for_storage)?;
        }
        Commands::SignSignRequest {
            key,
            sign_request_path,
            out,
        } => {
            let signer = Signer::new(read_private_key(&key)?);
            let req = SignRequest::from_bytes(read_file(&sign_request_path)?)?;
            let result = signer.sign_request(req)?;
            let for_storage: SignedSignRequestSerialyzed = result.into();
            let output = File::create(out)?;
            serde_json::to_writer_pretty(output, &for_storage)?;
        }
        Commands::CheckSignRequest {
            key,
            sign_request_path,
        } => {
            let checker = Checker::new(read_public_key(&key)?);
            // TODO: move to [SignedSignRequest]
            let req: SignedSignRequest =
                SignedSignRequestSerialyzed::try_from(read_file(&sign_request_path)?.as_ref())?
                    .try_into()?;
            let j = req.sign_request.get_sign_image()?;
            match checker.check(&j, &req.signature) {
                Some(_) => {
                    println!("signature valid");
                    return Ok(());
                }
                // better error
                None => Err(anyhow!("signature invalid"))?,
            }
        }
        Commands::Sign { key, data, at } => {
            let client = SignClient::new(at, read_private_key(&key)?);
            let result = client.sign(read_file(&data)?).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Commands::CheckResult {
            signature,
            to_be_signed,
            pub_key,
        } => {
            let data = read_file(&to_be_signed)?;
            let signature: Signature =
                SignatureSerialyzed::try_from(read_file(&signature)?)?.try_into()?;
            let checker = Checker::new(read_public_key(&pub_key)?);
            let res = checker.check(&data, &signature);
            match res {
                Some(r) => match r {
                    true => println!("signature is valid"),
                    false => eprintln!("signature is invalid"),
                },
                None => eprintln!("signature is invalid"),
            }
        }
    }
    Ok(())
}
