use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::anyhow;
use ata42::structs::{
    SignRequest, SignRequestSerialyzed, Signature, SignedSignRequest, SignedSignRequestSerialyzed,
};
use ring::{
    rand,
    signature::{self, Ed25519KeyPair, KeyPair},
};

fn generate_keys(path_private: PathBuf, path_public: PathBuf) -> Result<(), anyhow::Error> {
    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes =
        signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| anyhow!("error"))?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| anyhow!("error"))?;

    let private_key_bytes = pkcs8_bytes.as_ref();
    let mut file = File::create(path_private)?;
    file.write_all(private_key_bytes)?;

    let peer_public_key_bytes = key_pair.public_key().as_ref();
    let mut file = File::create(path_public)?;
    file.write_all(peer_public_key_bytes)?;
    Ok(())
}

fn create_sign_request(data: Vec<u8>) -> SignRequest {
    SignRequest::create(data)
}

fn sign_sign_request(
    req: SignRequest,
    private_key: Ed25519KeyPair,
) -> Result<SignedSignRequest, anyhow::Error> {
    let for_storage: SignRequestSerialyzed = req.clone().into();
    let j = serde_json::to_vec(&for_storage)?;
    let signature = private_key.sign(&j);
    let s = signature.as_ref();
    Ok(SignedSignRequest::create(
        req,
        Signature {
            value: s.to_vec(),
            algorithm: ata42::structs::SignAlgorithm::ED25519,
        },
    ))
}

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional name to operate on
    // name: Option<String>,

    /// Sets a custom config file
    // #[arg(short, long, value_name = "FILE")]
    // config: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// does testing things
    GenerateKeys {
        /// lists test values
        // #[arg(short, long)]
        // list: bool,
        private: PathBuf,
        public: PathBuf,
    },
    MakeSignRequest {
        data: PathBuf,
    },
    SignSignRequest {
        key: PathBuf,
        sign_request_path: PathBuf,
    },
    CheckSignRequest {
        key: PathBuf,
        sign_request_path: PathBuf,
    },
}

fn read_sign_request_from_file(path: PathBuf) -> Result<SignRequest, anyhow::Error> {
    let f = File::open(path)?;
    let v: SignRequestSerialyzed = serde_json::from_reader(f)?;
    let value: SignRequest = v
        .try_into()
        .map_err(|e| anyhow!("failed to read sign request"))?;
    Ok(value)
}

fn read_signed_sign_request_from_file(path: PathBuf) -> Result<SignedSignRequest, anyhow::Error> {
    let f = File::open(path)?;
    let v: SignedSignRequestSerialyzed = serde_json::from_reader(f)?;
    let value: SignedSignRequest = v.try_into().map_err(|e| anyhow!("error"))?;
    Ok(value)
}

fn read_private_key(path: PathBuf) -> Result<signature::Ed25519KeyPair, anyhow::Error> {
    let mut f = File::open(path)?;
    let mut pkcs8_bytes = vec![];
    f.read_to_end(&mut pkcs8_bytes)?;
    let key = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| anyhow!("error reading key"))?;
    Ok(key)
}

fn read_public_key(path: PathBuf) -> Result<signature::UnparsedPublicKey<Vec<u8>>, anyhow::Error> {
    let mut f = File::open(path)?;
    let mut pub_key = vec![];
    f.read_to_end(&mut pub_key)?;
    let peer_public_key: signature::UnparsedPublicKey<Vec<u8>> =
        signature::UnparsedPublicKey::new(&signature::ED25519, pub_key);
    Ok(peer_public_key)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(e) => match e {
            Commands::GenerateKeys { private, public } => {
                generate_keys(private, public)?;
            }
            Commands::MakeSignRequest { data } => {
                let mut input = File::open(data)?;
                let mut buf = vec![];
                input.read_to_end(&mut buf)?;
                let req = create_sign_request(buf);
                let for_storage: SignRequestSerialyzed = req.into();
                let output = File::create("request.json")?;
                serde_json::to_writer_pretty(output, &for_storage)?;
            }
            Commands::SignSignRequest {
                key,
                sign_request_path,
            } => {
                let req = read_sign_request_from_file(sign_request_path)?;
                let private_key = read_private_key(key)?;
                let result = sign_sign_request(req, private_key)?;
                let for_storage: SignedSignRequestSerialyzed = result.into();
                let output = File::create("signed.json")?;
                serde_json::to_writer_pretty(output, &for_storage)?;
            }
            Commands::CheckSignRequest {
                key,
                sign_request_path,
            } => {
                let req = read_signed_sign_request_from_file(sign_request_path)?;
                let key = read_public_key(key)?;
                let content: SignRequestSerialyzed = req.sign_request.into();
                let j = serde_json::to_vec(&content)?;
                let result = key.verify(&j, &req.signature.value);
                if result.is_ok() {
                    println!("signture valid")
                } else {
                    println!("signture invalid")
                }
            }
        },
        None => todo!(),
    }
    Ok(())
}
