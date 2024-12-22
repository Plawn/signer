use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::anyhow;
use ata42::{
    checker::Checker,
    signer::Signer,
    structs::{
        Serializer, SignRequest, SignRequestSerialyzed, SignedSignRequest,
        SignedSignRequestSerialyzed,
    },
    utils::read_file,
};
use ring::{
    rand,
    signature::{self, KeyPair},
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
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, pub_key);
    Ok(peer_public_key)
}

fn main() -> anyhow::Result<()> {
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
            let signer = Signer::new(read_private_key(key)?);
            let req = SignRequest::from_bytes(read_file(&sign_request_path)?)?;
            let result = signer.sign(req)?;
            let for_storage: SignedSignRequestSerialyzed = result.into();
            let output = File::create(out)?;
            serde_json::to_writer_pretty(output, &for_storage)?;
        }
        Commands::CheckSignRequest {
            key,
            sign_request_path,
        } => {
            let checker = Checker::new(read_public_key(key)?);
            // TODO: move to [SignedSignRequest]
            let req = read_signed_sign_request_from_file(sign_request_path)?;
            let j = req.sign_request.get_sign_image()?;
            match checker.check(&j, &req.signature) {
                Some(_) => {
                    println!("signature valid");
                    return Ok(());
                }
                None => Err(anyhow!("signature invalid"))?,
            }
        }
    }
    Ok(())
}
