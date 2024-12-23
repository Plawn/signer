use std::{fs::File, sync::Arc};

use ata42::{
    signer::Signer,
    structs::{Serializer, SignRequest, SignRequestSerialyzed, SignedSignRequestSerialyzed, StampedItem},
    utils::read_private_key,
};

struct AppState {
    signer: Signer,
    archiver: SimpleArchiver,
}
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio;

#[tokio::main]
async fn main() {
    let private_key = "CAs/timestamp/key.p8".into();
    let signer = Signer::new(read_private_key(private_key).expect("failed to read key"));
    let archiver = SimpleArchiver::new("archive");
    // create app state
    let state = Arc::from(AppState { signer, archiver });

    // create server using axum this time for comparison

    // create endpoint
    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/sign", post(sign))
        .with_state(state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn sign(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignedSignRequestSerialyzed>,
) -> Json<SignedSignRequestSerialyzed> {
    let content = serde_json::to_vec(&payload).expect("should not fail");
    let req = SignRequest::create(content, Serializer::JSON);
    let signed = state.signer.sign_request(req).expect("failed to sign");
    let s: SignedSignRequestSerialyzed = signed.into();
    state.archiver.archive(StampedItem {
        request: payload.clone(),
        response: s.clone(),
    }).expect("failed to archive");
    // data of the first sign request should be used
    // sign the query
    // push to archive
    // return signed query
    Json(s)
}

#[derive(Debug)]
pub struct ArchiveError;

trait Archiver {
    fn archive(&self, item: StampedItem) -> Result<(), ArchiveError>;
}

pub struct SimpleArchiver {
    directory: String,
}

impl SimpleArchiver {
    pub fn new(directory: &str) -> Self {
        Self {
            directory: directory.to_owned(),
        }
    }
}
impl Archiver for SimpleArchiver {
    fn archive(&self, item: StampedItem) -> Result<(), ArchiveError> {
        // push to local directory
        let uid = uuidv7::create();
        let filename = format!("{}/{}.json", self.directory, uid);
        // TODO: clean
        println!("trying to archive at {}", &filename);
        let f = File::create(filename).expect("failed to open file");
        serde_json::to_writer_pretty(f, &item).expect("failed to archive");
        Ok(())
    }
}
