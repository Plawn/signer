use std::{fs::File, sync::Arc};

use ata42::{
    errors::SignInfrastructureError,
    signer::Signer,
    structs::{Serializer, SignRequest, SignedSignRequestSerialyzed, StampedItem},
    utils::read_private_key,
};

struct AppState {
    signer: Signer,
    archiver: SimpleArchiver,
}
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

#[tokio::main]
async fn main() {
    let private_key = "CAs/timestamp/key.p8".into();
    let port = 3000;

    let signer = Signer::new(read_private_key(&private_key).expect("failed to read key"));
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

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

impl From<ArchiveError> for SignInfrastructureError {
    fn from(_: ArchiveError) -> Self {
        SignInfrastructureError::ArchiveError
    }
}

struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

async fn sign(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignedSignRequestSerialyzed>,
) -> Result<Json<SignedSignRequestSerialyzed>, AppError> {
    // TODO: remove expect
    let content = serde_json::to_vec(&payload).expect("should not fail");
    let req = SignRequest::create(content, Serializer::JSON);
    // TODO: remove expect
    let signed = state.signer.sign_request(req).expect("failed to sign");
    let s: SignedSignRequestSerialyzed = signed.into();

    match state.archiver.archive(StampedItem {
        request: payload.clone(),
        response: s.clone(),
    }) {
        Ok(_) => Ok(Json(s)),
        // clean this error
        Err(_) => Err(AppError(anyhow::Error::msg("Failed to archive"))),
    }
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
