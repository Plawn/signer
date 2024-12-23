use ata42::{
    errors::SignInfrastructureError,
    signer::Signer,
    structs::{Serializer, SignRequest, SignedSignRequestSerialyzed, StampedItem, DEFAULT_SERIALYZER},
    utils::read_private_key,
};
use tower_http::trace::TraceLayer;
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long, default_value = "3000")]
    port: u32,
    #[arg(long, default_value = "archive")]
    archive_folder: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let signer = Signer::new(read_private_key(&cli.private_key).expect("failed to read key"));
    let archiver = SimpleArchiver::new(&cli.archive_folder)?;
    let state = Arc::from(AppState { signer, archiver });

    let app = Router::new()
        .route("/live", get(|| async { "OK" }))
        .route("/sign", post(sign))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &cli.port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
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
    let content = DEFAULT_SERIALYZER.serialyze(&payload).expect("should not fail");
    let req = SignRequest::create(content, Serializer::JSON);
    // TODO: remove expect
    let signed = state.signer.sign_request(req).expect("failed to sign");
    let s: SignedSignRequestSerialyzed = signed.into();
    log::debug!("hello");
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
    directory: PathBuf,
}

impl SimpleArchiver {
    pub fn new(directory: &PathBuf) -> Result<Self, std::io::Error> {
        match Path::exists(Path::new(&directory)) {
            true => Ok(Self {
                directory: directory.to_owned(),
            }),
            false => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "folder not found",
            )),
        }
    }
}
impl Archiver for SimpleArchiver {
    fn archive(&self, item: StampedItem) -> Result<(), ArchiveError> {
        // push to local directory
        let uid = uuidv7::create();
        let filename = self.directory.as_path().join(uid + ".json");
        // TODO: clean
        println!("trying to archive at {:?}", &filename);
        let f = File::create(filename).map_err(|_| ArchiveError)?;
        serde_json::to_writer_pretty(f, &item).map_err(|_| ArchiveError)?;
        Ok(())
    }
}
