use std::sync::Arc;

use ata42::structs::{SignatureSerialyzed, SignedSignRequestSerialyzed};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;

struct AppState {
    stamper_client: StamperClient,
    authority_client: AuthoritySignerClient,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// address of the authority server
    #[arg(long)]
    authority_address: String,
    /// address of the stamp server
    #[arg(long)]
    stamp_address: String,

    #[arg(long, default_value = "4000")]
    port: u32,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let state = Arc::from(AppState {
        // add http client here
        stamper_client: StamperClient::new(&cli.stamp_address),
        authority_client: AuthoritySignerClient::new(&cli.authority_address),
    });

    let app = Router::new()
        .route("/live", get(|| async { "OK" }))
        .route("/sign", post(handle_signature))
        .with_state(state);

    // run our app with hyper, listening globally on port 3000
    let port = 4000;
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

struct StamperClient {
    client: reqwest::Client,
    at: String,
}

impl StamperClient {
    pub fn new(at: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            at: at.to_owned(),
        }
    }

    pub async fn sign(
        &self,
        payload: &SignedSignRequestSerialyzed,
    ) -> Result<SignedSignRequestSerialyzed, ()> {
        let stamped: SignedSignRequestSerialyzed = self
            .client
            .post(format!("{}/sign", self.at))
            .json(payload)
            .send()
            .await
            .inspect(|e| log::debug!("{:?}", e))
            // TODO fix expect
            .expect("failed to query stamper")
            .json()
            .await
            // TODO fix expect
            .expect("failed to parse result");
        Ok(stamped)
    }
}

struct AuthoritySignerClient {
    client: reqwest::Client,
    at: String,
}

impl AuthoritySignerClient {
    pub fn new(at: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            at: at.to_owned(),
        }
    }
    pub async fn sign(
        &self,
        stamped: &SignedSignRequestSerialyzed,
    ) -> Result<SignatureSerialyzed, ()> {
        let signature: SignatureSerialyzed = self
            .client
            .post(format!("{}/sign", self.at))
            .json(stamped)
            .send()
            .await
            .inspect(|e| log::debug!("{:?}", e))
            // TODO fix expect
            .expect("failed to query stamper")
            .json()
            .await
            // TODO fix expect
            .expect("failed to parse result");
        Ok(signature)
    }
}

/// Here we check if the user is authorized to request such signature
/// for now we always authorize all queries
fn authorize(_payload: &SignedSignRequestSerialyzed) -> bool {
    true
}

async fn handle_signature(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignedSignRequestSerialyzed>,
) -> Json<SignatureSerialyzed> {
    match authorize(&payload) {
        true => match state.stamper_client.sign(&payload).await {
            Ok(stamped) => match state.authority_client.sign(&stamped).await {
                Ok(signature) => Json(signature),
                Err(_) => todo!("should be a nice error, the authority signing failed"),
            },
            Err(_) => todo!("should be a nice error, the stamping failed"),
        },
        false => todo!("not authorized"),
    }
}
