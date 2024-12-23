use std::sync::Arc;

use ata42::structs::{SignatureSerialyzed, SignedSignRequestSerialyzed};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

struct AppState {
    stamper_client: StamperClient,
    authority_client: AuthoritySignerClient,
}

#[tokio::main]
async fn main() {
    // should load from conf
    let authority_addr = "http://localhost:8080";
    let stamp_addr = "http://localhost:3000";

    let state = Arc::from(AppState {
        // add http client here
        stamper_client: StamperClient::new(stamp_addr),
        authority_client: AuthoritySignerClient::new(authority_addr),
    });

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
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
