use std::sync::Arc;

use ata42::structs::{Signature, SignatureSerialyzed, SignedSignRequestSerialyzed};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

struct AppState {
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    let state = Arc::from(AppState {
        // add http client here
        client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/sign", post(handle_signature))
        .with_state(state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_signature(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignedSignRequestSerialyzed>,
) -> Json<SignatureSerialyzed> {
    // here it is stamped
    // we can use the result to call the authority server
    let stamped: SignedSignRequestSerialyzed = state
        .client
        .post("http://localhost:3000/sign")
        .json(&payload)
        .send()
        .await
        .inspect(|e| println!("{:?}", e))
        .expect("failed to query stamper")
        .json()
        .await
        .expect("failed to parse result");

    let signature: SignatureSerialyzed = state
        .client
        .post("http://localhost:8080/sign")
        .json(&stamped)
        .send()
        .await
        .expect("failed to query stamper")
        .json()
        .await
        .expect("failed to parse result");
    // get signed request
    // send to stamp
    // with result
    // send to autority
    // respond with final signature
    Json(signature)
}
