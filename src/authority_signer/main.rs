#![feature(error_generic_member_access, error_reporter)]

use std::sync::Arc;

use ata42::{
    structs::{SignedData, TimestampedData},
    utils::MyError,
};
use xitca_web::{
    handler::{handler_service, json::Json, state::StateRef},
    route::{get, post},
    App,
};

struct AppState {
    checker: ata42::checker::Checker,
    signer: ata42::signer::Signer,
}

fn main() -> std::io::Result<()> {
    // TODO: add certificate in state to make it easy to handle the verification
    let state = Arc::from(AppState {
        checker: ata42::checker::Checker::new(),
        signer: ata42::signer::Signer::new(),
    });
    App::new()
        .with_state(state)
        .at("/sign", post(handler_service(sign)))
        .enclosed_fn(ata42::utils::error_handler)
        .serve()
        .bind("0.0.0.0:8080")?
        .run()
        .wait()
}

async fn sign(
    StateRef(state): StateRef<'_, AppState>,
    Json(payload): Json<TimestampedData>,
) -> Result<Json<SignedData>, MyError> {
    let result = state.checker.check(
        payload.data.to_vec().unwrap(),
        payload.signature.to_vec().unwrap(),
    );
    match result {
        Some(v) => match !v {
            true => {
                // should sign here
                Ok(Json(SignedData::new()))
            }
            false => Err(MyError(anyhow::Error::msg("Failed"))),
        },
        None => Err(MyError(anyhow::Error::msg("Failed"))),
    }
}
