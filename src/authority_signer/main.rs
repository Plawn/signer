#![feature(error_generic_member_access, error_reporter)]

use std::sync::Arc;

use ata42::{
    checker::Checker, signer::Signer, structs::{SignedData, SignedSignRequest, SignedSignRequestSerialyzed, TimestampedData}, utils::{read_private_key, read_public_key, MyError}
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
    let private_key = "CAs/signer/key.p8".into();
    
    
    let public_key = "CAs/user/public.pem".into();
    // TODO: bad error
    let signer = Signer::new(read_private_key(private_key).expect("failed to read key"));
    // TODO: add certificate in state to make it easy to handle the verification
    let checker = Checker::new(read_public_key(public_key).expect("failed to read key"));
    
    let state = Arc::from(AppState {
        checker,
        signer,
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

use anyhow::anyhow;

async fn sign(
    StateRef(state): StateRef<'_, AppState>,
    Json(payload): Json<SignedSignRequestSerialyzed>,
) -> Result<Json<SignedData>, MyError> {
    println!("signed request: {:?}", payload);
    let value: SignedSignRequest = payload.try_into().unwrap();
    println!("got request: {:?}", value.signature);
    let result = state.checker.check(
        &value.sign_request.get_sign_image().unwrap(),
        &value.signature,
    );
    println!("got result: {:?}", result);
    match result {
        Some(v) => match v {
            true => {
                // should sign here
                Ok(Json(SignedData::new()))
            }
            false => Err(MyError(anyhow::Error::msg("Failed"))),
        },
        None => Err(MyError(anyhow::Error::msg("Failed"))),
    }
}
