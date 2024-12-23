#![feature(error_generic_member_access, error_reporter)]

use std::sync::Arc;

use ata42::{
    checker::Checker,
    signer::Signer,
    structs::{SignatureSerialyzed, SignedSignRequest, SignedSignRequestSerialyzed},
    utils::{read_private_key, read_public_key, MyError},
};
use xitca_web::{
    handler::{handler_service, json::Json, state::StateRef},
    route::post,
    App,
};

struct AppState {
    checker: ata42::checker::Checker,
    signer: ata42::signer::Signer,
}

fn main() -> std::io::Result<()> {
    let private_key = "CAs/signer/key.p8".into();

    // should be key of timestamp server
    let public_key = "CAs/timestamp/public.pem".into();
    // TODO: bad error
    let signer = Signer::new(read_private_key(&private_key).expect("failed to read key"));
    // TODO: add certificate in state to make it easy to handle the verification
    let checker = Checker::new(read_public_key(&public_key).expect("failed to read key"));
    let port = 8080;
    let state = Arc::from(AppState { checker, signer });
    App::new()
        .with_state(state)
        .at("/sign", post(handler_service(sign)))
        .enclosed_fn(ata42::utils::error_handler)
        .serve()
        .bind(format!("0.0.0.0:{}", port))?
        .run()
        .wait()
}

/// Checks wether the request is properly signed
fn authorize(payload: &SignedSignRequestSerialyzed, checker: &Checker) -> Result<bool, MyError> {
    let value: SignedSignRequest = payload.clone().try_into().unwrap();
    let result = checker.check(
        &value.sign_request.get_sign_image().unwrap(),
        &value.signature,
    );
    match result {
        Some(r) => Ok(r),
        None => Err(MyError(anyhow::Error::msg("Failed to validated signature"))),
    }
}

async fn sign(
    StateRef(state): StateRef<'_, AppState>,
    Json(payload): Json<SignedSignRequestSerialyzed>,
) -> Result<Json<SignatureSerialyzed>, MyError> {
    let result = authorize(&payload, &state.checker)?;
    log::debug!("Request has been archived by stamper: {:?}", result);
    match result {
        true => {
            let payload_data = &payload.sign_request.data.to_vec().unwrap();
            let base = SignedSignRequestSerialyzed::try_from(payload_data)
                .expect("failed to extract base query");
            let to_be_signed = &base.sign_request.data.to_vec().unwrap();
            let signed = state.signer.sign(to_be_signed);
            Ok(Json(signed.into()))
        }
        false => Err(MyError(anyhow::Error::msg("Invalid stamper signature"))),
    }
}
