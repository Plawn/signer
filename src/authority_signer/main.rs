use ata42::{
    checker::Checker,
    signer::Signer,
    structs::{SignatureSerialyzed, SignedSignRequest, SignedSignRequestSerialyzed},
    utils::{read_private_key, read_public_key, MyError},
};

use clap::Parser;
use std::{path::PathBuf, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use xitca_web::middleware::tower_http_compat::TowerHttpCompat;
use xitca_web::{
    handler::{handler_service, json::Json, state::StateRef},
    route::{get, post},
    App,
};

struct AppState {
    checker: ata42::checker::Checker,
    signer: ata42::signer::Signer,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(long)]
    stamp_public_key: PathBuf,
    #[arg(long, default_value = "8080")]
    port: u32,
}

fn main() -> std::io::Result<()> {
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
    let checker = Checker::new(read_public_key(&cli.stamp_public_key).expect("failed to read key"));
    let state = Arc::from(AppState { checker, signer });

    App::new()
        .with_state(state)
        .at("/live", get(handler_service(async || "OK")))
        .at("/sign", post(handler_service(sign)))
        .enclosed_fn(ata42::utils::error_handler)
        .enclosed(TowerHttpCompat::new(TraceLayer::new_for_http()))
        .serve()
        .bind(format!("0.0.0.0:{}", &cli.port))?
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
            let payload_data = payload.sign_request.data.to_vec().unwrap();
            let base = SignedSignRequestSerialyzed::try_from(payload_data.as_ref())
                .expect("failed to extract base query");
            let to_be_signed = &base.sign_request.data.to_vec().unwrap();
            let signed = state.signer.sign(to_be_signed);
            Ok(Json(signed.into()))
        }
        false => Err(MyError(anyhow::Error::msg("Invalid stamper signature"))),
    }
}

// fn e() -> std::io::Result<()> {
//     let cli = Cli::parse();

//     tracing_subscriber::registry()
//         .with(
//             tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
//                 // axum logs rejections from built-in extractors with the `axum::rejection`
//                 // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
//                 format!(
//                     "{}=debug,tower_http=debug,axum::rejection=trace",
//                     env!("CARGO_CRATE_NAME")
//                 )
//                 .into()
//             }),
//         )
//         .with(tracing_subscriber::fmt::layer())
//         .init();

//     let signer = Signer::new(read_private_key(&cli.private_key).expect("failed to read key"));
//     let checker = Checker::new(read_public_key(&cli.stamp_public_key).expect("failed to read key"));
//     let state = Arc::from(AppState { checker, signer });

//     let layers = vec![TowerHttpCompat::new(TraceLayer::new_for_http())];

//     let b = App::new()
//         .with_state(state)
//         .at("/live", get(handler_service(async || "OK")))
//         .at("/sign", post(handler_service(sign)))
//         .enclosed_fn(ata42::utils::error_handler);
//     let b1 = b.enclosed(layers.get(0).unwrap());
    
//     b1.serve()
//         .bind(format!("0.0.0.0:{}", &cli.port))?
//         .run()
//         .wait()
// }
