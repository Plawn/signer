use std::{sync::Arc};

use ata42::{Checker, SignedData, TimestampedData};
use xitca_web::{
    error::Error, handler::{handler_service, html::Html, json::Json, state::StateRef, Responder}, http::{StatusCode, WebResponse}, route::post, service::Service, App, WebContext
};

struct AppState {
    checker: Checker,
}

fn main() -> std::io::Result<()> {
    // TODO: add certificate in state to make it easy to handle the verification
    let state = Arc::from(AppState {
        checker: Checker::new(),
    });
    App::new()
        .with_state(state)
        .at("/sign", post(handler_service(sign)))
        // .enclosed_fn(error_handler)
        .serve()
        .bind("0.0.0.0:8080")?
        .run()
        .wait()
}
use anyhow;
use std::{convert::Infallible, error, fmt};
#[derive(Debug)]
struct MyError {
    err: anyhow::Error,
}
impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MyError")
    }
}
impl error::Error for MyError {}


impl From<anyhow::Error> for MyError {
    fn from(err: anyhow::Error) -> MyError {
        MyError { err }
    }
}

async fn sign(
    StateRef(state): StateRef<'_, AppState>,
    Json(payload): Json<TimestampedData>,
) -> Result<Json<SignedData>, anyhow::Error> {
    let result = state.checker.check(
        payload.data.to_vec().unwrap(),
        payload.signature.to_vec().unwrap(),
    );
    match result {
        Some(v) => match v {
            true => Ok(Json(SignedData::new())),
            false => Err(anyhow::Error::msg("Failed")),
        },
        None => Err(anyhow::Error::msg("Failed")),
    }
}


// a handler middleware observe route services output.
async fn error_handler<S>(service: &S, mut ctx: WebContext<'_>) -> Result<WebResponse, Error>
where
    S: for<'r> Service<WebContext<'r>, Response = WebResponse, Error = Error>
{
    // unlike WebResponse which is already a valid http response. the error is treated as it's
    // onw type on the other branch of the Result enum.  

    // since the handler function at the start of example always produce error. our middleware
    // will always observe the Error type value so let's unwrap it.
    let err = service.call(ctx.reborrow()).await.err().unwrap();
     
    // now we have the error value we can start to interact with it and add our logic of
    // handling it.

    // we can print the error.
    println!("{err}");

    // we can log the error.
    // tracing::error!("{err}");

    // we can render the error to html and convert it to http response.
    let html = format!("<!DOCTYPE html>\
        <html>\
        <body>\
        <h1>{err}</h1>\
        </body>\
        </html>");
    return (Html(html), StatusCode::BAD_REQUEST).respond(ctx).await;

    // or by default the error value is returned in Result::Err and passed to parent services
    // of App or other middlewares where eventually it would be converted to WebResponse.
     
    // "eventually" can either mean a downstream user provided error handler middleware/service
    // or the implicit catch all error middleware xitca-web offers. In the latter case a default
    // WebResponse is generated with minimal information describing the reason of error.

    // Err(err)
}
