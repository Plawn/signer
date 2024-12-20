#![feature(error_generic_member_access, error_reporter)]

use ata42::{Checker, SignedData, TimestampedData};
use std::{backtrace::Backtrace, convert::Infallible, error, fmt, sync::Arc};

use xitca_web::{
    error::{Error, MatchError},
    handler::{handler_service, html::Html, json::Json, state::StateRef, Responder},
    http::{StatusCode, WebResponse},
    route::{get, post},
    service::Service,
    App, WebContext,
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
        .enclosed_fn(error_handler)
        .serve()
        .bind("0.0.0.0:8080")?
        .run()
        .wait()
}

// a custom error type. must implement following traits:
// std::fmt::{Debug, Display} for formatting
// std::error::Error for backtrace and type casting
// From for converting from Self to xitca_web::error::Error type.
// xitca_web::service::Service for lazily generating http response.
struct MyError {
    // thread backtrace which can be requested after type erasing through std::error::Error::provide API.
    backtrace: Backtrace,
}


impl fmt::Debug for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MyError").finish()
    }
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("custom error")
    }
}

impl error::Error for MyError {
    // necessary for providing backtrace to xitca_web::error::Error instance.
    fn provide<'a>(&'a self, request: &mut error::Request<'a>) {
        request.provide_ref(&self.backtrace);
    }
}

// Error<C> is the main error type xitca-web uses and at some point MyError would
// need to be converted to it.
impl<C> From<MyError> for Error<C> {
    fn from(e: MyError) -> Self {
        Error::from_service(e)
    }
}

// response generator of MyError. in this case we generate blank bad request error.
impl<'r, C> Service<WebContext<'r, C>> for MyError {
    type Response = WebResponse;
    type Error = Infallible;

    async fn call(&self, ctx: WebContext<'r, C>) -> Result<Self::Response, Self::Error> {
        StatusCode::BAD_REQUEST.call(ctx).await
    }
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
        Some(v) => match v {
            true => Ok(Json(SignedData::new())),
            false => Err(MyError {
                backtrace: Backtrace::capture(),
            }),
        },
        None => Err(MyError {
            backtrace: Backtrace::capture(),
        }),
    }
}


// a middleware function used for intercept and interact with app handler outputs.
async fn error_handler<S, C>(s: &S, mut ctx: WebContext<'_, C>) -> Result<WebResponse, Error<C>>
where
    S: for<'r> Service<WebContext<'r, C>, Response = WebResponse, Error = Error<C>>,
{
    match s.call(ctx.reborrow()).await {
        Ok(res) => Ok(res),
        Err(e) => {
            // debug format error info.
            println!("{e:?}");

            // display format error info.
            println!("{e}");

            // generate http response actively. from here it's OK to early return it in Result::Ok
            // variant as error_handler function's output
            let _res = e.call(ctx.reborrow()).await?;
            // return Ok(_res);

            // upcast trait and downcast to concrete type again.
            // this offers the ability to regain typed error specific error handling.
            // *. this is a runtime feature and not reinforced at compile time.
            if let Some(_e) = e.upcast().downcast_ref::<MyError>() {
                // handle typed error.
            }

            // type casting can also be used to handle xitca-web's "internal" error types for overriding
            // default error behavior.
            // *. "internal" means these error types have their default error formatter and http response generator.
            // *. "internal" error types are public types exported through `xitca_web::error` module. it's OK to
            // override them for custom formatting/http response generating.
            if e.upcast().downcast_ref::<MatchError>().is_some() {
                // MatchError is error type for request not matching any route from application service.
                // in this case we override it's default behavior by generating a different http response.
                return (Html("<h1>404 Not Found</h1>"), StatusCode::NOT_FOUND)
                    .respond(ctx)
                    .await;
            }

            // below are error handling feature only enabled by using nightly rust.

            // utilize std::error module for backtrace and more advanced error info.
            let report = error::Report::new(&e).pretty(true).show_backtrace(true);
            // display error report
            println!("{report}");

            // the most basic error handling is to ignore it and return as is. xitca-web is able to take care
            // of error by utilizing it's according trait implements(Debug,Display,Error and Service impls)
            Err(e)
        }
    }
}
