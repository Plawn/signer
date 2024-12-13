use std::{io::Error, sync::Arc};

use ata42::{Checker, SignedData, TimestampedData};
use xitca_web::{
    handler::{handler_service, json::Json, state::StateRef},
    route::{get, post},
    App,
};

struct AppState {
    checker: Checker,
}

fn main() -> std::io::Result<()> {
    // TODO: add certificate in state to make it easy to handle the verification
    let checker = Arc::from(AppState {
        checker: Checker::new(),
    });
    App::new()
        // use trait object as application state
        .with_state(checker)
        // .with_state(object_state())
        // .at("/", get(handler_service(handler)))
        .at(
            "/sign",
            post(handler_service(sign)).get(handler_service(sign)),
        )
        .serve()
        .bind("127.0.0.1:8080")?
        .run()
        .wait()
}

// a simple trait for injecting dependent type and logic to application.
trait DI {
    fn name(&self) -> &'static str;
}

// thread safe trait object state constructor.
fn object_state() -> Arc<dyn DI + Send + Sync> {
    // a dummy type implementing DI trait.
    struct Foo {}

    impl DI for Foo {
        fn name(&self) -> &'static str {
            "foo"
        }
    }

    // only this function knows the exact type implementing DI trait.
    // everywhere else in the application it's only known as dyn DI trait object.
    Arc::new(Foo {})
}

// type ExampleType<'a> = StateRef<'a, dyn DI + Send + Sync>;

// // StateRef extractor is able extract &dyn DI from application state.
// async fn handler(StateRef(obj): ExampleType<'_>) -> String {
//     // get request to "/" path should return "hello foo" string response.
//     format!("hello {}", obj.name())
// }

async fn sign(
    StateRef(state): StateRef<'_, AppState>,
    Json(payload): Json<TimestampedData>,
) -> Result<Json<SignedData>, Error> {
    let result = state.checker.check();
    match result {
        Some(v) => match v {
            true => Ok(Json(SignedData::new())),
            false => Err(Error::last_os_error()),
        },
        None => Err(Error::last_os_error()),
    }
}

