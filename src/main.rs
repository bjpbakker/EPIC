use axum::{Router, extract::Path, http::StatusCode, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

async fn named_information(Path((alg, val)): Path<(String, String)>) -> (StatusCode, String) {
    match URL_SAFE_NO_PAD.decode(val.clone()) {
        Ok(h) => (
            StatusCode::OK,
            format!("{alg} - {val}", alg = alg, val = val),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, world" }))
        .route("/.well-known/ni/{alg}/{val}", get(named_information));

    let listener = tokio::net::TcpListener::bind("[::]:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
