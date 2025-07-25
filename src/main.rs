use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use log::debug;
use std::vec::Vec;
use std::{process::exit, sync::Arc};

use bomans::{
    config::{self},
    rrdp::RepoContent,
};
use rpki::rrdp::Hash;

fn bad_hash(val: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("invalid hash: {val}"))
}

fn not_found(hash: Hash) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("no such object: {hash}"))
}

fn der(data: Vec<u8>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream+der")],
        data,
    )
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        println!("Error: {e}");
        exit(1)
    }
}

async fn run() -> anyhow::Result<()> {
    let _config = config::configure()?;

    let repo = Arc::new(RepoContent::create_test()?);

    debug!("# Inventory");
    for (hash, obj) in repo.elements().iter() {
        let encoded = URL_SAFE_NO_PAD.encode(hash);
        let uri = obj.uri();
        debug!("- {encoded} -> {uri}");
    }

    let named_information = async move |Path((alg, val)): Path<(String, String)>| {
        if alg != "sha-256" {
            return (
                StatusCode::BAD_REQUEST,
                "unsupported hashing algorithm: {alg}",
            )
                .into_response();
        }
        match URL_SAFE_NO_PAD.decode(val.as_bytes()) {
            Ok(h) if h.len() == 32 => {
                if let Ok(hash) = Hash::try_from(h.as_slice()) {
                    debug!("GET {hash}");

                    let r = Arc::clone(&repo);
                    let objects = r.elements();
                    return match objects.get(&hash) {
                        Some(obj) => der(obj.data().to_vec()).into_response(),
                        None => not_found(hash).into_response(),
                    };
                } else {
                    bad_hash(val).into_response()
                }
            }
            _ => bad_hash(val).into_response(),
        }
    };

    let app = Router::new()
        .route("/", get(|| async { "Bomans" }))
        .route("/.well-known/ni/{alg}/{val}", get(named_information));

    let listener = tokio::net::TcpListener::bind("[::]:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    debug!("# Server Logs");

    Ok(())
}
