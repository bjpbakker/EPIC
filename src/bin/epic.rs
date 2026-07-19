use axum::{
    Router,
    body::Bytes,
    extract::Path,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError, debug, error, info, warn};

use std::process::exit;

use std::sync::Arc;
use tokio::{
    sync::RwLock,
    time::{Duration, sleep},
};

use epic::{
    erik::asn1,
    erik::state::ResolvedErikIndex,
    fetch::{
        retrieval::{FetchMapper, Fqdn},
        rrdp::RrdpState,
    },
};
use rpki::{
    dep::bcder::{Mode, encode::Values},
    rrdp::Hash,
    uri,
};

use structopt::StructOpt;

struct ConsoleLogger {
    max_level: Option<Level>,
}

impl ConsoleLogger {
    pub fn init(max_level: LevelFilter) -> Result<(), SetLoggerError> {
        log::set_boxed_logger(Box::new(ConsoleLogger {
            max_level: max_level.to_level(),
        }))
        .map(|()| log::set_max_level(max_level))
    }
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.max_level
            .map(|max| metadata.level() <= max)
            .unwrap_or(false)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let prefix = match record.metadata().level() {
                Level::Trace => "***",
                Level::Debug => "*",
                _ => "",
            };
            println!("{}{}", prefix, record.args());
        }
    }

    fn flush(&self) {}
}

fn bad_hash(val: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("invalid hash: {val}"))
}

fn not_found(kind: &str, resource: String) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("no such {kind}: {resource}"))
}

fn der(data: Bytes) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream+der")],
        data,
    )
}

#[tokio::main]
async fn main() {
    let opts = Opt::from_args();
    if let Err(cause) = ConsoleLogger::init(LevelFilter::Debug) {
        panic!("Failed to initialize logger: {}", cause);
    }

    info!("Starting EPIC to track {}", opts.fqdn.as_str());
    debug!(
        "Loading RPKI state from RRDP notify URL {}",
        opts.notify_url.as_str()
    );

    let rrdp_state = RrdpState::create(opts.notify_url.clone(), FetchMapper::empty()).await;
    if let Err(cause) = rrdp_state {
        error!("Cannot create RRDP state: {cause}");
        exit(1);
    }

    if let Ok(rrdp) = rrdp_state {
        info!("Starting HTTP server on port {}", opts.port);
        let state = Arc::new(RwLock::new(rrdp));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let updater_state = state.clone();
        let updater = rt.spawn(async move {
            loop {
                sleep(Duration::from_secs(30)).await;
                info!("Updating RRDP");
                let mut lock = updater_state.write().await;
                if let Err(cause) = lock.update().await {
                    warn!("RRDP update failed: {}", cause);
                }
            }
        });
        let http_state = state.clone();
        let http = run(opts, http_state);
        if let (_, Err(cause)) = tokio::join!(updater, http) {
            error!("HTTP server failed: {}", cause);
        }
    }
}

async fn run(cfg: Opt, state: Arc<RwLock<RrdpState>>) -> anyhow::Result<()> {
    let ni_state = state.clone();
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
                    let lock = ni_state.read().await;
                    match lock.elements.get(&hash) {
                        Some(obj) => der(obj.data().to_vec().into()).into_response(),
                        None => not_found("object", hash.to_string()).into_response(),
                    }
                } else {
                    bad_hash(val).into_response()
                }
            }
            _ => bad_hash(val).into_response(),
        }
    };

    let index_state = state.clone();
    let named_index = async move |Path(fqdn): Path<String>| {
        debug!("GET Erik index for {fqdn}");
        if fqdn != cfg.fqdn.as_str() {
            return not_found("index", fqdn).into_response();
        }
        let lock = index_state.read().await;
        if let Some(state) =
            ResolvedErikIndex::resolve(cfg.fqdn.as_str().into(), lock.manifests.values())
        {
            let index = asn1::ErikIndex::from(&state);
            return der(index.encode().to_captured(Mode::Der).into_bytes()).into_response();
        }
        return not_found("not yet", fqdn).into_response();
    };

    let app = Router::new()
        .route(
            "/",
            get(|| async { "EPIC: Erik Protocol Implementation Concept" }),
        )
        .route("/.well-known/ni/{alg}/{val}", get(named_information))
        .route("/.well-known/erik/index/{fqdn}", get(named_index));

    let listener = tokio::net::TcpListener::bind(format!("[::]:{}", cfg.port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    debug!("# Server Logs");

    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct Opt {
    #[structopt[short, long, default_value="3000"]]
    port: u16,

    #[structopt(long)]
    fqdn: Fqdn,

    #[structopt(long)]
    notify_url: uri::Https,
}
