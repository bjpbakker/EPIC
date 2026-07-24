use axum::{
    Router,
    body::Bytes,
    extract::Path,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use std::collections::HashMap;
use std::process::exit;
use std::str::FromStr;
use std::net::SocketAddr;

use std::sync::Arc;
use tokio::{
    sync::RwLock,
    time::{Duration, sleep},
};

use log::{LevelFilter, debug, error, info, warn};

use epic::{
    erik::{asn1, state::ResolvedErikIndex},
    fetch::{
        retrieval::{FetchMapper, Fqdn},
        rrdp::RrdpState,
    },
    log::ConsoleLogger,
};
use rpki::{dep::bcder::encode::Values, uri};

use structopt::StructOpt;

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

struct ServerState {
    indices: HashMap<Fqdn, asn1::ErikIndex>,
    objects: HashMap<asn1::Hash, Bytes>,
}

impl ServerState {
    fn init() -> Self {
        ServerState {
            indices: HashMap::new(),
            objects: HashMap::new(),
        }
    }

    fn update(&mut self, fqdn: &Fqdn, rrdp_state: &RrdpState) {
        if let Some(index) =
            ResolvedErikIndex::resolve(fqdn.as_str().into(), rrdp_state.manifests.values())
        {
            for partition in index.partitions.values() {
                let enc = asn1::ErikPartitionEncoder::from(partition);
                let der = enc.encode().to_captured(asn1::Mode::Der).into_bytes();
                let partition_ref = asn1::ErikPartitionRef::new(&der);
                self.objects.insert(partition_ref.hash, der);
            }
            for (hash, object) in rrdp_state.elements.clone() {
                self.objects.insert(hash, object.data().clone());
            }

            let erik_index = asn1::ErikIndex::from(&index);
            self.indices.insert(fqdn.clone(), erik_index);
        }
    }

    fn get_index(&self, fqdn_str: &str) -> Option<&asn1::ErikIndex> {
        Fqdn::from_str(fqdn_str)
            .ok()
            .map(|fqdn| self.indices.get(&fqdn))
            .flatten()
    }

    fn get_object(&self, hash: &asn1::Hash) -> Option<&Bytes> {
        self.objects.get(hash)
    }
}

type State = Arc<RwLock<ServerState>>;

#[tokio::main]
async fn main() {
    let opts = Arc::new(Opt::from_args());
    if let Err(cause) = ConsoleLogger::init(LevelFilter::Debug) {
        panic!("Failed to initialize logger: {}", cause);
    }

    info!("Starting EPIC to track {}", opts.fqdn.as_str());
    debug!(
        "Loading RPKI state from RRDP notify URL {}",
        opts.notify_url.as_str()
    );

    let init_rrdp = RrdpState::create(opts.notify_url.clone(), FetchMapper::empty()).await;
    if let Err(cause) = init_rrdp {
        error!("Cannot create RRDP state: {cause}");
        exit(1);
    }
    if let Ok(mut rrdp) = init_rrdp {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let mut init = ServerState::init();
        init.update(&opts.fqdn, &rrdp);

        let state: State = Arc::new(RwLock::new(init));
        let state_for_rrdp_updates = state.clone();

        let cfg = opts.clone();
        let updater = rt.spawn(async move {
            loop {
                sleep(Duration::from_secs(30)).await;
                info!("Updating RRDP");
                if let Err(cause) = rrdp.update().await {
                    warn!("RRDP update failed: {}", cause);
                    continue;
                }
                let mut state = state_for_rrdp_updates.write().await;
                state.update(&cfg.fqdn, &rrdp);
            }
        });
        let http_state = state.clone();
        let http = run(opts.clone(), http_state);
        if let (_, Err(cause)) = tokio::join!(updater, http) {
            error!("HTTP server failed: {}", cause);
        }
    }
}

async fn run(opts: Arc<Opt>, state: State) -> anyhow::Result<()> {
    let ni_state = state.clone();
    let named_information = async move |Path((alg, val)): Path<(String, String)>| {
        if alg != "sha-256" {
            return (
                StatusCode::BAD_REQUEST,
                format!("unsupported hashing algorithm: {alg}"),
            )
                .into_response();
        }
        match URL_SAFE_NO_PAD.decode(val.as_bytes()) {
            Ok(h) if h.len() == 32 => {
                if let Ok(hash) = asn1::Hash::try_from(h.as_slice()) {
                    debug!("GET {hash}");
                    let state = ni_state.read().await;
                    match state.get_object(&hash) {
                        Some(obj) => der(obj.clone()).into_response(),
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
        let lock = index_state.read().await;
        match lock.get_index(&fqdn) {
            Some(index) => {
                der(index.encode().to_captured(asn1::Mode::Der).into_bytes()).into_response()
            }
            None => not_found("index", fqdn).into_response(),
        }
    };

    let app = Router::new()
        .route(
            "/",
            get(|| async { "EPIC: Erik Protocol Implementation Concept" }),
        )
        .route("/.well-known/ni/{alg}/{val}", get(named_information))
        .route("/.well-known/erik/index/{fqdn}", get(named_index));

    let tls_config = RustlsConfig::from_pem_file(opts.cert_file.clone(), opts.key_file.clone()).await.unwrap();
    debug!("Setup TLS from certificate {} and key {}", opts.cert_file, opts.key_file);

    let addr = SocketAddr::from_str(format!("[::]:{}", opts.port).as_str())?;
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
    info!("Listening for HTTPS requests on {}:{}", addr.ip(), addr.port());

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

    #[structopt(long, default_value="./certificate.pem")]
    cert_file: String,
    #[structopt(long, default_value="./key.pem")]
    key_file: String,
}
