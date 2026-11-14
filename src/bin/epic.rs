use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures_util::stream::{self, Stream};

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;

use std::sync::Arc;
use tokio::{
    sync::RwLock,
    time::{Duration, sleep},
};

use log::{LevelFilter, debug, error, info, warn};

use epic::{
    erik::{
        asn1::{self, ErikPartition},
        state::ResolvedErikIndex,
    },
    fetch::{
        retrieval::{FetchMapper, Fqdn},
        rrdp::RrdpState,
    },
    log::ConsoleLogger,
};
use rpki::{dep::bcder::encode::Values, repository::Manifest, uri};

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
            .and_then(|fqdn| self.indices.get(&fqdn))
    }

    fn get_object(&self, hash: &asn1::Hash) -> Option<&Bytes> {
        self.objects.get(hash)
    }

    /// Returns a stream of DER encoded objects making up the snapshot for
    /// the given FQDN, or `None` if the FQDN is unknown.
    ///
    /// The stream is `'static`: it owns (cheap, ref-counted) clones of the
    /// `Bytes` rather than borrowing `self`. This means the caller can drop
    /// the `RwLock` read guard before the response body is sent, so a slow
    /// client does not block the RRDP updater, and the snapshot stays
    /// consistent even if the state is updated while streaming.
    fn get_snapshot(
        &self,
        fqdn_str: &str,
    ) -> Option<impl Stream<Item = Result<Bytes, Infallible>> + Send + 'static> {
        if let Some(index) = self.get_index(fqdn_str) {
            let mut objects: Vec<Bytes> = vec![];

            // We have to loop through all the partitions and find all manifests, and then
            // find all objects on those manifests.If anything is missing or cannot be parsed,
            // which should never happen in practice, then it is simply skipped.
            //
            // This is okay, because the snapshot is a best effort collection of all current
            // objects.
            for partition_ref in index.partition_list() {
                if let Some(partition_bytes) = self.get_object(&partition_ref.hash)
                    && let Ok(partition) = ErikPartition::decode(partition_bytes.as_ref())
                {
                    for mft_ref in &partition.manifest_refs {
                        if let Some(mft_bytes) = self.get_object(&mft_ref.hash)
                            && let Ok(mft) = Manifest::decode(mft_bytes.as_ref(), false)
                        {
                            objects.push(mft_bytes.clone());
                            objects.extend(
                                mft.iter()
                                    .filter_map(|f| asn1::Hash::try_from(f.hash().as_ref()).ok())
                                    .filter_map(|hash| self.get_object(&hash).cloned()),
                            );
                        }
                    }
                }
            }

            Some(stream::iter(objects.into_iter().map(Ok)))
        } else {
            None
        }
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
                match rrdp.update().await {
                    Ok(true) => {
                        let mut state = state_for_rrdp_updates.write().await;
                        state.update(&cfg.fqdn, &rrdp);
                        info!("RRDP: updated {}", cfg.fqdn.as_str());
                    },
                    Ok(false) => debug!("RRDP: no update for {}", cfg.fqdn.as_str()),
                    Err(cause) => warn!("RRDP: failed to update {}: {}", cfg.fqdn.as_str(), cause)
                }
            }
        });

        let http_state = state.clone();
        let http = run(opts.clone(), http_state);

        // Run the updater and server threads in paralel
        // and exit in case of unrecoverable errors.
        if let (_, Err(cause)) = tokio::join!(updater, http) {
            error!("HTTP server failed: {}", cause);
        }
    }
}

async fn run(opts: Arc<Opt>, state: State) -> anyhow::Result<()> {
    // Support function to get an object given the hash
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

    // Support function to get the index for a given FQDN
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

    // Support function to get the snapshot for a given FQDN
    let snapshot_state = state.clone();
    let snapshot = async move |Path(fqdn): Path<String>| {
        debug!("GET Erik snapshot for {fqdn}");
        // The read guard is dropped at the end of this statement, before
        // the body is streamed to the client.
        let snapshot = snapshot_state.read().await.get_snapshot(&fqdn);
        match snapshot {
            Some(objects) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream+der")],
                Body::from_stream(objects),
            )
                .into_response(),
            None => not_found("snapshot", fqdn).into_response(),
        }
    };

    let app = Router::new()
        .route(
            "/",
            get(|| async { "EPIC: Erik Protocol Implementation Concept" }),
        )
        .route("/.well-known/ni/{alg}/{val}", get(named_information))
        .route("/.well-known/erik/index/{fqdn}", get(named_index))
        .route("/.well-known/erik/snapshot/{fqdn}", get(snapshot));

    let tls_config = RustlsConfig::from_pem_file(&opts.cert_file, &opts.key_file)
        .await
        .unwrap();
    debug!(
        "Setup TLS from certificate {} and key {}",
        opts.cert_file, opts.key_file
    );

    let server_handle = axum_server::Handle::new();
    let listen_handle = server_handle.clone();
    tokio::spawn(async move {
        if let Some(bound) = listen_handle.listening().await {
            info!("Listening for HTTPS requests on {bound}");
        }
    });
    let addr = SocketAddr::from_str(format!("[::]:{}", opts.port).as_str())?;
    axum_server::bind_rustls(addr, tls_config)
        .handle(server_handle)
        .serve(app.into_make_service())
        .await?;
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

    #[structopt(long, default_value = "./certificate.pem")]
    cert_file: String,
    #[structopt(long, default_value = "./key.pem")]
    key_file: String,
}
