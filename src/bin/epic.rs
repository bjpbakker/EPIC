use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use tower_http::compression::CompressionLayer;

use bytes::Bytes;

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
    erik::{asn1, state::ResolvedErikIndex},
    fetch::{
        retrieval::{FetchMapper, Fqdn},
        rrdp::RrdpState,
    },
    log::ConsoleLogger,
    server::cache::{Cache, InMemoryCache},
    server::http,
};
use rpki::{dep::bcder::encode::Values, uri};

use structopt::StructOpt;

struct ServerState<C: Cache> {
    cache: C,
}

impl<C: Cache> ServerState<C> {
    fn init(cache: C) -> Self {
        ServerState { cache }
    }

    fn update(&mut self, fqdn: &Fqdn, rrdp_state: &RrdpState) {
        if let Some(index) =
            ResolvedErikIndex::resolve(fqdn.as_str().into(), rrdp_state.manifests.values())
        {
            for partition in index.partitions.values() {
                let enc = asn1::ErikPartitionEncoder::from(partition);
                let der = enc.encode().to_captured(asn1::Mode::Der).into_bytes();
                let partition_ref = asn1::ErikPartitionRef::new(&der);
                self.cache.write_object(&partition_ref.hash, &der);
            }
            for (hash, object) in rrdp_state.elements.clone() {
                self.cache.write_object(&hash, &object.data());
            }

            let erik_index = asn1::ErikIndex::from(&index);
            self.cache.write_index(fqdn, &erik_index);
        }
    }
}

/// Lets the generic HTTP handlers in `epic::server::http` read from the
/// server state directly.
impl<C: Cache> Cache for ServerState<C> {
    fn read_index(&self, fqdn: &Fqdn) -> Option<&asn1::ErikIndex> {
        self.cache.read_index(fqdn)
    }

    fn write_index(&mut self, fqdn: &Fqdn, index: &asn1::ErikIndex) {
        self.cache.write_index(fqdn, index)
    }

    fn read_object(&self, hash: &asn1::Hash) -> Option<&Bytes> {
        self.cache.read_object(hash)
    }

    fn write_object(&mut self, hash: &asn1::Hash, data: &Bytes) {
        self.cache.write_object(hash, data)
    }
}

type State<C> = Arc<RwLock<ServerState<C>>>;

#[tokio::main]
async fn main() {
    let opts = Arc::new(Opt::from_args());
    if let Err(cause) = ConsoleLogger::init(LevelFilter::Info) {
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

        let mut init = ServerState::init(InMemoryCache::init());
        init.update(&opts.fqdn, &rrdp);

        let state_lock = Arc::new(RwLock::new(init));

        let cfg = opts.clone();
        let update_lock = state_lock.clone();
        let updater = rt.spawn(async move {
            loop {
                sleep(Duration::from_secs(30)).await;
                match rrdp.update().await {
                    Ok(true) => {
                        let mut state = update_lock.write().await;
                        state.update(&cfg.fqdn, &rrdp);
                        info!("RRDP: updated {}", cfg.fqdn.as_str());
                    }
                    Ok(false) => debug!("RRDP: no update for {}", cfg.fqdn.as_str()),
                    Err(cause) => warn!("RRDP: failed to update {}: {}", cfg.fqdn.as_str(), cause),
                }
            }
        });

        let http = run(opts.clone(), state_lock.clone());

        // Run the updater and server threads in paralel and exit in case of unrecoverable errors.
        if let (_, Err(cause)) = tokio::join!(updater, http) {
            error!("HTTP server failed: {}", cause);
        }
    }
}

async fn run<C: Cache>(opts: Arc<Opt>, state: State<C>) -> anyhow::Result<()> {
    let app = Router::new()
        .route(
            "/",
            get(|| async { "EPIC: Erik Protocol Implementation Concept" }),
        )
        .route("/.well-known/ni/{alg}/{val}", get(http::get_ni_object))
        .route("/.well-known/erik/index/{fqdn}", get(http::get_index))
        .route("/.well-known/erik/snapshot/{fqdn}", get(http::get_snapshot))
        .with_state(state)
        .layer(CompressionLayer::new());

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
