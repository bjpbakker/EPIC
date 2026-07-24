// Get ErikIndex or Partition files and dump them as somewhat readable JSON.

use std::path::PathBuf;

use log::LevelFilter;
use rpki::{rrdp, uri};
use structopt::StructOpt;

use epic::{
    fetch::{
        erik_client::{self, ErikClient},
        retrieval::{FetchMapper, Fqdn},
    },
    log::ConsoleLogger,
};

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("Error: {e}");
        ::std::process::exit(1);
    }
}

async fn try_main() -> Result<(), anyhow::Error> {
    let opts = Opt::from_args();

    if let Err(cause) = ConsoleLogger::init(LevelFilter::Debug) {
        panic!("Failed to initialize logger: {}", cause);
    }

    let mapper = FetchMapper::empty();

    let json = match opts.mode {
        Mode::Index => {
            let index = erik_client::get_erik_index(&opts.server, &opts.fqdn, &mapper).await?;
            serde_json::to_string_pretty(&index)
        }
        Mode::Partition { hash } => {
            let partition = erik_client::get_erik_partition(hash, &opts.server, &mapper).await?;
            serde_json::to_string_pretty(&partition)
        }
        Mode::SegmentIndex => {
            let segment_index =
                erik_client::get_segment_index(&opts.server, &opts.fqdn, &mapper).await?;
            serde_json::to_string_pretty(&segment_index)
        }
        Mode::ErikClient { state_dir } => {
            let mut client =
                ErikClient::start(&opts.server, opts.fqdn, &mapper, &state_dir).await?;
            client.update(&opts.server, &mapper).await?;

            client.save(&state_dir)?;

            Ok("erik client updated".to_string())
        }
    }?;

    println!("{json}");

    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct Opt {
    #[structopt(short, long)]
    server: uri::Https,

    #[structopt(short, long)]
    fqdn: Fqdn,

    #[structopt(subcommand)] // Note that we mark a field as a subcommand
    mode: Mode,
}

#[derive(StructOpt, Debug)]
enum Mode {
    Index,
    Partition {
        #[structopt(short, long)]
        hash: rrdp::Hash,
    },
    SegmentIndex,
    ErikClient {
        #[structopt(short, long)]
        state_dir: PathBuf,
    },
}
