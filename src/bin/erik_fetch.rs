// Get ErikIndex or Partition files and dump them as somewhat readable JSON.

use rpki::{rrdp, uri};
use structopt::StructOpt;

use epic::fetch::{
    erik_client::ErikClient,
    retrieval::{FetchMapper, Fqdn},
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

    let mapper = FetchMapper::empty();

    let json = match opts.mode {
        Mode::Index => {
            let index = ErikClient::get_erik_index(opts.server, opts.fqdn, mapper).await?;
            serde_json::to_string_pretty(&index)
        }
        Mode::Partition { hash } => {
            let partition = ErikClient::get_erik_partition(hash, opts.server, mapper).await?;
            serde_json::to_string_pretty(&partition)
        }
        Mode::SegmentIndex => {
            let segment_index =
                ErikClient::get_segment_index(opts.server, opts.fqdn, mapper).await?;
            serde_json::to_string_pretty(&segment_index)
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
}
