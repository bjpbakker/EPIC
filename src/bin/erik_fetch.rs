// Get ErikIndex or Partition files and dump them as somewhat readable JSON.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rpki::{rrdp, uri};
use structopt::StructOpt;

use epic::{
    erik::asn1::{ErikIndex, ErikPartition, ErikSegmentIndex},
    fetch::retrieval::{FetchMapper, Fqdn},
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

    let fetch_mapper = FetchMapper::empty();
    let uri = match opts.mode {
        Mode::Index => opts
            .server
            .join(".well-known/erik/index/".as_ref())?
            .join(opts.fqdn.as_bytes())?,
        Mode::Partition { hash } => {
            let base64_hash = URL_SAFE_NO_PAD.encode(hash.as_slice());
            opts.server
                .join(".well-known/ni/sha-256/".as_ref())?
                .join(base64_hash.as_bytes())?
        }
        Mode::SegmentIndex => opts
            .server
            .join(".well-known/erik/segmentindex/".as_ref())?
            .join(opts.fqdn.as_bytes())?,
    };

    let output = match opts.mode {
        Mode::Index => {
            let index_bytes = fetch_mapper
                .resolve(uri)
                .await
                .fetch(None)
                .await?
                .try_into_data()?;
            let erik_index = ErikIndex::decode(index_bytes.as_ref())?;

            serde_json::to_string_pretty(&erik_index)?
        }
        Mode::Partition { .. } => {
            let partition_bytes = fetch_mapper
                .resolve(uri)
                .await
                .fetch(None)
                .await?
                .try_into_data()?;
            let partition = ErikPartition::decode(partition_bytes.as_ref())?;

            serde_json::to_string_pretty(&partition)?
        }
        Mode::SegmentIndex => {
            let segment_index_bytes = fetch_mapper
                .resolve(uri)
                .await
                .fetch(None)
                .await?
                .try_into_data()?;
            let segment_index = ErikSegmentIndex::decode(segment_index_bytes.as_ref())?;

            serde_json::to_string_pretty(&segment_index)?
        }
    };

    println!("{output}");

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
