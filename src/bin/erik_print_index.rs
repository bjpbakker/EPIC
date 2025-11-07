// Get ErikIndex or Partition files and dump them as somewhat readable JSON.

use bomans::{
    erik::asn1::ErikIndex,
    fetch::retrieval::{FetchMapper, Fqdn},
};
use rpki::uri;
use structopt::StructOpt;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("Error: {e}");
        ::std::process::exit(1);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let opts = Opt::from_args();

    let uri = opts
        .server
        .join(".well-known/erik/index/".as_ref())?
        .join(opts.fqdn.as_bytes())?;

    let fetch_mapper = FetchMapper::new();
    let index_bytes = fetch_mapper.resolve(uri).fetch(None)?.try_into_data()?;
    let erik_index = ErikIndex::decode(index_bytes.as_ref())?;

    let output = serde_json::to_string_pretty(&erik_index)?;

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
}
