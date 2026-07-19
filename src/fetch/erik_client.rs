//! Support for getting state from another Erik relay
//!

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rpki::{rrdp::Hash, uri};
use serde::{Deserialize, Serialize};

use crate::{
    erik::asn1::{ErikIndex, ErikPartition, ErikSegmentIndex},
    fetch::retrieval::{FetchMapper, Fqdn},
};

/// Gets the Erik Index for the given server and Fqdn
pub async fn get_erik_index(
    server: &uri::Https,
    fqdn: &Fqdn,
    mapper: &FetchMapper,
) -> Result<ErikIndex, anyhow::Error> {
    let uri = server
        .join(".well-known/erik/index/".as_ref())?
        .join(fqdn.as_bytes())?;

    let bytes = mapper.get_bytes(uri, None).await?;

    ErikIndex::decode(bytes.as_ref()).with_context(|| "Can't decode Erik Index")
}

/// Gets the Erik Segment Index for the given server and Fqdn
pub async fn get_segment_index(
    server: &uri::Https,
    fqdn: &Fqdn,
    mapper: &FetchMapper,
) -> Result<ErikSegmentIndex, anyhow::Error> {
    let uri = server
        .join(".well-known/erik/segmentindex/".as_ref())?
        .join(fqdn.as_bytes())?;

    let bytes = mapper.get_bytes(uri, None).await?;

    ErikSegmentIndex::decode(bytes.as_ref()).with_context(|| "Can't decode Erik Segment Index")
}

/// Gets the Erik Partition for the given server and hash of the partition
pub async fn get_erik_partition(
    hash: Hash,
    server: &uri::Https,
    mapper: &FetchMapper,
) -> Result<ErikPartition, anyhow::Error> {
    let base64_hash = URL_SAFE_NO_PAD.encode(hash.as_slice());

    let uri = server
        .join(".well-known/ni/sha-256/".as_ref())?
        .join(base64_hash.as_bytes())?;

    let bytes = mapper.get_bytes(uri, None).await?;

    ErikPartition::decode(bytes.as_ref()).with_context(|| "Can't decode Erik Partition")
}

/// An Erik Client that can maintain a local copy of the
/// state as is seen at another Erik relay.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErikClient {
    index: ErikIndex,
    partitions: Vec<ErikPartition>,
}

impl ErikClient {
    pub async fn initialise(
        server: &uri::Https,
        fqdn: &Fqdn,
        mapper: &FetchMapper,
    ) -> anyhow::Result<Self> {
        let index = get_erik_index(server, fqdn, mapper).await?;

        let mut partitions: Vec<ErikPartition> = vec![];
        for partition_ref in index.partition_list() {
            let hash = partition_ref.hash();
            let partition = get_erik_partition(hash, server, mapper).await?;
            partitions.push(partition);
        }

        Ok(Self { index, partitions })
    }
}

#[cfg(test)]
mod tests {}
