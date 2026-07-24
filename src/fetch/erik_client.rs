//! Support for getting state from another Erik relay
//!

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use log::debug;
use rpki::{rrdp::Hash, uri};
use serde::{Deserialize, Serialize};

use crate::{
    erik::asn1::{ErikIndex, ErikPartition, ErikSegmentIndex},
    fetch::retrieval::{FetchMapper, Fqdn},
    util,
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
    fqdn: Fqdn,
    index: ErikIndex,
    partitions: HashMap<Hash, ErikPartition>,
}

impl ErikClient {
    /// Starts an Erik client for the given FQDN,
    /// loading it from disk if present.
    pub async fn start(
        server: &uri::Https,
        fqdn: Fqdn,
        mapper: &FetchMapper,
        state_dir: &Path,
    ) -> anyhow::Result<Self> {
        if let Ok(client) = Self::load(state_dir, &fqdn) {
            Ok(client)
        } else {
            Self::initialise_new(server, fqdn, mapper).await
        }
    }

    /// Creates a new client without using prior state
    pub async fn initialise_new(
        server: &uri::Https,
        fqdn: Fqdn,
        mapper: &FetchMapper,
    ) -> anyhow::Result<Self> {
        let index = get_erik_index(server, &fqdn, mapper).await?;

        let mut partitions = HashMap::new();
        for partition_ref in index.partition_list() {
            let hash = partition_ref.hash();
            let partition = get_erik_partition(hash, server, mapper).await?;
            partitions.insert(hash, partition);
        }

        Ok(Self {
            fqdn,
            index,
            partitions,
        })
    }

    /// Update state
    pub async fn update(
        &mut self,
        server: &uri::Https,
        mapper: &FetchMapper,
    ) -> anyhow::Result<()> {
        // todo: conditional get 'if-modified-since'
        let index = get_erik_index(server, &self.fqdn, mapper).await?;

        if self.index == index {
            debug!(
                "Erik Index for {} at {} unchanged",
                self.fqdn.as_str(),
                server
            );

            // nothing to do, move along
            Ok(())
        } else {
            let mut partitions_to_process: HashSet<Hash> =
                index.partition_list().iter().map(|p| p.hash()).collect();

            // Keep the partitions still included in the new index
            // and drop the rest.
            self.partitions
                .retain(|hash, _| partitions_to_process.contains(hash));

            // Remove the references to partitions we already have
            partitions_to_process.retain(|hash| !self.partitions.contains_key(hash));

            for new_partition_hash in partitions_to_process {
                let partition = get_erik_partition(new_partition_hash, server, mapper).await?;
                self.partitions.insert(new_partition_hash, partition);
            }

            self.index = index;

            Ok(())
        }
    }

    /// Save the state of this client instance to disk
    pub fn save(&self, state_dir: &Path) -> anyhow::Result<()> {
        let fqdn: Fqdn = self.index.index_scope().try_into()?;
        let state_file = Self::state_file(state_dir, &fqdn);
        util::save_json(&self, &state_file)
    }

    /// Load a client instance from disk
    pub fn load(state_dir: &Path, fqdn: &Fqdn) -> anyhow::Result<Self> {
        let state_file = Self::state_file(state_dir, fqdn);
        util::load_json(&state_file)
    }

    fn state_file(state_dir: &Path, fqdn: &Fqdn) -> PathBuf {
        state_dir.join(format!("erik-client-{}.state", fqdn.as_str()))
    }
}

#[cfg(test)]
mod tests {}
