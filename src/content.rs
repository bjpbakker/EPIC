//! Keep track of the content of an Erik cache.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use log::{debug, info};
use serde::{Deserialize, Serialize};

use rpki::{
    repository::Manifest,
    rrdp::{Hash, PublishElement, Snapshot},
};

use crate::util::{de_bytes, ser_bytes};

/// This type contains a current element in a repository
#[derive(Debug, Deserialize, Serialize)]
pub struct RepoContentElement {
    /// The full URI where the the object was published.
    uri: rpki::uri::Rsync,

    /// The content of the object
    #[serde(serialize_with = "ser_bytes", deserialize_with = "de_bytes")]
    data: Bytes,
}

impl RepoContentElement {
    pub fn try_manifest(&self) -> Option<Manifest> {
        if self.uri.ends_with(".mft") {
            Manifest::decode(self.data.as_ref(), false).ok()
        } else {
            None
        }
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }
}

impl From<rpki::rrdp::PublishElement> for RepoContentElement {
    fn from(el: rpki::rrdp::PublishElement) -> Self {
        let (uri, data) = el.unpack();
        Self { uri, data }
    }
}

/// This type contains all current files published in a repository.
#[derive(Debug, Deserialize, Serialize)]
pub struct RepoContent {
    elements: HashMap<Hash, RepoContentElement>,
    manifests: HashMap<Hash, Manifest>,
}

impl RepoContent {
    /// To be deprecated when we implement proper fetching..
    pub fn create_test() -> anyhow::Result<Self> {
        let test_snapshot_file = include_bytes!(
            "../test-resources/rrdp-rev2656/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml"
        );
        let test_snapshot_bytes = Bytes::from_static(test_snapshot_file);

        let snapshot = Snapshot::parse(test_snapshot_bytes.as_ref()).unwrap();

        Self::create_from_snapshot(snapshot)
    }

    /// Create a full new RepoContent based on an RRDP snapshot.
    fn create_from_snapshot(snapshot: Snapshot) -> anyhow::Result<Self> {
        // Get all the publish elements from the snapshot
        let elements: HashMap<Hash, RepoContentElement> = snapshot
            .into_elements()
            .into_iter()
            .map(|e| (Hash::from_data(e.data()), e.into()))
            .collect();

        // Get all currently valid manifests from the elements
        // skip other objects, manifests that cannot be parsed
        // and expired manifests
        let manifests: HashMap<Hash, Manifest> = elements
            .iter()
            .flat_map(|(h, p)| p.try_manifest().map(|mft| (*h, mft)))
            .filter(|(_el, mft)| !mft.is_stale())
            .collect();

        Ok(RepoContent {
            elements,
            manifests,
        })
    }

    /// Get a map of the current PublishElements by their SHA256 hash
    /// including the rsync URI and Bytes content of the file.
    pub fn elements(&self) -> &HashMap<Hash, RepoContentElement> {
        &self.elements
    }

    /// Get a map of the current manifists by their SHA256 hash
    pub fn manifests(&self) -> &HashMap<Hash, Manifest> {
        &self.manifests
    }
}

#[cfg(test)]
mod tests {
    use crate::rrdp::RrdpState;

    use super::*;

    use std::path::PathBuf;

    #[test]
    fn create_repo_content_from_snapshot() {
        RepoContent::create_test().unwrap();
    }

    #[test]
    fn rrdp_state_deserialize() {
        let _state = RrdpState::recover(&PathBuf::from(
            "test-resources/validation/data-lacnic/rrdp-state.json",
        ))
        .unwrap();
    }
}
