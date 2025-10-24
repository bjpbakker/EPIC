//! This module contains the Erik Synchronization Data Structure types
//!

use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow};
use rpki::{
    crypto::KeyIdentifier,
    repository::{
        Manifest,
        x509::{Serial, Time},
    },
    rrdp::Hash,
};

/// ErikPartition as defined in section 3 of the draft.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikPartition {
    // version [0]
    // hashAlg SHA-256
    /// most recent this update among manifests
    partition_time: Time,

    /// Draft has a list, but we use a map for quick access
    /// and an Arc around ManifestRef for cheaper cloning
    /// which we will likely need when we start parsing and
    /// updating structures that own a partition. Note that
    /// ManifestRef is immutable.
    manifest_refs: HashMap<Hash, Arc<ManifestRef>>,
}

impl ErikPartition {
    /// Create a partition from manifests.
    pub fn from_manifests(manifests: &HashMap<Hash, Manifest>) -> anyhow::Result<Option<Self>> {
        let mut partition_time_opt: Option<Time> = None;
        let mut manifest_refs = HashMap::new();

        for (hash, mft) in manifests {
            let manifest_ref = ManifestRef::try_from(mft)?;

            if let Some(time) = partition_time_opt {
                if time > manifest_ref.this_update {}
            } else {
                partition_time_opt = Some(manifest_ref.this_update)
            }

            manifest_refs.insert(*hash, Arc::new(manifest_ref));
        }

        if let Some(partition_time) = partition_time_opt {
            Ok(Some(ErikPartition {
                partition_time,
                manifest_refs,
            }))
        } else {
            Ok(None)
        }
    }
}

/// ManifestRef as defined in section 3 of the draft.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ManifestRef {
    hash: Hash,
    size: usize,
    aki: KeyIdentifier,
    manifest_number: Serial,
    this_update: Time,
    location: KeyIdentifier, // SKI, draft wants a sequence here, I don't understand why
}

impl TryFrom<&Manifest> for ManifestRef {
    type Error = anyhow::Error;

    fn try_from(mft: &Manifest) -> Result<Self, Self::Error> {
        let manifest_bytes = mft.to_captured();
        Ok(ManifestRef {
            hash: Hash::from_data(&manifest_bytes),
            size: manifest_bytes.len(),
            aki: mft
                .cert()
                .authority_key_identifier()
                .ok_or(anyhow!("Manifest has EE cert without AKI?!?"))?,
            manifest_number: mft.manifest_number(),
            this_update: mft.this_update(),
            location: mft.cert().subject_key_identifier(),
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::content::RepoContent;

    use super::*;

    use bytes::Bytes;

    #[test]
    fn manifest_ref_from_manifest() {
        let manifest_der = include_bytes!("../test-resources/erik-types/manifest.mft");
        let manifest_bytes = Bytes::from_static(manifest_der);
        let manifest = Manifest::decode(manifest_bytes.as_ref(), true).unwrap();

        let manifest_ref = ManifestRef::try_from(&manifest).unwrap();
    }

    #[test]
    fn partition_from_manifests() {
        let erik_content = RepoContent::create_test().unwrap();

        let manifests = erik_content.manifests();

        // normally the manifest SKI determines which partition it should appear
        // in, but here we just put all manifests in a partition to unit test
        // the function to create a partation for (selected) manifests.
        ErikPartition::from_manifests(manifests).unwrap();
    }
}
