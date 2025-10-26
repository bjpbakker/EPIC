//! This module contains the Erik Synchronization Data Structure types
//!

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use rpki::{
    crypto::KeyIdentifier,
    repository::{
        Manifest,
        x509::{Serial, Time},
    },
    rrdp::Hash,
};

use crate::content::RepoContent;

/// The Erik Partition key is used to determine
/// which partition should be used for a ManifestRef
///
/// DISCUSS: The draft says this should go up to 1024
/// but we only go up to 256 here, because it's just
/// much easier to take the first full byte from the
/// authoirty key identifier, rather than the first
/// 10 bits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ErikPartitionKey(u8);

impl From<&ManifestRef> for ErikPartitionKey {
    fn from(mft_ref: &ManifestRef) -> Self {
        Self(mft_ref.aki.as_slice()[0])
    }
}

/// ErikIndex as defined in section 3 of the draft
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikIndex {
    // version [0]
    index_scope: String, // FQDN, perhaps we should use a strong type
    index_time: Time,
    // hashAlg RSA-256
    partitions: HashMap<ErikPartitionKey, ErikPartition>,
}

impl ErikIndex {
    /// Creates and ErikIndex from the given content.
    pub fn from_content(index_scope: String, content: &RepoContent) -> Option<Self> {
        let mut partitions: HashMap<ErikPartitionKey, ErikPartition> = HashMap::new();

        for mft_ref in content
            .manifests()
            .values()
            // convert to ManifestRef and skip any mft without AKI (this should never happen)
            .flat_map(|mft| ManifestRef::try_from(mft).ok())
        {
            let partition_key = ErikPartitionKey::from(&mft_ref);

            if let Some(partition) = partitions.get_mut(&partition_key) {
                partition.add_manifest_ref(mft_ref);
            } else {
                partitions.insert(
                    partition_key,
                    ErikPartition::create_from_manifest_ref(mft_ref),
                );
            }
        }

        // If partitions is empty we return None, otherwise we find the
        // most recent partition time among partitions and return Some
        // ErikIndex using that valid as its index_time.
        partitions
            .values()
            .map(|p| p.partition_time)
            .max()
            .map(|max_partition_time| ErikIndex {
                index_scope,
                index_time: max_partition_time,
                partitions,
            })
    }
}

/// ErikPartition as defined in section 3 of the draft.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikPartition {
    // version [0]
    // hashAlg SHA-256
    /// most recent this update among manifests
    partition_time: Time,

    /// We use an Arc around ManifestRef for cheaper cloning
    /// which we will likely need when we start parsing and
    /// updating structures that own a partition. Note that
    /// ManifestRef is immutable.
    manifest_refs: HashSet<Arc<ManifestRef>>,
}

impl ErikPartition {
    fn create_from_manifest_ref(mft: ManifestRef) -> Self {
        let partition_time = mft.this_update;
        let mut manifest_refs = HashSet::new();
        manifest_refs.insert(Arc::new(mft));

        ErikPartition {
            partition_time,
            manifest_refs,
        }
    }

    fn add_manifest_ref(&mut self, mft_ref: ManifestRef) {
        if self.partition_time > mft_ref.this_update {
            self.partition_time = mft_ref.this_update;
        }
        self.manifest_refs.insert(Arc::new(mft_ref));
    }
}

/// ManifestRef as defined in section 3 of the draft.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

        let _manifest_ref = ManifestRef::try_from(&manifest).unwrap();
    }

    #[test]
    fn erik_index_from_content() {
        let repo_content = RepoContent::create_test().unwrap();

        ErikIndex::from_content("krill-ui-dev.do.nlnetlabs.nl".to_string(), &repo_content);
    }
}
