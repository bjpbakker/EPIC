//! This module contains the Erik Synchronization Data Structure types
//!

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use rpki::{
    crypto::{DigestAlgorithm, KeyIdentifier},
    dep::bcder::{
        Captured, Ia5String, Mode, OctetString, Oid, Tag,
        encode::{self, PrimitiveContent, Values},
    },
    oid::SHA256,
    repository::{
        Manifest,
        x509::{Serial, Time},
    },
    rrdp::Hash,
    uri,
};
use serde::{Deserialize, Serialize};

use crate::content::RepoContent;

// See: https://misc.daniel-marschall.de/asn.1/oid-converter/online.php
// 1.3.6.1.4.1.41948.826 => 06 0A 2B 06 01 04 01 82 C7 5C 86 3A
pub const ERIK_INDEX_OID: Oid<&[u8]> = Oid(&[
    0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc7, 0x5c, 0x86, 0x3a,
]);

/// The Erik Partition key is used to determine
/// which partition should be used for a ManifestRef
///
/// DISCUSS: The draft says this should go up to 1024
/// but we only go up to 256 here, because it's just
/// much easier to take the first full byte from the
/// authority key identifier, rather than the first
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

        for mft_ref in content.manifests().values() {
            let partition_key = ErikPartitionKey::from(mft_ref.as_ref());

            if let Some(partition) = partitions.get_mut(&partition_key) {
                partition.add_manifest_ref(mft_ref.clone());
            } else {
                partitions.insert(
                    partition_key,
                    ErikPartition::create_from_manifest_ref(mft_ref.clone()),
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

/// ErikIndexEncoder
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikIndexEncoder {
    content: ErikIndexContentEncoder,
}

impl ErikIndexEncoder {
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((ERIK_INDEX_OID.encode_ref(), self.content.encode()))
    }
}

impl From<&ErikIndex> for ErikIndexEncoder {
    fn from(index: &ErikIndex) -> Self {
        let content = ErikIndexContentEncoder::from(index);

        ErikIndexEncoder { content }
    }
}

/// ErikIndexContentEncoder
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikIndexContentEncoder {
    index_scope: Ia5String,
    index_time: Time,
    partitions: Captured,
}

impl ErikIndexContentEncoder {
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence_as(
            Tag::CTX_0,
            OctetString::encode_wrapped(
                Mode::Der,
                encode::sequence((
                    // version [0] default, not encoded
                    self.index_scope.encode_ref(),
                    self.index_time.encode_generalized_time(),
                    SHA256.encode(),
                    encode::sequence(self.partitions.encode()),
                )),
            ),
        )
    }
}

impl From<&ErikIndex> for ErikIndexContentEncoder {
    fn from(index: &ErikIndex) -> Self {
        let mut captured = Captured::builder(Mode::Der);

        for p in index.partitions.values() {
            let part_enc = ErikPartitionEncoder::from(p);
            let bytes = part_enc.to_captured().into_bytes();
            let erik_part_ref = ErikPartitionRef::new(&bytes);
            captured.extend(erik_part_ref.encode());
        }

        ErikIndexContentEncoder {
            index_scope: Ia5String::from_string(index.index_scope.clone()).unwrap(),
            index_time: index.index_time,
            partitions: captured.freeze(),
        }
    }
}

/// ErikPartitionRef as defined in section 3 of the draft.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikPartitionRef {
    _identifier: u32, // To be deprecated
    hash: Hash,
    size: u32, // max 4GB is enough
}

impl ErikPartitionRef {
    pub fn new(partition_bytes: &Bytes) -> Self {
        let _identifier = 1;
        let hash = Hash::from_data(&partition_bytes);
        let size = partition_bytes.len() as u32;

        ErikPartitionRef {
            _identifier,
            hash,
            size,
        }
    }

    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            self._identifier.encode(),
            self.hash.as_slice().encode(),
            self.size.encode(),
        ))
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
    fn create_from_manifest_ref(mft: Arc<ManifestRef>) -> Self {
        let partition_time = mft.this_update;
        let mut manifest_refs = HashSet::new();
        manifest_refs.insert(mft);

        ErikPartition {
            partition_time,
            manifest_refs,
        }
    }

    fn add_manifest_ref(&mut self, mft_ref: Arc<ManifestRef>) {
        if self.partition_time > mft_ref.this_update {
            self.partition_time = mft_ref.this_update;
        }
        self.manifest_refs.insert(mft_ref);
    }
}

/// ErikPartitionEncoder
///
/// This type is introduced because of lifetime and typing
/// shenanigans. It's hard to encode something that has a
/// set or vec of some type. Manifests and ROAs in rpki-rs
/// use a Captured for this and then have special code to
/// construnct or or iterate over that content. This makes
/// sense in Routinator because it avoids cloning data, and
/// Krill does not care much, because it can just create the
/// signed objects once and then keep them around.
///
/// In the contect of this codebase however, we want to keep
/// many ManifestRef's around in Arcs for cheap sharing between
/// various ErikPartitionIndex instances.
///
/// So, the best work around that I can come up with for now
/// is to have an ErikPartitionEncoder type that can be built
/// from an ErikPartition and that can own a 'Captured' for
/// the ManifestRef entries. This is not too costly, as we
/// should really only have to encode an ErikPartition once,
/// after which we can keep the encoded bytes around and stick
/// it in a hash -> bytes value store.
///
/// Better suggestions are welcome!
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikPartitionEncoder {
    // version [0]
    // hashAlg SHA-256
    /// most recent this update among manifests
    partition_time: Time,
    manifest_refs: Captured,
}

impl From<&ErikPartition> for ErikPartitionEncoder {
    fn from(p: &ErikPartition) -> Self {
        // Build a SORTED sequence of manifest refs
        let mut captured = Captured::builder(Mode::Der);
        let mut refs: Vec<_> = p.manifest_refs.iter().collect();
        refs.sort();
        for mft_ref in refs {
            captured.extend(mft_ref.encode());
        }

        ErikPartitionEncoder {
            partition_time: p.partition_time,
            manifest_refs: captured.freeze(),
        }
    }
}

impl ErikPartitionEncoder {
    /// Returns a value encoder for a reference to the manifest.
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            self.partition_time.encode_generalized_time(),
            DigestAlgorithm::sha256().encode(),
            encode::sequence(&self.manifest_refs),
        ))
    }

    /// Returns a DER encoded Captured for this.
    pub fn to_captured(&self) -> Captured {
        self.encode().to_captured(Mode::Der)
    }
}

/// ManifestRef as defined in section 3 of the draft.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[allow(dead_code)]
pub struct ManifestRef {
    hash: Hash,
    size: usize,
    aki: KeyIdentifier,
    manifest_number: Serial,
    this_update: Time,

    /// DISCUS:
    /// - Why do we need this?
    /// - How should this be encoded? Like the full SIA?
    /// - If we need this, why not the one rsync URI for the mft object itself?
    /// - And if so, why can't we just encode it as a string?
    ///
    /// My guess it that the intent is to make this generic over whatever
    /// SIA may become in future, but still why do we need this here? Users
    /// can just get the actual object by hash and parse it.
    ///
    /// For now, just using a single Rsync URI here. But we may have to
    /// change this.
    location: uri::Rsync,
}

impl ManifestRef {
    pub fn new(
        hash: Hash,
        size: usize,
        aki: KeyIdentifier,
        manifest_number: Serial,
        this_update: Time,
        location: uri::Rsync,
    ) -> Self {
        ManifestRef {
            hash,
            size,
            aki,
            manifest_number,
            this_update,
            location,
        }
    }
}

impl ManifestRef {
    fn encode(&'_ self) -> impl encode::Values + '_ {
        let size = self.size as u128;

        encode::sequence((
            self.hash.as_slice().encode(),
            size.encode(),
            self.aki.encode(),
            self.manifest_number.encode(),
            self.this_update.encode_generalized_time(),
            self.location.encode_general_name(),
        ))
    }
}

impl TryFrom<&Manifest> for ManifestRef {
    type Error = anyhow::Error;

    fn try_from(mft: &Manifest) -> Result<Self, Self::Error> {
        let manifest_bytes = mft.to_captured();

        let location = mft
            .cert()
            .signed_object()
            .ok_or(anyhow!("Manifest EE has no URI for the signed object"))?
            .clone();

        Ok(ManifestRef {
            hash: Hash::from_data(&manifest_bytes),
            size: manifest_bytes.len(),
            aki: mft
                .cert()
                .authority_key_identifier()
                .ok_or(anyhow!("Manifest has EE cert without AKI?!?"))?,
            manifest_number: mft.manifest_number(),
            this_update: mft.this_update(),
            location,
        })
    }
}

impl Ord for ManifestRef {
    // Hashes are supposed to be unique, so we can order by hash alone
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hash.as_slice().cmp(other.hash.as_slice())
    }
}

impl PartialOrd for ManifestRef {
    // Hashes are supposed to be unique, so we can order by hash alone
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {

    use crate::content::RepoContent;

    use super::*;

    // use base64::engine::general_purpose::STANDARD;

    use ::base64::prelude::*;
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
        test_index_from_content();
    }

    #[test]
    fn erik_partition_encode() {
        let erik = test_index_from_content();
        let partition = erik.partitions.values().next().unwrap();
        let encoder = ErikPartitionEncoder::from(partition);
        encoder.to_captured();
    }

    #[test]
    fn erik_index_encode() {
        let erik = test_index_from_content();
        let encoder = ErikIndexEncoder::from(&erik);
        let encoded = encoder.encode().to_captured(Mode::Der).into_bytes();
        BASE64_STANDARD.encode(encoded.as_ref());
    }

    fn test_index_from_content() -> ErikIndex {
        let repo_content = RepoContent::create_test().unwrap();
        ErikIndex::from_content("krill-ui-dev.do.nlnetlabs.nl".to_string(), &repo_content).unwrap()
    }
}
