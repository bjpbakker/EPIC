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
        decode::{self, DecodeError, IntoSource, Source},
        encode::{self, PrimitiveContent, Values},
    },
    oid::{self, SHA256},
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
pub const ERIK_INDEX_OID: Oid<&[u8]> = Oid(&[43, 6, 1, 4, 1, 130, 199, 92, 134, 58]);

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
pub struct ResolvedErikIndex {
    // version [0]
    index_scope: String, // FQDN, perhaps we should use a strong type
    index_time: Time,
    // hashAlg RSA-256
    partitions: HashMap<ErikPartitionKey, ErikPartition>,
}

impl ResolvedErikIndex {
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
            .map(|max_partition_time| ResolvedErikIndex {
                index_scope,
                index_time: max_partition_time,
                partitions,
            })
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ErikIndex {
    index_scope: Ia5String,
    index_time: Time,
    partitions: Vec<ErikPartitionRef>,
}

impl ErikIndex {
    pub fn encode(&self) -> impl encode::Values {
        let content =         encode::sequence_as(
            Tag::CTX_0,
            OctetString::encode_wrapped(
                Mode::Der,
                encode::sequence((
                    // version [0] default, not encoded
                    self.index_scope.encode_ref(),
                    self.index_time.encode_generalized_time(),
                    SHA256.encode(),
                    encode::sequence(encode::iter(self.partitions.iter().map(|p| p.encode()))),
                )),
            ),
        );
        encode::sequence((ERIK_INDEX_OID.encode_ref(), content))
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let content: OctetString = cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;
            if oid != ERIK_INDEX_OID {
                return Err(cons.content_err("not an Erik index OID"));
            }
            cons.take_constructed_if(Tag::CTX_0, OctetString::take_from)
        })?;

        Mode::Der
            .decode(content, |cons| {
                cons.take_sequence(|cons| {
                    let index_scope = Ia5String::take_from(cons)?;
                    let index_time = Time::take_from(cons)?;
                    let hashing_algorithm = Oid::take_from(cons)?;
                    if hashing_algorithm != oid::SHA256 {
                        return Err(cons.content_err("invalid digest algorithm"));
                    }
                    let partitions = cons.take_sequence(|cons| {
                        let mut partitions = vec![];
                        while let Some(partition) =
                            cons.take_opt_constructed_if(Tag::SEQUENCE, |cons| {
                                _ = cons.take_opt_u8()?;
                                let hash_value = OctetString::take_from(cons)?;
                                let hash = Hash::try_from(hash_value.into_bytes().as_ref())
                                    .map_err(|_| cons.content_err("invalid hash value"))?;
                                let size = cons.take_u32()?;
                                Ok(ErikPartitionRef { hash, size })
                            })?
                        {
                            partitions.push(partition)
                        }
                        Ok(partitions)
                    })?;
                    Ok(ErikIndex {
                        index_scope,
                        index_time,
                        partitions,
                    })
                })
            })
            .map_err(|err| err.convert())
    }
}

impl From<&ResolvedErikIndex> for ErikIndex {
    fn from(index: &ResolvedErikIndex) -> Self {
        let mut partitions = vec![];
        for p in index.partitions.values() {
            let part_enc = ErikPartitionEncoder::from(p);
            let bytes = part_enc.to_captured().into_bytes();
            let erik_part_ref = ErikPartitionRef::new(&bytes);
            partitions.push(erik_part_ref);
        }
        partitions.sort();

        ErikIndex {
            index_scope: Ia5String::from_string(index.index_scope.clone()).unwrap(),
            index_time: index.index_time,
            partitions,
        }
    }
}

/// ErikPartitionRef as defined in section 3 of the draft.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub struct ErikPartitionRef {
    hash: Hash,
    size: u32, // max 4GB is enough
}

impl ErikPartitionRef {
    pub fn new(partition_bytes: &Bytes) -> Self {
        let hash = Hash::from_data(&partition_bytes);
        let size = partition_bytes.len() as u32;

        ErikPartitionRef { hash, size }
    }

    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((self.hash.as_slice().encode(), self.size.encode()))
    }
}

impl Ord for ErikPartitionRef {
    // Hashes are supposed to be unique, so we can order by hash alone
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hash.as_slice().cmp(other.hash.as_slice())
    }
}

impl PartialOrd for ErikPartitionRef {
    // Hashes are supposed to be unique, so we can order by hash alone
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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

// - Decode
impl ErikPartition {
    /// Decodes an ErikPartition from a source.
    #[allow(clippy::redundant_closure)]
    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

    /// Takes an ErikPartition from a constructed value
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let partition_time = Time::take_from(cons)?;
            let alg = DigestAlgorithm::take_from(cons)?;
            if alg != DigestAlgorithm::sha256() {
                return Err(cons.content_err("Wrong digest algorithm"));
            }

            let mut manifest_refs = HashSet::new();

            cons.take_sequence(|cons| {
                while let Some(entry) = ManifestRef::take_opt_from(cons)? {
                    manifest_refs.insert(Arc::new(entry));
                }
                Ok(())
            })?;

            Ok(ErikPartition {
                partition_time,
                manifest_refs,
            })
        })
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

    /// For now this is a single URI for the AD_SIGNED_OBJECT
    /// but we may get more access descriptors in future.
    locations: uri::Rsync,
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
            locations: location,
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
            encode::sequence((
                oid::AD_SIGNED_OBJECT.encode(),
                self.locations.encode_general_name(),
            )),
        ))
    }

    /// Takes a ManifestRef from a constructed value
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let hash = {
                let octets = OctetString::take_from(cons)?.into_bytes();
                Hash::try_from(octets.as_ref()).map_err(|_| cons.content_err("invalid hash"))?
            };
            let size = cons.take_u32()? as usize; // Will error out on sizes > 4GB
            let aki = KeyIdentifier::take_from(cons)?;
            let manifest_number = Serial::take_from(cons)?;
            let this_update = Time::take_from(cons)?;

            let locations = Self::take_locations(cons)?;

            Ok(ManifestRef {
                hash,
                size,
                aki,
                manifest_number,
                this_update,
                locations,
            })
        })
    }

    /// Take the locations value from a constructed value
    pub fn take_locations<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<uri::Rsync, DecodeError<S::Error>> {
        // Coded after how the SIA is parsed in Cert in rpki-rs.
        // Re-using the code directly was not possible, because
        // the relevant functions are not public.
        cons.take_sequence(|cons| {
            // We have an SIA sequence and expect only 1 entry
            // for the ad_signed_object
            oid::AD_SIGNED_OBJECT.skip_if(cons)?;
            cons.take_value_if(Tag::CTX_6, |content| {
                let string = Ia5String::from_content(content)?;
                uri::Rsync::from_bytes(string.into_bytes())
                    .map_err(|_| content.content_err("invalid uri for manifest"))
            })
        })
    }
}

impl TryFrom<&Manifest> for ManifestRef {
    type Error = anyhow::Error;

    fn try_from(mft: &Manifest) -> Result<Self, Self::Error> {
        let manifest_bytes = mft.to_captured();

        let locations = mft
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
            locations,
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

    use ::base64::prelude::*;
    use bytes::Bytes;
    use rpki::dep::bcder::decode::IntoSource;

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
    fn erik_partition_encode_and_decode() {
        let erik = test_index_from_content();
        let partition = erik.partitions.values().next().unwrap();
        let encoder = ErikPartitionEncoder::from(partition);
        let encoded = encoder.to_captured().into_bytes();
        // let base64 = BASE64_STANDARD.encode(encoded.as_ref());
        // println!("{base64}");

        let _decoded = ErikPartition::decode(encoded).unwrap();
    }

    #[test]
    fn erik_index_encode() {
        let erik = test_index_from_content();
        let encoder = ErikIndex::from(&erik);
        let encoded = encoder.encode().to_captured(Mode::Der).into_bytes();
        let base64 = BASE64_STANDARD.encode(encoded.as_ref());
        println!("{base64}");

        let decoded = Mode::Der
            .decode(encoded, ErikIndex::take_from)
            .unwrap();
    }

    #[test]
    fn erik_index_decode_rfc_example() {
        let input = include_bytes!("../test-resources/erik-types/05-index.der");
        let index = Mode::Der
            .decode(input.as_ref().into_source(),
                |cons| ErikIndex::take_from(cons),
            )
            .unwrap();
        assert_eq!(256, index.partitions.len());
        let encoded = index.encode().to_captured(Mode::Der).into_bytes();
        // This does not yet work as the 05 draft example includes the partition identifier field.
        // The idenfiier is skipped (when present) during decoding, but is not added back in with encoding.
        //assert_eq!(Bytes::from(input.as_slice()), encoded);
        let base64 = BASE64_STANDARD_NO_PAD.encode(encoded.as_ref());
        println!("{base64}");
    }

    fn test_index_from_content() -> ResolvedErikIndex {
        let repo_content = RepoContent::create_test().unwrap();
        ResolvedErikIndex::from_content("krill-ui-dev.do.nlnetlabs.nl".to_string(), &repo_content).unwrap()
    }
}
