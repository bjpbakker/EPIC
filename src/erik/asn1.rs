//! This module contains the Erik Synchronization Data Structure types
//!

use std::{collections::HashSet, sync::Arc};

use anyhow::{Result, anyhow};
use bytes::Bytes;
use rpki::{
    crypto::KeyIdentifier,
    dep::bcder::{
        Captured, OctetString, Oid, Tag,
        decode::{self, DecodeError, IntoSource, Source},
        encode::{self, PrimitiveContent, Values},
    },
    oid,
    repository::{
        Manifest,
    },
    uri,
};
use serde::{Deserialize, Serialize};

use crate::{
    erik,
    util::{de_ia5_string, ser_ia5_string},
};

pub use rpki::dep::bcder::{Ia5String, Mode};
pub use rpki::rrdp::Hash;
pub use rpki::repository::x509::{Serial, Time};

// Use 'bin/mkoid' in the bcder lib to produce these OIDs
/// 1.2.840.113549.1.9.16.1.55
pub const ERIK_INDEX_OID: Oid<&[u8]> = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 55]);
/// 1.2.840.113549.1.9.16.1.56
pub const ERIK_PARTITION_OID: Oid<&[u8]> = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 56]);
/// 1.3.6.1.4.1.41948.828
pub const ERIK_SEGMENT_INDEX_OID: Oid<&[u8]> = Oid(&[43, 6, 1, 4, 1, 130, 199, 92, 134, 60]);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErikIndex {
    #[serde(serialize_with = "ser_ia5_string", deserialize_with = "de_ia5_string")]
    pub index_scope: Ia5String,
    pub index_time: Time,
    pub partition_list: Vec<ErikPartitionRef>,
}

impl ErikIndex {
    pub fn index_scope(&self) -> &Ia5String {
        &self.index_scope
    }

    pub fn partition_list(&self) -> &Vec<ErikPartitionRef> {
        &self.partition_list
    }

    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            ERIK_INDEX_OID.encode_ref(),
            encode::sequence_as(
                Tag::CTX_0,
                encode::sequence((
                    // version [0] default, not encoded
                    self.index_scope.encode_ref(),
                    self.index_time.encode_generalized_time(),
                    encode::sequence(oid::SHA256.encode()),
                    encode::sequence(encode::iter(self.partition_list.iter().map(|p| p.encode()))),
                )),
            ),
        ))
    }

    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;
            if oid != ERIK_INDEX_OID {
                return Err(cons.content_err(format!(
                    "not an Erik index OID. Got: {}, expected: {}",
                    oid, ERIK_INDEX_OID
                )));
            }

            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    let index_scope = Ia5String::take_from(cons)?;
                    let index_time = Time::take_from(cons)?;
                    let hashing_algorithm = cons.take_sequence(|cons| Oid::take_from(cons))?;
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
                        partition_list: partitions,
                    })
                })
            })
        })
    }
}

impl From<&erik::state::ResolvedErikIndex> for ErikIndex {
    fn from(index: &erik::state::ResolvedErikIndex) -> Self {
        let mut partitions: Vec<ErikPartitionRef> = index.partitions.values()
            .map(ErikPartitionRef::from)
            .collect();
        partitions.sort();
        ErikIndex {
            index_scope: Ia5String::from_string(index.index_scope.clone()).unwrap(),
            index_time: index.index_time,
            partition_list: partitions,
        }
    }
}

/// ErikPartitionRef as defined in section 3 of the draft.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[allow(dead_code)]
pub struct ErikPartitionRef {
    pub hash: Hash,
    pub size: u32, // max 4GB is enough
}

impl ErikPartitionRef {
    pub fn new(partition_bytes: &Bytes) -> Self {
        let hash = Hash::from_data(partition_bytes);
        let size = partition_bytes.len() as u32;

        ErikPartitionRef { hash, size }
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((self.hash.as_slice().encode(), self.size.encode()))
    }
}

impl From<&ErikPartition> for ErikPartitionRef {
    fn from(partition: &ErikPartition) -> Self {
        let enc = ErikPartitionEncoder::from(partition);
        let bytes = enc.to_captured().into_bytes();
        ErikPartitionRef::new(&bytes)
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct ErikPartition {
    // version [0]
    // hashAlg SHA-256
    /// most recent this update among manifests
    pub partition_time: Time,

    /// We use an Arc around ManifestRef for cheaper cloning
    /// which we will likely need when we start parsing and
    /// updating structures that own a partition. Note that
    /// ManifestRef is immutable.
    pub manifest_refs: HashSet<Arc<ManifestRef>>,
}

impl ErikPartition {
    pub fn create_from_manifest_ref(mft: Arc<ManifestRef>) -> Self {
        let partition_time = mft.this_update;
        let mut manifest_refs = HashSet::new();
        manifest_refs.insert(mft);

        ErikPartition {
            partition_time,
            manifest_refs,
        }
    }

    pub fn add_manifest_ref(&mut self, mft_ref: Arc<ManifestRef>) {
        if self.partition_time > mft_ref.this_update {
            self.partition_time = mft_ref.this_update;
        }
        self.manifest_refs.insert(mft_ref);
    }
}

// - Decode
impl ErikPartition {
    /// Decodes an ErikPartition from a source.
    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

    /// Takes an ErikPartition from a constructed value
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        // Take the outer EncapsulatedContentInfo first
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;
            if oid != ERIK_PARTITION_OID {
                return Err(cons.content_err(format!(
                    "not an Erik index OID. Got: {}, expected: {}",
                    oid, ERIK_PARTITION_OID,
                )));
            }
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    let partition_time = Time::take_from(cons)?;
                    let hash_algorithm = cons.take_sequence(|cons| Oid::take_from(cons))?;
                    if hash_algorithm != oid::SHA256 {
                        return Err(cons.content_err("invalid digest algorithm"));
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
    pub partition_time: Time,
    pub manifest_refs: Captured,
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
    /// Encode, you may want to call to_captured
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            ERIK_PARTITION_OID.encode_ref(),
            encode::sequence_as(
                Tag::CTX_0,
                encode::sequence((
                    self.partition_time.encode_generalized_time(),
                    encode::sequence(oid::SHA256.encode()),
                    encode::sequence(&self.manifest_refs),
                )),
            ),
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
    pub hash: Hash,
    pub size: usize,
    pub aki: KeyIdentifier,
    pub manifest_number: Serial,
    pub this_update: Time,

    /// For now this is a single URI for the AD_SIGNED_OBJECT
    /// but we may get more access descriptors in future.
    pub locations: uri::Rsync,
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
            encode::sequence(encode::sequence((
                oid::AD_SIGNED_OBJECT.encode(),
                self.locations.encode_general_name(),
            ))),
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
            cons.take_sequence(|cons| {
                oid::AD_SIGNED_OBJECT.skip_if(cons)?;
                cons.take_value_if(Tag::CTX_6, |content| {
                    let uri_string = Ia5String::from_content(content)?;
                    uri::Rsync::from_bytes(uri_string.to_bytes()).map_err(|e| {
                        content.content_err(format!(
                            "invalid uri for manifest: {}, uri: {}",
                            e, uri_string
                        ))
                    })
                })
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErikSegmentIndex {
    #[serde(serialize_with = "ser_ia5_string", deserialize_with = "de_ia5_string")]
    pub segment_scope: Ia5String,
    pub segment_time: Time,
    pub segments: Vec<ErikSegmentRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErikSegmentRef {
    pub segment: Time,
    pub index: Hash,
}

impl ErikSegmentRef {
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            self.segment.encode_generalized_time(),
            self.index.as_slice().encode(),
        ))
    }
}

impl ErikSegmentIndex {
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            ERIK_SEGMENT_INDEX_OID.encode_ref(),
            encode::sequence_as(
                Tag::CTX_0,
                encode::sequence((
                    // version [0] default, not encoded
                    self.segment_scope.encode_ref(),
                    self.segment_time.encode_generalized_time(),
                    encode::sequence(oid::SHA256.encode()),
                    encode::sequence(encode::iter(self.segments.iter().map(|x| x.encode()))),
                )),
            ),
        ))
    }

    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;
            if oid != ERIK_SEGMENT_INDEX_OID {
                return Err(cons.content_err(format!(
                    "not an Erik segment index OID. Got: {}, expected: {}",
                    oid, ERIK_SEGMENT_INDEX_OID
                )));
            }

            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    // TODO: check version
                    let segment_scope = Ia5String::take_from(cons)?;
                    let segment_time = Time::take_from(cons)?;
                    let hashing_algorithm = cons.take_sequence(|cons| Oid::take_from(cons))?;
                    if hashing_algorithm != oid::SHA256 {
                        return Err(cons.content_err("invalid digest algorithm"));
                    }

                    let segments = cons.take_sequence(|cons| {
                        let mut segments = vec![];
                        while let Some(segment) =
                            cons.take_opt_constructed_if(Tag::SEQUENCE, |cons| {
                                let segment = Time::take_from(cons)?;
                                let hash_value = OctetString::take_from(cons)?;
                                let index = Hash::try_from(hash_value.into_bytes().as_ref())
                                    .map_err(|_| cons.content_err("invalid hash value"))?;
                                Ok(ErikSegmentRef { segment, index })
                            })?
                        {
                            segments.push(segment)
                        }
                        Ok(segments)
                    })?;
                    Ok(ErikSegmentIndex {
                        segment_scope,
                        segment_time,
                        segments,
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::content::RepoContent;

    use super::*;

    use ::base64::prelude::*;

    #[test]
    fn erik_partition_encode_and_decode() {
        let erik = test_index_from_content();
        let partition = erik.partitions.values().next().unwrap();
        let encoder = ErikPartitionEncoder::from(partition);
        let encoded = encoder.to_captured().into_bytes();
        let _base64 = BASE64_STANDARD.encode(encoded.as_ref());
        // println!("{base64}");

        let _decoded = ErikPartition::decode(encoded).unwrap();
    }

    #[test]
    fn erik_partition_decode_rfc_example() {
        let partition_der =
            include_bytes!("../../test-resources/erik-types/erik-partition-rfc.der");

        ErikPartition::decode(partition_der.as_ref()).unwrap();
    }

    #[test]
    fn erik_index_encode() {
        let erik = test_index_from_content();
        let encoder = ErikIndex::from(&erik);
        let encoded = encoder.encode().to_captured(Mode::Der).into_bytes();
        let _base64 = BASE64_STANDARD.encode(encoded.as_ref());
        // println!("{_base64}");

        let decoded = Mode::Der.decode(encoded, ErikIndex::take_from).unwrap();
        assert_eq!(encoder, decoded);
    }

    #[test]
    fn erik_index_decode_rfc_example() {
        let index_der = include_bytes!("../../test-resources/erik-types/erik-index-rfc.der");
        let index = ErikIndex::decode(index_der.as_ref()).unwrap();

        assert_eq!(256, index.partition_list.len());
        let encoded = index.encode().to_captured(Mode::Der).into_bytes();

        assert_eq!(Bytes::from(index_der.as_ref()), encoded);
        let _base64 = BASE64_STANDARD_NO_PAD.encode(encoded.as_ref());
        // println!("{_base64}");
    }

    #[test]
    fn erik_segment_index_support_rfc_example() {
        let sample_der =
            include_bytes!("../../test-resources/erik-types/erik-segment-index-rfc.der");
        let segment_index = ErikSegmentIndex::decode(sample_der.as_ref()).unwrap();
        let encoded = segment_index.encode().to_captured(Mode::Der).into_bytes();
        assert_eq!(Bytes::from(sample_der.as_ref()), encoded);
    }

    fn test_index_from_content() -> erik::state::ResolvedErikIndex {
        let repo_content = RepoContent::create_test().unwrap();
        erik::state::ResolvedErikIndex::from_content(
            "krill-ui-dev.do.nlnetlabs.nl".to_string(),
            &repo_content,
        )
        .unwrap()
    }
}
