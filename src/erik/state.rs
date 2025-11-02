use std::collections::HashMap;

use rpki::repository::x509::Time;

use crate::content::RepoContent;
use crate::erik::asn1;

/// The Erik Partition key is used to determine
/// which partition should be used for a ManifestRef
///
/// DISCUSS: The draft says this should go up to 1024
/// but we only go up to 256 here, because it's just
/// much easier to take the first full byte from the
/// authority key identifier, rather than the first
/// 10 bits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ErikPartitionKey(u8);

impl From<&asn1::ManifestRef> for ErikPartitionKey {
    fn from(mft_ref: &asn1::ManifestRef) -> Self {
        Self(mft_ref.aki.as_slice()[0])
    }
}

/// ErikIndex as defined in section 3 of the draft
#[derive(Clone, Debug)]
pub struct ResolvedErikIndex {
    // version [0]
    pub index_scope: String, // FQDN, perhaps we should use a strong type
    pub index_time: Time,
    // hashAlg RSA-256
    pub partitions: HashMap<ErikPartitionKey, asn1::ErikPartition>,
}

impl ResolvedErikIndex {
    /// Creates and ErikIndex from the given content.
    pub fn from_content(index_scope: String, content: &RepoContent) -> Option<Self> {
        let mut partitions: HashMap<ErikPartitionKey, asn1::ErikPartition> = HashMap::new();

        for mft_ref in content.manifests().values() {
            let partition_key = ErikPartitionKey::from(mft_ref.as_ref());

            if let Some(partition) = partitions.get_mut(&partition_key) {
                partition.add_manifest_ref(mft_ref.clone());
            } else {
                partitions.insert(
                    partition_key,
                    asn1::ErikPartition::create_from_manifest_ref(mft_ref.clone()),
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

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use rpki::repository::Manifest;

    #[test]
    fn manifest_ref_from_manifest() {
        let manifest_der = include_bytes!("../../test-resources/erik-types/manifest.mft");
        let manifest_bytes = Bytes::from_static(manifest_der);
        let manifest = Manifest::decode(manifest_bytes.as_ref(), true).unwrap();

        let _manifest_ref = asn1::ManifestRef::try_from(&manifest).unwrap();
    }
}
