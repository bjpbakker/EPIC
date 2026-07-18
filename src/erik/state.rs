use std::collections::HashMap;

use rpki::repository::x509::Time;

use crate::content::RepoContent;
use crate::erik::asn1;

/// This key determines which partition is used for a ManifestRef.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ErikPartitionKey(u8);

impl From<&asn1::ManifestRef> for ErikPartitionKey {
    fn from(mft_ref: &asn1::ManifestRef) -> Self {
        // The strategy implemented here is to use the first byte of the AKI.
        // This has the advantage that an updated manifest for a given CA
        // certificate will end up in the same partition as the previous
        // manifest. In other words, it would result in updating one partition
        // only, rather than two.
        //
        // Note that the KeyIdentifier is guaranteed to be 20 bytes long,
        // so taking the first byte can never panic.
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
    pub fn resolve<'a, I>(scope: String, content: I) -> Option<Self>
    where
        I: std::iter::Iterator<Item = &'a std::sync::Arc<asn1::ManifestRef>>,
    {
        let mut partitions: HashMap<ErikPartitionKey, asn1::ErikPartition> = HashMap::new();

        for mft_ref in content {
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
                index_scope: scope,
                index_time: max_partition_time,
                partitions,
            })
    }

    /// Creates and ErikIndex from the given content.
    pub fn from_content(index_scope: String, content: &RepoContent) -> Option<Self> {
        Self::resolve(index_scope, content.manifests().values())
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
