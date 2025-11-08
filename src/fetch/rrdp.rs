//! Fetch content from an RRDP source.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use rpki::{
    repository::Manifest,
    rrdp::{self, Hash, NotificationFile, Snapshot},
    uri,
};
use uuid::Uuid;

use crate::{
    erik::asn1::ManifestRef,
    fetch::retrieval::FetchMapper,
    util::{de_bytes, ser_bytes},
};

/// Gets content from an RRDP source. Fully trusts the
/// RRDP source to be complete and reliable with regards
/// to withdraws and updates.
///
/// Intended for use with a trusted local RRDP repository
/// as input.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct RrdpState {
    /// The RRDP notify URI and mapping.
    notify: uri::Https,

    /// The mapper that can be used to retrieve RRDP xml files.
    fetch_mapper: FetchMapper,

    /// The RRDP session of this snapshot.
    session_id: Uuid,

    /// The serial number of the update of this snapshot.
    serial: u64,

    /// All current elements
    elements: HashMap<Hash, Arc<RepoContentElement>>,

    /// All current manifest references. Derived and updated
    /// whenever the elements are updated.
    manifests: HashMap<Hash, Arc<ManifestRef>>,
}

impl RrdpState {
    /// Create a new state for the given RRDP notify URI
    /// and mapper. Will fetch and parse the notification
    /// file and then the snapshot file to create state.
    ///
    /// In case of trouble this errors out as one might
    /// expect.
    pub fn create(notify: uri::Https, fetch_mapper: FetchMapper) -> anyhow::Result<Self> {
        let notification = Self::get_notification_file(&notify, &fetch_mapper)?;
        let session_id = notification.session_id();
        let serial = notification.serial();

        let snapshot = Self::get_snapshot_file(notification.snapshot().uri(), &fetch_mapper)?;
        let elements = Self::elements_from_snapshot(snapshot);

        let manifests = Self::manifests_from_elements(&elements);

        Ok(Self {
            notify,
            fetch_mapper,
            session_id,
            serial,
            elements,
            manifests,
        })
    }

    fn get_notification_file(
        notify: &uri::Https,
        fetch_mapper: &FetchMapper,
    ) -> anyhow::Result<NotificationFile> {
        let notification_bytes = fetch_mapper
            .resolve(notify.clone())
            .fetch(None)?
            .try_into_data()?;

        NotificationFile::parse(notification_bytes.as_ref())
            .with_context(|| "Failed to parse notification file")
    }

    fn get_snapshot_file(
        snapshot_uri: &uri::Https,
        fetch_mapper: &FetchMapper,
    ) -> anyhow::Result<Snapshot> {
        let snapshot_bytes = fetch_mapper
            .resolve(snapshot_uri.clone())
            .fetch(None)?
            .try_into_data()?;

        Snapshot::parse(snapshot_bytes.as_ref()).with_context(|| "Failed to parse snapshot file")
    }

    fn elements_from_snapshot(snapshot: Snapshot) -> HashMap<Hash, Arc<RepoContentElement>> {
        snapshot
            .into_elements()
            .into_iter()
            .map(|el| {
                (
                    rrdp::Hash::from_data(el.data()),
                    Arc::new(RepoContentElement::from(el)),
                )
            })
            .collect()
    }

    fn manifests_from_elements(
        elements: &HashMap<Hash, Arc<RepoContentElement>>,
    ) -> HashMap<Hash, Arc<ManifestRef>> {
        elements
            .iter()
            .flat_map(|(hash, rce)| {
                rce.try_manifest_ref(true)
                    .ok()
                    .map(|mft_ref| (*hash, Arc::new(mft_ref)))
            })
            .collect()
    }
}

/// This type contains a current element in a repository
#[derive(Debug, Deserialize, Serialize)]
pub struct RepoContentElement {
    /// The full URI where the object was published.
    uri: rpki::uri::Rsync,

    /// The content of the object
    #[serde(serialize_with = "ser_bytes", deserialize_with = "de_bytes")]
    data: Bytes,
}

impl RepoContentElement {
    pub fn try_manifest_ref(&self, accept_stale: bool) -> anyhow::Result<ManifestRef> {
        if self.uri.ends_with(".mft") {
            let mft = Manifest::decode(self.data.as_ref(), false)?;
            let hash = Hash::from_data(self.data.as_ref());
            let size = self.data.len();
            let aki = mft
                .cert()
                .authority_key_identifier()
                .ok_or_else(|| anyhow!("manifest has no AKI?!?"))?;
            let manifest_number = mft.manifest_number();

            let this_update = mft.this_update();
            let location = self.uri.clone();

            if !accept_stale && mft.is_stale() {
                Err(anyhow!("manifest is stale"))
            } else {
                Ok(ManifestRef::new(
                    hash,
                    size,
                    aki,
                    manifest_number,
                    this_update,
                    location,
                ))
            }
        } else {
            Err(anyhow!("Not a manifest"))
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
    manifests: HashMap<Hash, Arc<ManifestRef>>,
}

impl RepoContent {
    /// To do: make this #[cfg[test]] when we have real content fetching in place
    pub fn create_test() -> anyhow::Result<Self> {
        let test_snapshot_file = include_bytes!(
            "../../test-resources/rrdp-rev2656/rrdp/e9be21e7-c537-4564-b742-64700978c6b4/2656/snapshot.xml"
        );
        let test_snapshot_bytes = Bytes::from_static(test_snapshot_file);

        let snapshot = Snapshot::parse(test_snapshot_bytes.as_ref()).unwrap();

        Self::create_from_snapshot(snapshot, true)
    }

    /// Create a full new RepoContent based on an RRDP snapshot.
    ///
    /// if use_test = true stale manifests are included
    fn create_from_snapshot(snapshot: Snapshot, accept_stale: bool) -> anyhow::Result<Self> {
        // Get all the publish elements from the snapshot
        let elements: HashMap<Hash, RepoContentElement> = snapshot
            .into_elements()
            .into_iter()
            .map(|e| (Hash::from_data(e.data()), e.into()))
            .collect();

        // Get all currently valid manifests from the elements
        // skip other objects, manifests that cannot be parsed
        // and expired manifests
        let manifests: HashMap<Hash, Arc<ManifestRef>> = elements
            .iter()
            .flat_map(|(h, p)| p.try_manifest_ref(accept_stale).map(|mft| (*h, mft.into())))
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
    pub fn manifests(&self) -> &HashMap<Hash, Arc<ManifestRef>> {
        &self.manifests
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::util::https;

    use super::*;

    #[test]
    fn create_rrdp_state() {
        let notification_uri = https("https://krill-ui-dev.do.nlnetlabs.nl/rrdp/notification.xml");
        let mut mapper = FetchMapper::new();
        mapper.add_disk_mapper(
            (&notification_uri).into(),
            PathBuf::from("test-resources/rrdp-rev2656/"),
        );

        let rrdp_state = RrdpState::create(notification_uri, mapper).unwrap();

        assert!(!rrdp_state.elements.is_empty());
        assert!(!rrdp_state.manifests.is_empty());
    }

    #[test]
    fn create_repo_content_from_snapshot() {
        let content = RepoContent::create_test().unwrap();
        assert!(!content.manifests.is_empty());
    }
}
