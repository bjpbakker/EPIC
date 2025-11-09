//! Fetch content from an RRDP source.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use rpki::{
    crypto::KeyIdentifier,
    repository::Manifest,
    rrdp::{self, Delta, Hash, NotificationFile, Snapshot},
    uri,
};
use uuid::Uuid;

use crate::{
    erik::asn1::ManifestRef,
    fetch::retrieval::{FetchMapper, FetchResponse},
    util::{de_bytes, ser_bytes},
};

type Etag = Option<String>;

enum NotificationFileResponse {
    UnModified,
    Notification {
        etag: Etag,
        notification_file: NotificationFile,
    },
}

impl NotificationFileResponse {
    fn try_into_etag_and_file(self) -> anyhow::Result<(Etag, NotificationFile)> {
        match self {
            NotificationFileResponse::UnModified => {
                Err(anyhow!("Notification file was unmodified"))
            }
            NotificationFileResponse::Notification {
                etag,
                notification_file,
            } => Ok((etag, notification_file)),
        }
    }
}

/// Gets content from an RRDP source. Fully trusts the
/// RRDP source to be complete and reliable with regards
/// to withdraws and updates.
///
/// Intended for use with a trusted local RRDP repository
/// as input.
///
/// IMPORTANT: If this is used with an untrusted RRDP repo
/// or a repo that is used by untrusted CAs then validation
/// of manifests MUST be done to prevent that anyone can
/// forge a manifest using some CA certificate's SKI as its
/// EE cert's AKI to poison the relay.
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

    /// Last seen ETag
    etag: Etag,

    /// All current elements
    elements: HashMap<Hash, Arc<RepoContentElement>>,

    /// All current manifest references. Derived and updated
    /// whenever the elements are updated.
    manifests: HashMap<KeyIdentifier, Arc<ManifestRef>>,
}

impl RrdpState {
    /// Create a new state for the given RRDP notify URI
    /// and mapper. Will fetch and parse the notification
    /// file and then the snapshot file to create state.
    ///
    /// In case of trouble this errors out as one might
    /// expect.
    pub fn create(notify: uri::Https, fetch_mapper: FetchMapper) -> anyhow::Result<Self> {
        let (etag, notification) =
            Self::get_notification_file(&notify, &None, &fetch_mapper)?.try_into_etag_and_file()?;

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
            etag,
            elements,
            manifests,
        })
    }

    /// Update.
    ///
    /// Returns:
    /// Err       in case of issues
    /// Ok(true)  in case there was an update
    /// Ok(false) in case there was no update
    pub fn update(&mut self) -> anyhow::Result<bool> {
        match Self::get_notification_file(&self.notify, &self.etag, &self.fetch_mapper)? {
            NotificationFileResponse::UnModified => Ok(false),
            NotificationFileResponse::Notification {
                etag,
                mut notification_file,
            } => {
                // Update the ETag. For now, we do this before updating
                //
                // pro -> this stops us from retrying notification files that reference
                //        broken delta(s) and a broken snapshot that we would fall back
                //        to in case deltas are incomplete or broken.
                //
                // con -> if notification file retrieval was ok, but we cannot
                //        fetch deltas, nor snapshot if we fall back. I.e. there
                //        was an issue with retrieval rather than the content, then
                //        this prevents us from retrying for the same notification
                //        file.
                //
                self.etag = etag;

                if self.session_id == notification_file.session_id()
                    && self.serial == notification_file.serial()
                {
                    // Nothing to do here. Likely ETags are not supported by the
                    // server (or we are mapping to disk) and we got a response,
                    // it's no different from what we have already.
                    return Ok(false);
                }

                if self.session_id != notification_file.session_id() {
                    // session changed, we will have to use the snapshot
                    self.update_from_snapshot(&notification_file)?
                } else {
                    // try delta, if if fails fall back to snapshot
                    if self.update_from_deltas(&mut notification_file).is_err() {
                        self.update_from_snapshot(&notification_file)?;
                    }
                }

                Ok(true)
            }
        }
    }

    fn update_from_deltas(
        &mut self,
        notification_file: &mut NotificationFile,
    ) -> anyhow::Result<()> {
        if !notification_file.sort_and_verify_deltas(None) {
            return Err(anyhow!("There is a gap in the deltas"));
        }

        let mut new_elements: HashMap<Hash, Arc<RepoContentElement>> = HashMap::new();
        for delta_ref in notification_file.deltas() {
            let delta = Self::get_delta_file(delta_ref.uri(), &self.fetch_mapper)?;

            // Sanity check the updates and withdraws as mismatches indicate
            // that we are out of sync and should do a full snapshot resync
            // instead.
            //
            // But other than that we do not remove any content here. We keep
            // old files (by hash) around. It is not yet implemented, but the
            // idea is to use the current set of manifests to determine which
            // objects are not longer referenced, and may be moved into some
            // cold(er) storage in case we need to save space or memory.
            for el in delta.into_elements() {
                match el {
                    rrdp::DeltaElement::Publish(publish_element) => {
                        let (uri, data) = publish_element.unpack();
                        let hash = Hash::from_data(data.as_ref());
                        let rce = Arc::new(RepoContentElement { uri, data });
                        new_elements.insert(hash, rce);
                    }
                    rrdp::DeltaElement::Update(update_element) => {
                        let (uri, hash, data) = update_element.unpack();
                        if !self.elements.contains_key(&hash) && !new_elements.contains_key(&hash) {
                            return Err(anyhow!("Deltas contain update for an unknown object"));
                        }
                        let rce = Arc::new(RepoContentElement { uri, data });
                        new_elements.insert(hash, rce);
                    }
                    rrdp::DeltaElement::Withdraw(withdraw_element) => {
                        let hash = withdraw_element.hash();
                        if !self.elements.contains_key(hash) && !new_elements.contains_key(hash) {
                            return Err(anyhow!("Deltas contain withdraw for an unknown object"));
                        }
                    }
                }
            }
        }
        let new_manifests = Self::manifests_from_elements(&new_elements);

        self.add_new_elements(new_elements);
        self.add_new_manifests(new_manifests);

        Ok(())
    }

    fn update_from_snapshot(&mut self, notification_file: &NotificationFile) -> anyhow::Result<()> {
        let snapshot =
            Self::get_snapshot_file(notification_file.snapshot().uri(), &self.fetch_mapper)?;

        self.serial = snapshot.serial();
        self.session_id = snapshot.session_id();

        let elements = Self::elements_from_snapshot(snapshot);
        let manifests = Self::manifests_from_elements(&elements);

        self.add_new_elements(elements);
        self.add_new_manifests(manifests);

        Ok(())
    }

    fn add_new_elements(&mut self, elements: HashMap<Hash, Arc<RepoContentElement>>) {
        for (hash, rce) in elements {
            // Insert the element if it's missing by way of
            // clippy's opinion of idiomatic Rust.
            self.elements.entry(hash).or_insert(rce);
        }
    }

    fn add_new_manifests(&mut self, manifests: HashMap<KeyIdentifier, Arc<ManifestRef>>) {
        for (aki, mft_ref) in manifests {
            if let Some(existing) = self.manifests.get(&aki) {
                if existing.manifest_number < mft_ref.manifest_number {
                    self.manifests.insert(aki, mft_ref);
                }
            } else {
                self.manifests.insert(aki, mft_ref);
            }
        }
    }

    fn get_notification_file(
        notify: &uri::Https,
        etag: &Etag,
        fetch_mapper: &FetchMapper,
    ) -> anyhow::Result<NotificationFileResponse> {
        match fetch_mapper.resolve(notify.clone()).fetch(etag.as_ref())? {
            FetchResponse::Data { bytes, etag } => {
                let notification_file = NotificationFile::parse(bytes.as_ref())
                    .with_context(|| "Failed to parse notification file")?;

                Ok(NotificationFileResponse::Notification {
                    notification_file,
                    etag,
                })
            }
            FetchResponse::UnModified => Ok(NotificationFileResponse::UnModified),
        }
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

    fn get_delta_file(delta_uri: &uri::Https, fetch_mapper: &FetchMapper) -> anyhow::Result<Delta> {
        let delta_bytes = fetch_mapper
            .resolve(delta_uri.clone())
            .fetch(None)?
            .try_into_data()?;

        Delta::parse(delta_bytes.as_ref()).with_context(|| "Failed to parse snapshot file")
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

    /// Gets the manifests from the given current set of elements.
    /// This assumes that there is only 1 manifest for an AKI, and
    /// performs NO validation that the Manifest EE cert is validly
    /// signed by a keypair that matches the AKI.
    fn manifests_from_elements(
        elements: &HashMap<Hash, Arc<RepoContentElement>>,
    ) -> HashMap<KeyIdentifier, Arc<ManifestRef>> {
        elements
            .values()
            .flat_map(|rce| {
                rce.try_manifest_ref(true)
                    .ok()
                    .map(|mft_ref| (mft_ref.aki, Arc::new(mft_ref)))
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
        let mut mapper = FetchMapper::empty();
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
