//! This module is responsible for all fetching things from disk
//! or HTTPS, or mapping HTTPS requests to disk for testing.

use std::{collections::HashMap, path::PathBuf, time::Duration};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use reqwest::{StatusCode, blocking::Client, header};
use rpki::uri;
use structopt::clap::{crate_name, crate_version};

use crate::util;

pub const USER_AGENT: &str = concat!(crate_name!(), "/", crate_version!());

/// The FQDN host part of a URI, as used in the Erik protocol,
/// as well as in mapping content for FQDNs to local disk, e.g.
/// for testing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fqdn(String);

impl From<&uri::Https> for Fqdn {
    fn from(uri: &uri::Https) -> Self {
        Self(uri.authority().to_ascii_lowercase())
    }
}

/// Maps fetches for URIs to a ResolvedSource
///
/// Contains 0 or more DiskMappers that know how to map
/// matching URIs to a location on disk. If there is no
/// applicable mapper then the URI will be used as is.
#[derive(Clone, Debug)]
pub struct FetchMapper {
    disk_mappers: HashMap<Fqdn, PathBuf>,
}

impl FetchMapper {
    pub fn new() -> Self {
        FetchMapper {
            disk_mappers: HashMap::new(),
        }
    }

    pub fn add_disk_mapper(&mut self, fqdn: Fqdn, base_dir: PathBuf) {
        self.disk_mappers.insert(fqdn, base_dir);
    }

    pub fn resolve(&self, uri: uri::Https) -> ResolvedSource {
        let fqdn = Fqdn::from(&uri);

        match self.disk_mappers.get(&fqdn) {
            Some(base_path) => {
                let path = match uri.path().strip_prefix('/') {
                    Some(rel) => base_path.join(rel),
                    None => base_path.clone(),
                };

                ResolvedSource::File(path)
            }
            None => ResolvedSource::Uri(uri),
        }
    }
}

/// This is a resolved source for some requested URI, which can
/// either be remote, i.e. a Uri, or some local path on disk.
///
/// This type supports fetching the actual data for the source.
#[derive(Clone, Debug)]
pub enum ResolvedSource {
    File(PathBuf),
    Uri(uri::Https),
}

impl ResolvedSource {
    pub fn fetch(&self, etag: Option<&String>) -> anyhow::Result<FetchResponse> {
        match self {
            ResolvedSource::Uri(uri) => {
                let client = Client::builder()
                    .danger_accept_invalid_certs(true) // make this configurable
                    .danger_accept_invalid_hostnames(true)
                    .timeout(Duration::from_secs(60))
                    .build()?;

                let mut request_builder = client.get(uri.as_str());
                request_builder = request_builder.header(header::USER_AGENT, USER_AGENT);

                if let Some(etag) = etag {
                    request_builder = request_builder.header(header::IF_NONE_MATCH, etag);
                }

                let response = request_builder
                    .send()
                    .with_context(|| format!("Could not GET: {uri}"))?;

                match response.status() {
                    StatusCode::OK => {
                        let etag = match response.headers().get(header::ETAG) {
                            None => None,
                            Some(header_value) => Some(
                                header_value
                                    .to_str()
                                    .with_context(|| "invalid ETag in response header")?
                                    .to_owned(),
                            ),
                        };

                        let bytes = response.bytes().with_context(|| {
                            format!("Got no response from '{uri}' even though the status was OK")
                        })?;

                        Ok(FetchResponse::Data { bytes, etag })
                    }
                    StatusCode::NOT_MODIFIED => Ok(FetchResponse::UnModified),
                    _ => Err(anyhow!(
                        "Got unexpected HTTP response to GET for {}: {}",
                        uri,
                        response.status()
                    )),
                }
            }
            ResolvedSource::File(path) => {
                let bytes = util::read_file(path).with_context(|| {
                    format!(
                        "Failed to read source from path: '{}'",
                        path.to_string_lossy()
                    )
                })?;
                Ok(FetchResponse::Data { bytes, etag: None })
            }
        }
    }
}

/// Contains a response from a fetch
#[derive(Clone, Debug)]
pub enum FetchResponse {
    Data { bytes: Bytes, etag: Option<String> },
    UnModified,
}

impl FetchResponse {
    pub fn try_into_data(self) -> anyhow::Result<Bytes> {
        match self {
            FetchResponse::Data { bytes, .. } => Ok(bytes),
            _ => Err(anyhow!("No data in response.")),
        }
    }
}
