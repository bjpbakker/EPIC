use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::stream::{self, Stream};
use log::debug;
use rpki::{dep::bcder::encode::Values, repository::Manifest};
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::{erik::asn1, fetch::retrieval::Fqdn, server::cache::Cache};

fn der(data: Bytes) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream+der")],
        data,
    )
}

fn bad_hash(val: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, format!("invalid hash: {val}"))
}

fn not_found(kind: &str, resource: String) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("no such {kind}: {resource}"))
}

fn make_snapshot<C: Cache>(
    cache: RwLockReadGuard<C>,
    fqdn: &Fqdn,
) -> Option<impl Stream<Item = Result<Bytes, Infallible>> + Send + 'static> {
    if let Some(index) = cache.read_index(&fqdn) {
        let mut objects: Vec<Bytes> = vec![];
        // We have to loop through all the partitions and find all manifests, and then
        // find all objects on those manifests.If anything is missing or cannot be parsed,
        // which should never happen in practice, then it is simply skipped.
        //
        // This is okay, because the snapshot is a best effort collection of all current
        // objects.
        for partition_ref in index.partition_list() {
            if let Some(partition_bytes) = cache.read_object(&partition_ref.hash)
                && let Ok(partition) = asn1::ErikPartition::decode(partition_bytes.as_ref())
            {
                for mft_ref in &partition.manifest_refs {
                    if let Some(mft_bytes) = cache.read_object(&mft_ref.hash)
                        && let Ok(mft) = Manifest::decode(mft_bytes.as_ref(), false)
                    {
                        objects.push(mft_bytes.clone());
                        objects.extend(
                            mft.iter()
                                .filter_map(|f| asn1::Hash::try_from(f.hash().as_ref()).ok())
                                .filter_map(|hash| cache.read_object(&hash).cloned()),
                        );
                    }
                }
            }
        }

        Some(stream::iter(objects.into_iter().map(Ok)))
    } else {
        None
    }
}

/// HTTP handler that returns the snapshot for a given FQDN.
pub async fn get_snapshot<C: Cache>(
    State(cache): State<Arc<RwLock<C>>>,
    Path(fqdn): Path<String>,
) -> Response {
    debug!("GET Erik snapshot for {fqdn}");
    if let Ok(fqdn) = Fqdn::from_str(&fqdn) {
        // The read guard is dropped at the end of this statement, before the body is streamed to the client.
        if let Some(snapshot) = make_snapshot(cache.read().await, &fqdn) {
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream+der")],
                Body::from_stream(snapshot),
            )
                .into_response();
        }
    }
    not_found("snapshot", fqdn).into_response()
}

/// HTTP handler that returns the index for a given FQDN.
pub async fn get_index<C: Cache>(
    State(cache): State<Arc<RwLock<C>>>,
    Path(fqdn): Path<String>,
) -> Response {
    debug!("GET Erik index for {fqdn}");
    if let Ok(fqdn) = Fqdn::from_str(&fqdn) {
        let lock = cache.read().await;
        if let Some(index) = lock.read_index(&fqdn) {
            return der(index.encode().to_captured(asn1::Mode::Der).into_bytes()).into_response();
        }
    }
    not_found("index", fqdn).into_response()
}

/// HTTP handler that implements the Named Information [1] endpoint for any object in the EPIC server cache.
///
/// [1] - https://www.ietf.org/archive/id/draft-farrell-decade-ni-00.html
pub async fn get_ni_object<C: Cache>(
    State(cache): State<Arc<RwLock<C>>>,
    Path((alg, val)): Path<(String, String)>,
) -> Response {
    if alg != "sha-256" {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported hashing algorithm: {alg}"),
        )
            .into_response();
    }
    match URL_SAFE_NO_PAD.decode(val.as_bytes()) {
        Ok(h) if h.len() == 32 => {
            if let Ok(hash) = asn1::Hash::try_from(h.as_slice()) {
                debug!("GET NI: {hash}");
                let lock = cache.read().await;
                match lock.read_object(&hash) {
                    Some(obj) => der(obj.clone()).into_response(),
                    None => not_found("object", hash.to_string()).into_response(),
                }
            } else {
                bad_hash(val).into_response()
            }
        }
        _ => bad_hash(val).into_response(),
    }
}
