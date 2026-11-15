use axum::body::Bytes;
use std::collections::HashMap;

use crate::{erik::asn1, fetch::retrieval::Fqdn};

pub trait Cache: Send + Sync + 'static {
    fn read_index(&self, fqdn: &Fqdn) -> Option<&asn1::ErikIndex>;
    fn write_index(&mut self, fqdn: &Fqdn, index: &asn1::ErikIndex);

    fn read_object(&self, hash: &asn1::Hash) -> Option<&Bytes>;
    fn write_object(&mut self, hash: &asn1::Hash, data: &Bytes);
}

pub struct InMemoryCache {
    indices: HashMap<Fqdn, asn1::ErikIndex>,
    objects: HashMap<asn1::Hash, Bytes>,
}

impl InMemoryCache {
    pub fn init() -> Self {
        InMemoryCache {
            indices: HashMap::new(),
            objects: HashMap::new(),
        }
    }
}

impl Cache for InMemoryCache {
    fn read_index(&self, fqdn: &Fqdn) -> Option<&asn1::ErikIndex> {
        self.indices.get(fqdn)
    }

    fn write_index(&mut self, fqdn: &Fqdn, index: &asn1::ErikIndex) {
        self.indices.insert(fqdn.clone(), index.clone());
    }

    fn read_object(&self, hash: &asn1::Hash) -> Option<&Bytes> {
        self.objects.get(hash)
    }

    fn write_object(&mut self, hash: &asn1::Hash, data: &Bytes) {
        self.objects.insert(hash.clone(), data.clone());
    }
}
