//! Parse streams of RPKI objects for snapshots and segments

use bytes::Bytes;
use rpki::{
    dep::bcder::{
        Captured, Mode,
        decode::{self, DecodeError, IntoSource, Source},
    },
    repository::{Cert, Crl, Manifest, Roa, aspa::Aspa},
};

/// Represents a list of objects.
#[derive(Debug)]
pub struct ObjectStream(Vec<Captured>);

impl ObjectStream {
    pub fn decode<S: IntoSource>(
        source: S,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut objects = vec![];

        while let Ok(captured) = cons.capture_one() {
            objects.push(captured);
        }
        Ok(ObjectStream(objects))
    }

    pub fn into_captured(self) -> Vec<Captured> {
        self.0
    }

    pub fn into_repository_objects(self) -> Vec<RepositoryObject> {
        self.0.into_iter().map(Into::into).collect()
    }
}

#[derive(Debug)]
pub enum RepositoryObject {
    Manifest(Manifest),
    Crl(Crl),
    Certificate(Cert),
    Roa(Roa),
    Aspa(Aspa),
    Unknown(Bytes),
}

impl RepositoryObject {
    pub fn to_bytes(&self) -> Bytes {
        match self {
            RepositoryObject::Manifest(manifest) => manifest.to_captured().into_bytes(),
            RepositoryObject::Crl(crl) => crl.to_captured().into_bytes(),
            RepositoryObject::Certificate(cert) => cert.to_captured().into_bytes(),
            RepositoryObject::Roa(roa) => roa.to_captured().into_bytes(),
            RepositoryObject::Aspa(aspa) => aspa.to_captured().into_bytes(),
            RepositoryObject::Unknown(bytes) => bytes.clone(),
        }
    }
}

impl From<Captured> for RepositoryObject {
    fn from(captured: Captured) -> Self {
        if let Ok(mft) = Manifest::decode(captured.as_ref(), false) {
            RepositoryObject::Manifest(mft)
        } else if let Ok(crl) = Crl::decode(captured.as_ref()) {
            RepositoryObject::Crl(crl)
        } else if let Ok(cert) = Cert::decode(captured.as_ref()) {
            RepositoryObject::Certificate(cert)
        } else if let Ok(roa) = Roa::decode(captured.as_ref(), false) {
            RepositoryObject::Roa(roa)
        } else if let Ok(aspa) = Aspa::decode(captured.as_ref(), false) {
            RepositoryObject::Aspa(aspa)
        } else {
            RepositoryObject::Unknown(captured.into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn parse_segment() {
        let sample_segment = include_bytes!("../../test-resources/object-stream/segment.bytes");
        let objects = ObjectStream::decode(sample_segment.as_ref())
            .unwrap()
            .into_captured();

        let mut object_bytes_mut = BytesMut::new();
        for object in objects {
            object_bytes_mut.extend_from_slice(object.as_ref());
        }
        let object_bytes = object_bytes_mut.freeze();

        assert_eq!(sample_segment, object_bytes.as_ref());
    }
}
