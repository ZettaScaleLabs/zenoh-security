//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

//! Sample primitives
use crate::buffers::ZBuf;
use crate::prelude::ZenohId;
use crate::prelude::{KeyExpr, SampleKind, Value};
use crate::query::Reply;
use crate::time::{new_reception_timestamp, Timestamp};
#[zenoh_macros::unstable]
use serde::Serialize;
use std::convert::{TryFrom, TryInto};
use zenoh_protocol::core::Encoding;

pub type SourceSn = u64;

/// The locality of samples to be received by subscribers or targeted by publishers.
#[zenoh_macros::unstable]
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum Locality {
    SessionLocal,
    Remote,
    #[default]
    Any,
}
#[cfg(not(feature = "unstable"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Locality {
    SessionLocal,
    Remote,
    #[default]
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DataInfo {
    pub kind: SampleKind,
    pub encoding: Option<Encoding>,
    pub timestamp: Option<Timestamp>,
    pub source_id: Option<ZenohId>,
    pub source_sn: Option<SourceSn>,
}

/// Informations on the source of a zenoh [`Sample`].
#[zenoh_macros::unstable]
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// The [`ZenohId`] of the zenoh instance that published the concerned [`Sample`].
    pub source_id: Option<ZenohId>,
    /// The sequence number of the [`Sample`] from the source.
    pub source_sn: Option<SourceSn>,
}

#[test]
#[cfg(feature = "unstable")]
fn source_info_stack_size() {
    assert_eq!(std::mem::size_of::<SourceInfo>(), 16 * 2);
}

#[zenoh_macros::unstable]
impl SourceInfo {
    pub(crate) fn empty() -> Self {
        SourceInfo {
            source_id: None,
            source_sn: None,
        }
    }
}

#[zenoh_macros::unstable]
impl From<DataInfo> for SourceInfo {
    fn from(data_info: DataInfo) -> Self {
        SourceInfo {
            source_id: data_info.source_id,
            source_sn: data_info.source_sn,
        }
    }
}

#[zenoh_macros::unstable]
impl From<Option<DataInfo>> for SourceInfo {
    fn from(data_info: Option<DataInfo>) -> Self {
        match data_info {
            Some(data_info) => data_info.into(),
            None => SourceInfo::empty(),
        }
    }
}

mod attachments {
    #[zenoh_macros::unstable]
    use zenoh_buffers::{reader::HasReader, writer::HasWriter, ZBuf, ZBufReader, ZSlice};
    #[zenoh_macros::unstable]
    use zenoh_codec::{LCodec, RCodec, WCodec, Zenoh080};
    #[zenoh_macros::unstable]
    use zenoh_protocol::zenoh::ext::AttachmentType;

    #[zenoh_macros::unstable]
    #[derive(Clone)]
    pub struct Attachments {
        pub(crate) inner: ZBuf,
    }
    #[zenoh_macros::unstable]
    impl Default for Attachments {
        fn default() -> Self {
            Self::new()
        }
    }
    #[zenoh_macros::unstable]
    impl<const ID: u8> From<Attachments> for AttachmentType<ID> {
        fn from(this: Attachments) -> Self {
            AttachmentType { buffer: this.inner }
        }
    }
    #[zenoh_macros::unstable]
    impl<const ID: u8> From<AttachmentType<ID>> for Attachments {
        fn from(this: AttachmentType<ID>) -> Self {
            Attachments { inner: this.buffer }
        }
    }
    #[zenoh_macros::unstable]
    impl Attachments {
        pub fn new() -> Self {
            Self {
                inner: vec![0u8].into(),
            }
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
        pub fn len(&self) -> usize {
            Zenoh080.read(&mut self.inner.reader()).unwrap_or(0)
        }
        pub fn iter(&self) -> AttachmentsIterator {
            self.into_iter()
        }
        fn _get(&self, key: &[u8]) -> Option<ZSlice> {
            self.iter()
                .find_map(|(k, v)| (k.as_slice() == key).then_some(v))
        }
        pub fn get<Key: AsRef<[u8]>>(&self, key: &Key) -> Option<ZSlice> {
            self._get(key.as_ref())
        }
        fn _insert(&mut self, key: &[u8], value: &[u8]) {
            let codec = Zenoh080;
            let mut len = self.len();
            let prevlen = codec.w_len(len);
            len += 1;

            let mut writer = self.inner.writer();
            codec.write(&mut writer, key).unwrap(); // Infallible, barring alloc failure
            codec.write(&mut writer, value).unwrap(); // Infallible, barring alloc failure

            let mut buf = [0u8; 10];
            let buf = {
                let mut writer = buf.writer();
                codec.write(&mut writer, len).unwrap(); // Infallible
                let len = 10 - writer.len();
                &buf[..len]
            };

            self.inner.splice(..prevlen, buf);
        }
        pub fn insert<Key: AsRef<[u8]> + ?Sized, Value: AsRef<[u8]> + ?Sized>(
            &mut self,
            key: &Key,
            value: &Value,
        ) {
            self._insert(key.as_ref(), value.as_ref())
        }
    }
    #[zenoh_macros::unstable]
    pub struct AttachmentsIterator<'a> {
        reader: ZBufReader<'a>,
        remaining: usize,
    }
    #[zenoh_macros::unstable]
    impl<'a> core::iter::IntoIterator for &'a Attachments {
        type Item = (ZSlice, ZSlice);
        type IntoIter = AttachmentsIterator<'a>;
        fn into_iter(self) -> Self::IntoIter {
            let mut reader = self.inner.reader();
            match Zenoh080.read(&mut reader) {
                Ok(remaining) => AttachmentsIterator { reader, remaining },
                Err(_) => AttachmentsIterator {
                    reader,
                    remaining: 0,
                },
            }
        }
    }
    #[zenoh_macros::unstable]
    impl core::fmt::Debug for Attachments {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{{")?;
            for (key, value) in self {
                let key = key.as_slice();
                let value = value.as_slice();
                match core::str::from_utf8(key) {
                    Ok(key) => write!(f, "\"{key}\": ")?,
                    Err(_) => {
                        write!(f, "0x")?;
                        for byte in key {
                            write!(f, "{byte:02X}")?
                        }
                    }
                }
                match core::str::from_utf8(value) {
                    Ok(value) => write!(f, "\"{value}\", ")?,
                    Err(_) => {
                        write!(f, "0x")?;
                        for byte in value {
                            write!(f, "{byte:02X}")?
                        }
                        write!(f, ", ")?
                    }
                }
            }
            write!(f, "}}")
        }
    }
    #[zenoh_macros::unstable]
    impl<'a> core::iter::Iterator for AttachmentsIterator<'a> {
        type Item = (ZSlice, ZSlice);
        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }
            let Ok(key) = Zenoh080.read(&mut self.reader) else {
                self.remaining = 0;
                return None;
            };
            let Ok(value) = Zenoh080.read(&mut self.reader) else {
                self.remaining = 0;
                return None;
            };
            Some((key, value))
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.remaining, Some(self.remaining))
        }
    }
    #[zenoh_macros::unstable]
    impl core::iter::ExactSizeIterator for AttachmentsIterator<'_> {}
    #[zenoh_macros::unstable]
    impl<'a> core::iter::FromIterator<(&'a [u8], &'a [u8])> for Attachments {
        fn from_iter<T: IntoIterator<Item = (&'a [u8], &'a [u8])>>(iter: T) -> Self {
            let codec = Zenoh080;
            let mut buffer: Vec<u8> = Vec::new();
            buffer.push(0);
            let mut writer = buffer.writer();
            let mut n = 0usize;
            for (key, value) in iter {
                codec.write(&mut writer, key).unwrap(); // Infallible, barring allocation failures
                codec.write(&mut writer, value).unwrap(); // Infallible, barring allocation failures
                n += 1;
            }
            if n < 128 {
                buffer[0] = n as u8
            } else {
                let mut buf = [0u8; 10];
                let mut len = buf.writer();
                codec.write(&mut len, n).unwrap(); // Infallible
                let len = 10 - len.len();
                let buf = &buf[..len];
                buffer.splice(..1, buf.iter().copied());
            }
            Self {
                inner: buffer.into(),
            }
        }
    }
}
#[zenoh_macros::unstable]
pub use attachments::{Attachments, AttachmentsIterator};

/// A zenoh sample.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Sample {
    /// The key expression on which this Sample was published.
    pub key_expr: KeyExpr<'static>,
    /// The value of this Sample.
    pub value: Value,
    /// The kind of this Sample.
    pub kind: SampleKind,
    /// The [`Timestamp`] of this Sample.
    pub timestamp: Option<Timestamp>,

    #[cfg(feature = "unstable")]
    /// <div class="stab unstable">
    ///   <span class="emoji">🔬</span>
    ///   This API has been marked as unstable: it works as advertised, but we may change it in a future release.
    ///   To use it, you must enable zenoh's <code>unstable</code> feature flag.
    /// </div>
    ///
    /// Infos on the source of this Sample.
    pub source_info: SourceInfo,

    #[cfg(feature = "unstable")]
    /// <div class="stab unstable">
    ///   <span class="emoji">🔬</span>
    ///   This API has been marked as unstable: it works as advertised, but we may change it in a future release.
    ///   To use it, you must enable zenoh's <code>unstable</code> feature flag.
    /// </div>
    ///
    /// A map of key-value pairs, where each key and value are byte-slices.
    pub attachments: Option<Attachments>,
}

impl Sample {
    /// Creates a new Sample.
    #[inline]
    pub fn new<IntoKeyExpr, IntoValue>(key_expr: IntoKeyExpr, value: IntoValue) -> Self
    where
        IntoKeyExpr: Into<KeyExpr<'static>>,
        IntoValue: Into<Value>,
    {
        Sample {
            key_expr: key_expr.into(),
            value: value.into(),
            kind: SampleKind::default(),
            timestamp: None,
            #[cfg(feature = "unstable")]
            source_info: SourceInfo::empty(),
            #[cfg(feature = "unstable")]
            attachments: None,
        }
    }
    /// Creates a new Sample.
    #[inline]
    pub fn try_from<TryIntoKeyExpr, IntoValue>(
        key_expr: TryIntoKeyExpr,
        value: IntoValue,
    ) -> Result<Self, zenoh_result::Error>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'static>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'static>>>::Error: Into<zenoh_result::Error>,
        IntoValue: Into<Value>,
    {
        Ok(Sample {
            key_expr: key_expr.try_into().map_err(Into::into)?,
            value: value.into(),
            kind: SampleKind::default(),
            timestamp: None,
            #[cfg(feature = "unstable")]
            source_info: SourceInfo::empty(),
            #[cfg(feature = "unstable")]
            attachments: None,
        })
    }

    /// Creates a new Sample with optional data info.
    #[inline]
    pub(crate) fn with_info(
        key_expr: KeyExpr<'static>,
        payload: ZBuf,
        data_info: Option<DataInfo>,
    ) -> Self {
        let mut value: Value = payload.into();
        if let Some(data_info) = data_info {
            if let Some(encoding) = &data_info.encoding {
                value.encoding = encoding.clone();
            }
            Sample {
                key_expr,
                value,
                kind: data_info.kind,
                timestamp: data_info.timestamp,
                #[cfg(feature = "unstable")]
                source_info: data_info.into(),
                #[cfg(feature = "unstable")]
                attachments: None,
            }
        } else {
            Sample {
                key_expr,
                value,
                kind: SampleKind::default(),
                timestamp: None,
                #[cfg(feature = "unstable")]
                source_info: SourceInfo::empty(),
                #[cfg(feature = "unstable")]
                attachments: None,
            }
        }
    }

    /// Gets the timestamp of this Sample.
    #[inline]
    pub fn get_timestamp(&self) -> Option<&Timestamp> {
        self.timestamp.as_ref()
    }

    /// Sets the timestamp of this Sample.
    #[inline]
    pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Sets the source info of this Sample.
    #[zenoh_macros::unstable]
    #[inline]
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = source_info;
        self
    }

    #[inline]
    /// Ensure that an associated Timestamp is present in this Sample.
    /// If not, a new one is created with the current system time and 0x00 as id.
    /// Get the timestamp of this sample (either existing one or newly created)
    pub fn ensure_timestamp(&mut self) -> &Timestamp {
        if let Some(ref timestamp) = self.timestamp {
            timestamp
        } else {
            let timestamp = new_reception_timestamp();
            self.timestamp = Some(timestamp);
            self.timestamp.as_ref().unwrap()
        }
    }

    #[zenoh_macros::unstable]
    pub fn attachments(&self) -> Option<&Attachments> {
        self.attachments.as_ref()
    }

    #[zenoh_macros::unstable]
    pub fn attachments_mut(&mut self) -> &mut Option<Attachments> {
        &mut self.attachments
    }

    #[allow(clippy::result_large_err)]
    #[zenoh_macros::unstable]
    pub fn with_attachments(mut self, attachments: Attachments) -> Self {
        self.attachments = Some(attachments);
        self
    }
}

impl std::ops::Deref for Sample {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl std::ops::DerefMut for Sample {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl std::fmt::Display for Sample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SampleKind::Delete => write!(f, "{}({})", self.kind, self.key_expr),
            _ => write!(f, "{}({}: {})", self.kind, self.key_expr, self.value),
        }
    }
}

impl TryFrom<Reply> for Sample {
    type Error = Value;

    fn try_from(value: Reply) -> Result<Self, Self::Error> {
        value.sample
    }
}
