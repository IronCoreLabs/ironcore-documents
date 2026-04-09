use bytes::Bytes;
use itertools::Itertools;
use protobuf::Message;

use crate::{Error, Result, vector_encryption_metadata::VectorEncryptionMetadata};
use std::fmt::Display;

// This file is for functions which are working with our key id header value.
// This value has the following structure:
// 4 Byte id. This value is a u32 encoded in big endian format.
// 1 Byte where the first 4 bits are used for which type of edek the id points to (Standalone, Saas Shield, DCP).
//   The next 4 bits are to denote which type of data follows it (vector metadata, IronCore Edoc, deterministic ciphertext)
// 1 Byte of 0

// EdekType numeric values. Note that in order to compare to these values you must bitmask
// off the bottom 4 bits of the byte first.
const SAAS_SHIELD_EDEK_TYPE_NUM: u8 = 0u8;
const STANDALONE_EDEK_TYPE_NUM: u8 = 128u8;
const DCP_EDEK_TYPE_NUM: u8 = 64u8;

// PayloadType numeric values.Note that in order to compare to these values you must bitmask
// off the top 4 bits of the byte first.
const DETERMINISTIC_PAYLOAD_TYPE_NUM: u8 = 0u8;
const VECTOR_METADATA_PAYLOAD_TYPE_NUM: u8 = 1u8;
const STANDARD_EDEK_PAYLOAD_TYPE_NUM: u8 = 2u8;

pub(crate) const KEY_ID_HEADER_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadType {
    DeterministicField,
    VectorMetadata,
    StandardEdek,
}

impl Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadType::DeterministicField => write!(f, "Deterministic Field"),
            PayloadType::VectorMetadata => write!(f, "Vector Metadata"),
            PayloadType::StandardEdek => write!(f, "Standard EDEK"),
        }
    }
}

impl PayloadType {
    pub(crate) fn to_numeric_value(self) -> u8 {
        match self {
            PayloadType::DeterministicField => DETERMINISTIC_PAYLOAD_TYPE_NUM,
            PayloadType::VectorMetadata => VECTOR_METADATA_PAYLOAD_TYPE_NUM,
            PayloadType::StandardEdek => STANDARD_EDEK_PAYLOAD_TYPE_NUM,
        }
    }

    pub(crate) fn from_numeric_value(candidate: &u8) -> Result<PayloadType> {
        let masked_candidate = candidate & 0x0F; // Mask off the top 4 bits.
        match masked_candidate {
            DETERMINISTIC_PAYLOAD_TYPE_NUM => Ok(PayloadType::DeterministicField),
            VECTOR_METADATA_PAYLOAD_TYPE_NUM => Ok(PayloadType::VectorMetadata),
            STANDARD_EDEK_PAYLOAD_TYPE_NUM => Ok(PayloadType::StandardEdek),
            _ => Err(Error::PayloadTypeError(format!(
                "Byte {masked_candidate} isn't a valid payload type."
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdekType {
    Standalone,
    SaasShield,
    DataControlPlatform,
}

impl Display for EdekType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdekType::Standalone => write!(f, "Standalone"),
            EdekType::SaasShield => write!(f, "SaaS Shield"),
            EdekType::DataControlPlatform => write!(f, "Data Control Platform"),
        }
    }
}

impl EdekType {
    pub(crate) fn to_numeric_value(self) -> u8 {
        match self {
            EdekType::SaasShield => SAAS_SHIELD_EDEK_TYPE_NUM,
            EdekType::Standalone => STANDALONE_EDEK_TYPE_NUM,
            EdekType::DataControlPlatform => DCP_EDEK_TYPE_NUM,
        }
    }

    pub(crate) fn from_numeric_value(candidate: &u8) -> Result<EdekType> {
        let masked_candidate = candidate & 0xF0; // Mask off the bottom 4 bits.
        match masked_candidate {
            SAAS_SHIELD_EDEK_TYPE_NUM => Ok(EdekType::SaasShield),
            STANDALONE_EDEK_TYPE_NUM => Ok(EdekType::Standalone),
            DCP_EDEK_TYPE_NUM => Ok(EdekType::DataControlPlatform),
            _ => Err(Error::EdekTypeError(format!(
                "Byte {masked_candidate} isn't a valid edek type."
            ))),
        }
    }
}

/// The key id header parsed into its pieces.
#[derive(Debug, PartialEq)]
pub struct KeyIdHeader {
    pub key_id: KeyId,
    pub edek_type: EdekType,
    pub payload_type: PayloadType,
}

impl KeyIdHeader {
    pub fn new(edek_type: EdekType, payload_type: PayloadType, key_id: KeyId) -> KeyIdHeader {
        KeyIdHeader {
            edek_type,
            payload_type,
            key_id,
        }
    }

    /// Write this header onto the front of the document.
    pub fn put_header_on_document<U: IntoIterator<Item = u8>>(&self, document: U) -> Bytes {
        self.write_to_bytes().into_iter().chain(document).collect()
    }

    /// Write the header to bytes. This is done by writing the key_id to be 4 bytes, putting the edek and payload types into
    /// the next byte and padding with a zero. See the comment at the top of this file for more information.
    pub fn write_to_bytes(&self) -> Bytes {
        let iter = u32::to_be_bytes(self.key_id.0).into_iter().chain([
            self.edek_type.to_numeric_value() | self.payload_type.to_numeric_value(),
            0u8,
        ]);
        Bytes::from_iter(iter)
    }

    /// This is not public because callers should use use decode_version_prefixed_value instead.
    pub(crate) fn parse_from_bytes(b: [u8; 6]) -> Result<KeyIdHeader> {
        let [one, two, three, four, five, six] = b;
        if six == 0u8 {
            let key_id = KeyId(u32::from_be_bytes([one, two, three, four]));
            let edek_type = EdekType::from_numeric_value(&five)?;
            let payload_type = PayloadType::from_numeric_value(&five)?;
            Ok(KeyIdHeader {
                edek_type,
                payload_type,
                key_id,
            })
        } else {
            Err(Error::KeyIdHeaderMalformed(format!(
                "The last byte of the header should be 0, but it was {six}"
            )))
        }
    }
}

/// Create the key_id_header and vector metadata. The first value is the key_id header and the
/// second is the vector metadata. These can be passed to encode_vector_metadata to create a single
/// byte string.
pub fn create_vector_metadata(
    key_id_header: KeyIdHeader,
    iv: Bytes,
    auth_hash: Bytes,
) -> (Bytes, VectorEncryptionMetadata) {
    let vector_encryption_metadata = VectorEncryptionMetadata {
        iv,
        auth_hash,
        ..Default::default()
    };
    (key_id_header.write_to_bytes(), vector_encryption_metadata)
}

/// Form the bytes that represent the vector metadata to the outside world.
/// This is the protobuf with the key_id_header put onto the front.
pub fn encode_vector_metadata(
    key_id_header_bytes: Bytes,
    vector_metadata: VectorEncryptionMetadata,
) -> Bytes {
    key_id_header_bytes
        .into_iter()
        .chain(
            vector_metadata
                .write_to_bytes()
                .expect("Writing to in memory bytes failed"),
        )
        .collect_vec()
        .into()
}

/// Decode a value which has the key_id_header put on the front by breaking it up.
/// This returns the key id, edek type and the remaining bytes.
pub fn decode_version_prefixed_value(mut value: Bytes) -> Result<(KeyIdHeader, Bytes)> {
    let value_len = value.len();
    if value_len >= KEY_ID_HEADER_LEN {
        let rest = value.split_off(KEY_ID_HEADER_LEN);
        match value[..] {
            [one, two, three, four, five, six] => {
                let key_id_header =
                    KeyIdHeader::parse_from_bytes([one, two, three, four, five, six])?;
                Ok((key_id_header, rest))
            }
            // This should not ever be able to happen since we sliced off 6 above
            _ => Err(Error::KeyIdHeaderTooShort(value_len)),
        }
    } else {
        Err(Error::KeyIdHeaderTooShort(value_len))
    }
}

/// Get the bytes that can be used for a prefix search of key_id headers.
pub fn get_prefix_bytes_for_search(key_id_header: KeyIdHeader) -> Bytes {
    key_id_header.write_to_bytes()
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_create_produces_saas_shield() {
        let iv_bytes: Bytes = (1..12).collect_vec().into();
        let auth_hash_bytes: Bytes = (1..16).collect_vec().into();
        let (header, result) = create_vector_metadata(
            KeyIdHeader::new(
                EdekType::SaasShield,
                PayloadType::DeterministicField,
                KeyId(72000),
            ),
            iv_bytes.clone(),
            auth_hash_bytes.clone(),
        );
        assert_eq!(
            header.to_vec(),
            vec![0, 1, 25, 64, SAAS_SHIELD_EDEK_TYPE_NUM, 0]
        );
        assert_eq!(result.iv, iv_bytes);
        assert_eq!(result.auth_hash, auth_hash_bytes);
    }

    #[test]
    fn test_create_produces_standalone() {
        let iv_bytes: Bytes = (1..12).collect_vec().into();
        let auth_hash_bytes: Bytes = (1..16).collect_vec().into();
        let (header, result) = create_vector_metadata(
            KeyIdHeader::new(
                EdekType::Standalone,
                PayloadType::DeterministicField,
                KeyId(72000),
            ),
            iv_bytes.clone(),
            auth_hash_bytes.clone(),
        );
        assert_eq!(
            header.to_vec(),
            vec![0, 1, 25, 64, STANDALONE_EDEK_TYPE_NUM, 0]
        );
        assert_eq!(result.iv, iv_bytes);
        assert_eq!(result.auth_hash, auth_hash_bytes);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let iv_bytes: Bytes = (1..12).collect_vec().into();
        let auth_hash_bytes: Bytes = (1..16).collect_vec().into();
        let key_id = KeyId(72000);
        let (header, result) = create_vector_metadata(
            KeyIdHeader::new(EdekType::Standalone, PayloadType::StandardEdek, key_id),
            iv_bytes.clone(),
            auth_hash_bytes.clone(),
        );

        let encode_result = encode_vector_metadata(header, result.clone());
        let (final_key_id_header, final_vector_bytes) =
            decode_version_prefixed_value(encode_result).unwrap();
        assert_eq!(final_key_id_header.key_id, key_id);
        assert_eq!(final_key_id_header.edek_type, EdekType::Standalone);
        assert_eq!(final_key_id_header.payload_type, PayloadType::StandardEdek);
        assert_eq!(final_vector_bytes, result.write_to_bytes().unwrap());
    }

    fn edek_type_roundtrip(e: EdekType) -> Result<EdekType> {
        EdekType::from_numeric_value(&e.to_numeric_value())
    }
    #[test]
    fn test_edek_type_to_and_from_roundtrip() {
        let all_types = [
            EdekType::Standalone,
            EdekType::SaasShield,
            EdekType::DataControlPlatform,
        ];

        // If you add to this match, add to the array above otherwise the test will pass but you won't be testing them all.
        for e in all_types {
            match e {
                EdekType::Standalone => edek_type_roundtrip(EdekType::Standalone),
                EdekType::SaasShield => edek_type_roundtrip(EdekType::SaasShield),
                EdekType::DataControlPlatform => edek_type_roundtrip(EdekType::DataControlPlatform),
            }
            .unwrap();
        }
    }

    fn payload_type_roundtrip(e: PayloadType) -> Result<PayloadType> {
        PayloadType::from_numeric_value(&e.to_numeric_value())
    }

    #[test]
    fn test_payload_type_to_and_from_roundtrip() {
        let all_types = [
            PayloadType::DeterministicField,
            PayloadType::VectorMetadata,
            PayloadType::StandardEdek,
        ];

        // If you add to this match, add to the array above otherwise the test will pass but you won't be testing them all.
        for e in all_types {
            match e {
                PayloadType::DeterministicField => {
                    payload_type_roundtrip(PayloadType::DeterministicField)
                }
                PayloadType::VectorMetadata => payload_type_roundtrip(PayloadType::VectorMetadata),
                PayloadType::StandardEdek => payload_type_roundtrip(PayloadType::StandardEdek),
            }
            .unwrap();
        }
    }
}
