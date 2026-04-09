use bytes::{Buf, Bytes};
use protobuf::Message;

use crate::{Error, Result, aes::IvAndCiphertext, icl_header_v4::V4DocumentHeader};

use super::key_id_header::{self, KeyIdHeader};

#[derive(Debug, PartialEq)]
pub struct AttachedDocument {
    pub key_id_header: KeyIdHeader,
    pub edek: V4DocumentHeader,
    pub edoc: IvAndCiphertext,
}

impl TryFrom<Vec<u8>> for AttachedDocument {
    type Error = Error;

    /// Breaks apart an attached edoc into its parts.
    fn try_from(value: Vec<u8>) -> Result<Self> {
        Bytes::from(value).try_into()
    }
}

impl TryFrom<Bytes> for AttachedDocument {
    type Error = Error;

    /// Breaks apart an attached edoc into its parts.
    fn try_from(value: Bytes) -> Result<Self> {
        let (key_id_header, mut attached_document_with_header) =
            key_id_header::decode_version_prefixed_value(value)?;
        if attached_document_with_header.len() > 2 {
            let edek_len = attached_document_with_header.get_u16();
            if attached_document_with_header.len() > edek_len as usize {
                let header_bytes = attached_document_with_header.split_to(edek_len as usize);
                let edek = protobuf::Message::parse_from_bytes(&header_bytes[..])
                    .map_err(|e| Error::HeaderParseErr(e.to_string()))?;
                Ok(AttachedDocument {
                    key_id_header,
                    edek,
                    edoc: IvAndCiphertext(attached_document_with_header),
                })
            } else {
                Err(Error::HeaderParseErr(
                    "The EDEK you passed in was too short based on the length bytes.".to_string(),
                ))
            }
        } else {
            Err(Error::HeaderParseErr("Header is too short.".to_string()))
        }
    }
}

impl AttachedDocument {
    /// Write out the entire v5 attached documents to bytes.
    pub fn write_to_bytes(&self) -> Result<Bytes> {
        let AttachedDocument {
            key_id_header,
            edek,
            edoc,
        } = self;
        let key_id_header_bytes = key_id_header.write_to_bytes();
        let encoded_edek = edek.write_to_bytes().expect("Writing to bytes is safe");
        if encoded_edek.len() > u16::MAX as usize {
            Err(Error::HeaderLengthOverflow(encoded_edek.len() as u64))
        } else {
            let len = encoded_edek.len() as u16;

            let result = [
                key_id_header_bytes.as_ref(),
                &len.to_be_bytes(),
                &encoded_edek,
                &edoc.0, // Note that the edoc is written without the leading OIRON since it's an attached document.
            ]
            .concat();
            Ok(result.into())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Error,
        aes::IvAndCiphertext,
        icl_header_v4::{
            V4DocumentHeader,
            v4document_header::{
                EdekWrapper, SignedPayload,
                edek_wrapper::{Aes256GcmEncryptedDek, Edek},
            },
        },
        v5::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType},
    };

    use super::*;

    #[test]
    fn test_roundtrip() {
        let key_id_header = KeyIdHeader::new(
            EdekType::SaasShield,
            PayloadType::StandardEdek,
            KeyId(u32::MAX),
        );

        let edek_wrapper = EdekWrapper {
            edek: Some(Edek::Aes256GcmEdek(Aes256GcmEncryptedDek {
                ciphertext: [42u8; 255].as_ref().into(),
                ..Default::default()
            })),
            ..Default::default()
        };

        let edek = V4DocumentHeader {
            signed_payload: Some(SignedPayload {
                edeks: vec![edek_wrapper],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };

        let edoc = IvAndCiphertext(vec![100, 200, 0].into());
        let expected_result = AttachedDocument {
            key_id_header,
            edek,
            edoc,
        };
        let encoded = expected_result.write_to_bytes().unwrap();
        let result: AttachedDocument = encoded.try_into().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_len_too_long() {
        // The `0,255` after the `0` is the u16 representing length. It is too large.
        let encoded = vec![
            255u8, 255, 255, 255, 2, 0, 0, 255, 18, 7, 18, 5, 26, 3, 18, 1, 42, 100, 200,
        ];
        let result = AttachedDocument::try_from(encoded).unwrap_err();
        assert_eq!(
            result,
            Error::HeaderParseErr(
                "The EDEK you passed in was too short based on the length bytes.".to_string()
            )
        );
    }

    #[test]
    fn test_header_too_short() {
        // This value is just a key_id header with 1 0 after.
        let encoded = vec![255u8, 255, 255, 255, 2, 0, 0];
        let result = AttachedDocument::try_from(encoded).unwrap_err();
        assert_eq!(
            result,
            Error::HeaderParseErr("Header is too short.".to_string())
        );
    }
}
