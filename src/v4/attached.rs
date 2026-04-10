use crate::{Error, Result, aes::IvAndCiphertext, icl_header_v4::V4DocumentHeader};
use bytes::{Buf, Bytes};
use protobuf::Message;

use super::{MAGIC, PRE_HEADER_LEN, V4};

fn get_v4_header_and_payload(mut b: Bytes) -> Result<(Bytes, IvAndCiphertext)> {
    let initial_len = b.len();
    if initial_len >= PRE_HEADER_LEN {
        let first_byte = b.get_u8();
        if first_byte == V4 {
            //Check to see if the next 4 bytes are the IRON ascii chars
            let maybe_magic = b.split_to(MAGIC.len());
            Some(maybe_magic)
                .filter(|bytes| bytes.as_ref() == MAGIC)
                .ok_or(Error::NoIronCoreMagic)?;
            //The following 2 bytes should be a u16 (big endian). This is the size of the PB header
            let header_size = b.get_u16().into();
            if b.len() >= header_size {
                //Break off the bytes after `header_size` and leave the header in `b`.
                let header = b.split_to(header_size);
                Ok((header, IvAndCiphertext(b)))
            } else {
                Err(Error::SpecifiedLengthTooLong(header_size as u32))
            }
        } else {
            Err(Error::InvalidVersion(first_byte))
        }
    } else {
        Err(Error::EdocTooShort(initial_len))
    }
}

/// Construct an IronCore attached EDOC from the constituent parts.
pub fn encode_attached_edoc(header: V4DocumentHeader, payload: IvAndCiphertext) -> Result<Bytes> {
    let encoded_header: Vec<u8> = header
        .write_to_bytes()
        .map_err(|e| Error::ProtoSerializationErr(e.to_string()))?;
    if encoded_header.len() > u16::MAX as usize {
        Err(Error::HeaderLengthOverflow(encoded_header.len() as u64))
    } else {
        let len = encoded_header.len() as u16;

        let result = [
            &[V4],
            &MAGIC[..],
            &len.to_be_bytes(),
            &encoded_header,
            &payload.0,
        ]
        .concat();
        Ok(result.into())
    }
}

/// Breaks apart an attached edoc into its parts.
pub fn decode_attached_edoc(b: Bytes) -> Result<(V4DocumentHeader, IvAndCiphertext)> {
    let (header_bytes, attached_document) = get_v4_header_and_payload(b)?;

    let pb = protobuf::Message::parse_from_bytes(&header_bytes[..])
        .map_err(|e| Error::HeaderParseErr(e.to_string()))?;
    Ok((pb, attached_document))
}

#[cfg(test)]
mod test {
    use crate::icl_header_v4::v4document_header::{
        EdekWrapper, SignedPayload,
        edek_wrapper::{Aes256GcmEncryptedDek, Edek},
    };

    use super::*;
    #[test]
    fn edoc_encode_decode_roundtrip() -> Result<()> {
        let header = V4DocumentHeader::default();
        let payload = IvAndCiphertext([42u8; 10].as_ref().into());

        // with payload
        let edoc = encode_attached_edoc(header.clone(), payload.clone())?;
        let (decoded_header, decoded_payload) = decode_attached_edoc(edoc)?;

        assert_eq!(&decoded_header, &header);
        assert_eq!(decoded_payload, payload);

        // No payload
        let edoc2 = encode_attached_edoc(header.clone(), IvAndCiphertext::default())?;
        let (decoded_header2, decoded_payload2) = decode_attached_edoc(edoc2)?;
        assert!(decoded_payload2.0.is_empty());
        assert_eq!(&decoded_header2, &header);
        Ok(())
    }

    #[test]
    fn edoc_encode_fail_headers_too_long() {
        let aes_edek = Aes256GcmEncryptedDek {
            //V4DocumentHeader_EdekWrapper_Aes256GcmEncryptedDek {
            ciphertext: [42u8; u16::MAX as usize + 1].as_ref().into(),
            ..Default::default()
        };

        let edek_wrapper = EdekWrapper {
            edek: Some(Edek::Aes256GcmEdek(aes_edek)),
            ..Default::default()
        };

        let signed_payload = SignedPayload {
            edeks: vec![edek_wrapper],
            ..Default::default()
        };

        let header = V4DocumentHeader {
            signed_payload: Some(signed_payload).into(),
            ..Default::default()
        };

        let result = encode_attached_edoc(header, IvAndCiphertext::default());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::HeaderLengthOverflow(_)
        ));
    }

    #[test]
    fn decode_bad_version() -> Result<()> {
        let header = V4DocumentHeader::default();
        let payload = IvAndCiphertext([42u8; 10].as_ref().into());

        let mut edoc = encode_attached_edoc(header, payload)?.to_vec();
        edoc[0] = 3;
        let result = decode_attached_edoc(edoc.into());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidVersion(3)));
        Ok(())
    }

    #[test]
    fn decode_too_short() {
        let result = decode_attached_edoc(vec![7u8].into());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::EdocTooShort(1)));
    }

    #[test]
    fn decode_bad_magic() -> Result<()> {
        let header = V4DocumentHeader::default();

        let mut edoc = encode_attached_edoc(header, IvAndCiphertext::default())?.to_vec();
        // bytes [1] to [4] should be IRON
        edoc[4] = b"M"[0];
        let result = decode_attached_edoc(edoc.into());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::NoIronCoreMagic));
        Ok(())
    }

    #[test]
    fn decode_bad_header_len() -> Result<()> {
        let header = V4DocumentHeader::default();

        let mut edoc = encode_attached_edoc(header, IvAndCiphertext::default())?.to_vec();
        // bytes [5] and [6] are a u16 saying how long the header is.
        // the data following must be at least as long as the header len
        let len = 1u16.to_be_bytes();
        assert_eq!(len.len(), 2);

        edoc[5] = len[0];
        edoc[6] = len[1];
        let result = decode_attached_edoc(edoc.into());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::SpecifiedLengthTooLong(_)
        ));
        Ok(())
    }
}
