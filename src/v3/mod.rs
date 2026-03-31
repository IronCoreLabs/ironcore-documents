use crate::aes::IvAndCiphertext;
use crate::v4::MAGIC;
use crate::{
    Error,
    aes::{
        EncryptionKey, PlaintextDocument, aes_encrypt_with_iv, decrypt_document_with_attached_iv,
    },
    icl_header_v3::V3DocumentHeader,
    signing::AES_KEY_LEN,
};
use bytes::Bytes;
use protobuf::Message;

const IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

const V3: u8 = 3u8;

/// For external users to check the first bytes of an edoc.
pub const VERSION_AND_MAGIC: [u8; 5] = [V3, MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3]];

// [3, b"IRON]
const MAGIC_HEADER_LEN: usize = 5;
// 2 bytes indicate the length of the protobuf header
const HEADER_LEN_LEN: usize = 2;
const DETACHED_HEADER_LEN: usize = MAGIC_HEADER_LEN + HEADER_LEN_LEN;

/// These are detached encrypted bytes, which means they have a `3IRON` +
/// `<2 bytes of header length>` + `<proto V3DocumentHeader>` + IV + CIPHERTEXT.
/// Not created directly, use the TryFrom implementation instead.
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    v3_document_header: V3DocumentHeader,
    iv_and_ciphertext: IvAndCiphertext,
}

impl TryFrom<Vec<u8>> for EncryptedPayload {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let value_len = value.len();
        if value_len < DETACHED_HEADER_LEN {
            Err(Error::EdocTooShort(value_len))?
        };
        let (magic_header, header_len_and_rest) = value.split_at(MAGIC_HEADER_LEN);
        let (header_len_len, header_and_cipher) = header_len_and_rest.split_at(HEADER_LEN_LEN);
        if magic_header != [&[V3], &MAGIC[..]].concat() {
            Err(Error::NoIronCoreMagic)?
        };
        let header_len = u16::from_be_bytes(
            header_len_len
                .try_into()
                .expect("This is safe as we split off 2 bytes."),
        ) as usize;
        if header_and_cipher.len() < header_len {
            Err(Error::HeaderParseErr(format!(
                "Proto header length specified: {}, bytes remaining: {}",
                header_len,
                header_and_cipher.len()
            )))?
        };
        let (header, iv_and_cipher) = header_and_cipher.split_at(header_len);
        let v3_document_header: V3DocumentHeader =
            Message::parse_from_bytes(header).map_err(|_| {
                Error::HeaderParseErr("Unable to parse header as V3DocumentHeader".to_string())
            })?;
        Ok(EncryptedPayload {
            v3_document_header,
            iv_and_ciphertext: iv_and_cipher.to_vec().into(),
        })
    }
}

impl EncryptedPayload {
    /// Decrypt a V3 detached document and verify its signature.
    pub fn decrypt(self, key: &EncryptionKey) -> Result<PlaintextDocument, Error> {
        if verify_signature(key.0, &self.v3_document_header) {
            decrypt_document_with_attached_iv(key, &self.iv_and_ciphertext)
        } else {
            Err(Error::DecryptError(
                "Signature validation failed.".to_string(),
            ))
        }
    }
}

struct V3Signature {
    iv: [u8; IV_LEN],
    gcm_tag: [u8; GCM_TAG_LEN],
}

fn decompose_signature(sig: &Bytes) -> Option<V3Signature> {
    if sig.len() < IV_LEN + GCM_TAG_LEN {
        None
    } else {
        let (iv, _) = sig.split_at(IV_LEN);
        let (_, gcm_tag) = sig.split_at(sig.len() - GCM_TAG_LEN);
        Some(V3Signature {
            iv: iv.try_into().unwrap(),           // Length was validated up-front
            gcm_tag: gcm_tag.try_into().unwrap(), // Length was validated up-front
        })
    }
}

pub fn verify_signature(key: [u8; AES_KEY_LEN], v3_header: &V3DocumentHeader) -> bool {
    // If we have no header or authTag, that means this document was encrypted before the header was added, which would only happen if the
    // document was encrypted with the Java SDK. In that case, we'll just ignore the verification and try to decrypt, which might still work.
    if v3_header.header.is_none() || !v3_header.has_saas_shield() || v3_header.sig.is_empty() {
        true
    } else {
        let maybe_sig = decompose_signature(&v3_header.sig);
        match maybe_sig {
            Some(sig) => aes_encrypt_with_iv(
                crate::aes::EncryptionKey(key),
                &v3_header
                    .saas_shield()
                    .write_to_bytes()
                    .expect("Writing proto to bytes failed."),
                sig.iv,
                &[],
            )
            .map(|(_, new_sig)| {
                let new_sig_length = new_sig.0.len();
                let (_, new_gcm_tag) = new_sig.0.split_at(new_sig_length - GCM_TAG_LEN);
                new_gcm_tag == sig.gcm_tag
            })
            .unwrap_or(false),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use itertools::Itertools;

    #[test]
    fn verify_known_good_sig_in_v3_header() {
        // dek and proto_bytes copied from TSC-java test
        let dek: [u8; 32] = (0..32).collect_vec().try_into().unwrap();
        let proto_bytes = vec![
            10, 28, 49, 113, -17, 60, -119, -97, -121, 94, 89, 92, 34, 19, -54, -49, -110, -121,
            -57, -116, -15, -106, 69, -116, -42, -112, 84, 73, -128, -57, 26, 10, 10, 8, 116, 101,
            110, 97, 110, 116, 73, 100,
        ]
        .into_iter()
        .map(|x| x as u8)
        .collect_vec();
        let header = Message::parse_from_bytes(&proto_bytes).unwrap();
        assert!(verify_signature(dek, &header))
    }

    #[test]
    fn verify_known_bad_sig_in_v3_header() {
        // {
        //   "sig": [1, 2, 3],
        //   "saas_shield": {
        //     "tenant_id": "tenantId"
        //   }
        // }
        let proto_bytes = hex!("0a030102031a0a0a0874656e616e744964");
        let dek: [u8; 32] = (0..32).collect_vec().try_into().unwrap();
        let header = Message::parse_from_bytes(&proto_bytes).unwrap();
        assert!(!verify_signature(dek, &header));
    }

    #[test]
    fn verify_empty_v3_header() {
        let dek: [u8; 32] = (0..32).collect_vec().try_into().unwrap();
        let empty_header = V3DocumentHeader::new();
        assert!(verify_signature(dek, &empty_header))
    }

    #[test]
    fn verify_empty_sig_v3_header() {
        // {
        //   "sig": [],
        //   "saas_shield": {
        //     "tenant_id": "tenantId"
        //   }
        // }
        let proto_bytes = hex!("0a001a0a0a0874656e616e744964");
        let dek: [u8; 32] = (0..32).collect_vec().try_into().unwrap();
        let header = Message::parse_from_bytes(&proto_bytes).unwrap();
        assert!(verify_signature(dek, &header));
    }

    #[test]
    fn decompose_signature_works() {
        let sig_1 = (0..28).collect_vec();
        let decomposed_1 = decompose_signature(&sig_1.into()).unwrap();
        let expected_iv_1 = (0..12).collect_vec();
        let expected_tag_1 = (12..28).collect_vec();
        assert_eq!(&decomposed_1.iv[..], expected_iv_1);
        assert_eq!(&decomposed_1.gcm_tag[..], expected_tag_1);

        let sig_2 = (0..100).collect_vec();
        let decomposed_2 = decompose_signature(&sig_2.into()).unwrap();
        let expected_iv_2 = (0..12).collect_vec();
        let expected_tag_2 = (84..100).collect_vec();
        assert_eq!(&decomposed_2.iv[..], expected_iv_2);
        assert_eq!(&decomposed_2.gcm_tag[..], expected_tag_2);

        let sig_3 = (0..10).collect_vec();
        let decomposed_failure = decompose_signature(&sig_3.into());
        assert!(decomposed_failure.is_none());
    }

    #[test]
    fn encrypted_payload_too_short() {
        let document = vec![3, 73, 82, 79, 78, 0];
        let err = EncryptedPayload::try_from(document);
        assert!(matches!(err, Err(Error::EdocTooShort(_))))
    }

    #[test]
    fn encrypted_payload_invalid_header_len() {
        let document = vec![
            3, 73, 82, 79, 78, 0, 100, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        let err = EncryptedPayload::try_from(document);
        assert!(matches!(err, Err(Error::HeaderParseErr(_))))
    }

    #[test]
    fn encrypted_payload_no_magic() {
        let document = vec![1, 73, 82, 79, 78, 0, 12, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let err = EncryptedPayload::try_from(document);
        assert!(matches!(err, Err(Error::NoIronCoreMagic)))
    }

    #[test]
    fn form_good_encrypted_payload() {
        let document = vec![
            3, 73, 82, 79, 78, 0, 42, 10, 28, 20, 31, 98, 61, 23, 74, 221, 61, 102, 44, 153, 142,
            172, 70, 145, 180, 36, 193, 133, 249, 72, 1, 181, 31, 205, 205, 1, 197, 26, 10, 10, 8,
            116, 101, 110, 97, 110, 116, 73, 100, 49, 113, 239, 60, 137, 159, 135, 94, 89, 92, 34,
            19, 231, 165, 112, 184, 171, 237, 133, 20, 97, 193, 60, 0, 85, 139, 184, 144, 44, 184,
            129, 210, 203, 21, 167, 53, 17, 51, 49, 42, 92, 207, 102, 98, 174, 198, 128, 199, 19,
            42, 145, 251, 86, 201, 214, 33, 117, 232, 18, 93,
        ];
        let payload = EncryptedPayload::try_from(document);
        assert!(payload.is_ok());
    }

    #[test]
    fn decrypt_good_document() {
        let dek = EncryptionKey((0..32).collect_vec().try_into().unwrap());
        let document = vec![
            3, 73, 82, 79, 78, 0, 42, 10, 28, 20, 31, 98, 61, 23, 74, 221, 61, 102, 44, 153, 142,
            172, 70, 145, 180, 36, 193, 133, 249, 72, 1, 181, 31, 205, 205, 1, 197, 26, 10, 10, 8,
            116, 101, 110, 97, 110, 116, 73, 100, 49, 113, 239, 60, 137, 159, 135, 94, 89, 92, 34,
            19, 231, 165, 112, 184, 171, 237, 133, 20, 97, 193, 60, 0, 85, 139, 184, 144, 44, 184,
            129, 210, 203, 21, 167, 53, 17, 51, 49, 42, 92, 207, 102, 98, 174, 198, 128, 199, 19,
            42, 145, 251, 86, 201, 214, 33, 117, 232, 18, 93,
        ];
        let payload = EncryptedPayload::try_from(document).unwrap();
        let decrypted = payload.decrypt(&dek).unwrap();
        assert_eq!(decrypted.0, (0..32).collect_vec());
    }

    #[test]
    fn decrypt_bad_signature_document() {
        let dek = EncryptionKey((0..32).collect_vec().try_into().unwrap());
        let document = vec![
            3, 73, 82, 79, 78, 0, 42, 10, 28, 20, 32, 98, 61, 23, 74, 221, 61, 102, 44, 153, 142,
            172, 70, 145, 180, 36, 193, 133, 249, 72, 1, 181, 31, 205, 205, 1, 197, 26, 10, 10, 8,
            116, 101, 110, 97, 110, 116, 73, 100, 49, 113, 239, 60, 137, 159, 135, 94, 89, 92, 34,
            19, 231, 165, 112, 184, 171, 237, 133, 20, 97, 193, 60, 0, 85, 139, 184, 144, 44, 184,
            129, 210, 203, 21, 167, 53, 17, 51, 49, 42, 92, 207, 102, 98, 174, 198, 128, 199, 19,
            42, 145, 251, 86, 201, 214, 33, 117, 232, 18, 93,
        ];
        let payload = EncryptedPayload::try_from(document).unwrap();
        let err = payload.decrypt(&dek).unwrap_err();
        assert!(matches!(err, Error::DecryptError(_)));
    }
}
