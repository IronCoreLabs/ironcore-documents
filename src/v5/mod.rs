// Reexport the v4 aes, because we also use it for v5.
pub use crate::v4::aes;
pub mod attached;
pub mod key_id_header;
use crate::{
    Error, Result,
    aes::{EncryptionKey, IvAndCiphertext, PlaintextDocument, encrypt_and_attach_iv_with_prefix},
    icl_header_v4::V4DocumentHeader,
};
use bytes::{Buf, Bytes};
use key_id_header::KeyIdHeader;
use rand::CryptoRng;

// The V5 data format is defined by 2 data formats. One for the edek and one for encrypted data encrypted with that edek.
// The edek format is a 6 byte key id (see the key_id_header module) followed by a V4DocumentHeader proto.
// The edoc format is the EncryptedPayload below, which is 0 + IRON folowed by the encrypted data (iv, aes encrypted data and tag).
const MAGIC: &[u8; 4] = crate::v4::MAGIC;
pub(crate) const V0: u8 = 0u8;
/// For external users to check the first bytes of an edoc.
pub const VERSION_AND_MAGIC: [u8; 5] = [V0, MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3]];
/// This is 0 + IRON
pub(crate) const DETACHED_HEADER_LEN: usize = 5;

/// These are detached encrypted bytes, which means they have a `0IRON` + IV + CIPHERTEXT.
/// This value is correct by construction and will be validated when we create it.
/// There is no public constructor, only the TryFrom implementations.
#[derive(Debug, Clone)]
pub struct EncryptedPayload(PayloadBytes);

#[derive(Debug, Clone)]
enum PayloadBytes {
    /// Without the `0IRON` header.
    IvAndCiphertext(IvAndCiphertext),
    /// `0IRON` + IV + CIPHERTEXT.
    Encoded(Vec<u8>),
}

impl PartialEq for EncryptedPayload {
    fn eq(&self, other: &Self) -> bool {
        self.iv_and_ciphertext() == other.iv_and_ciphertext()
    }
}

impl Eq for EncryptedPayload {}

impl Default for EncryptedPayload {
    fn default() -> EncryptedPayload {
        IvAndCiphertext::default().into()
    }
}

impl TryFrom<Bytes> for EncryptedPayload {
    type Error = Error;

    fn try_from(mut value: Bytes) -> core::result::Result<Self, Self::Error> {
        if value.len() < DETACHED_HEADER_LEN {
            Err(Error::EdocTooShort(value.len()))
        } else if value.get_u8() == V0 {
            let maybe_magic = value.split_to(MAGIC.len());
            if maybe_magic.as_ref() == MAGIC {
                Ok(IvAndCiphertext(value).into())
            } else {
                Err(Error::NoIronCoreMagic)
            }
        } else {
            Err(Error::HeaderParseErr(
                "`0IRON` magic expected on the encrypted document.".to_string(),
            ))
        }
    }
}

impl TryFrom<Vec<u8>> for EncryptedPayload {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> core::result::Result<Self, Self::Error> {
        Bytes::from(value).try_into()
    }
}

impl From<IvAndCiphertext> for EncryptedPayload {
    fn from(value: IvAndCiphertext) -> Self {
        EncryptedPayload(PayloadBytes::IvAndCiphertext(value))
    }
}

impl EncryptedPayload {
    fn iv_and_ciphertext(&self) -> &[u8] {
        match &self.0 {
            PayloadBytes::IvAndCiphertext(iv_and_ciphertext) => iv_and_ciphertext.as_ref(),
            PayloadBytes::Encoded(encoded) => &encoded[DETACHED_HEADER_LEN..],
        }
    }

    /// Convert the encrypted payload to t
    pub fn to_aes_value_with_attached_iv(self) -> IvAndCiphertext {
        match self.0 {
            PayloadBytes::IvAndCiphertext(iv_and_ciphertext) => iv_and_ciphertext,
            PayloadBytes::Encoded(encoded) => {
                IvAndCiphertext(Bytes::from(encoded).slice(DETACHED_HEADER_LEN..))
            }
        }
    }

    /// Decrypt a V5 detached document. The document should have the expected header
    pub fn decrypt(self, key: &EncryptionKey) -> Result<PlaintextDocument> {
        crate::aes::decrypt_document_with_attached_iv(key, &self.to_aes_value_with_attached_iv())
    }

    pub fn write_to_bytes(&self) -> Vec<u8> {
        match &self.0 {
            PayloadBytes::IvAndCiphertext(iv_and_ciphertext) => {
                let mut result = Vec::with_capacity(iv_and_ciphertext.len() + DETACHED_HEADER_LEN);
                result.push(V0);
                result.extend_from_slice(MAGIC);
                result.extend_from_slice(iv_and_ciphertext.as_ref());
                result
            }
            PayloadBytes::Encoded(encoded) => encoded.clone(),
        }
    }

    /// The same bytes as [`EncryptedPayload::write_to_bytes`]. Payloads returned by [`encrypt_detached_document`]
    /// are returned without copying.
    pub fn into_bytes(self) -> Vec<u8> {
        match self.0 {
            PayloadBytes::Encoded(encoded) => encoded,
            PayloadBytes::IvAndCiphertext(_) => self.write_to_bytes(),
        }
    }
}

/// Encrypt a document to be used as a detached document. This means it will have a header of `0IRON` as the first
/// 5 bytes.
pub fn encrypt_detached_document<R: CryptoRng>(
    rng: &mut R,
    key: EncryptionKey,
    document: PlaintextDocument,
) -> Result<EncryptedPayload> {
    encrypt_and_attach_iv_with_prefix(rng, key, &VERSION_AND_MAGIC, &document.0)
        .map(|encoded| EncryptedPayload(PayloadBytes::Encoded(encoded)))
}

pub fn parse_standard_edek(edek_bytes: Bytes) -> Result<(KeyIdHeader, V4DocumentHeader)> {
    let (key_id_header, proto_bytes) = key_id_header::decode_version_prefixed_value(edek_bytes)?;
    let pb = protobuf::Message::parse_from_bytes(&proto_bytes[..])
        .map_err(|e| Error::HeaderParseErr(e.to_string()))?;
    Ok((key_id_header, pb))
}

pub fn parse_standard_edoc(edoc: Bytes) -> Result<IvAndCiphertext> {
    let encrypted_payload: EncryptedPayload = edoc.try_into()?;
    Ok(encrypted_payload.to_aes_value_with_attached_iv())
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    #[test]
    fn encrypt_decrypt_detached_document_roundtrips() {
        let mut rng = ChaCha20Rng::seed_from_u64(172u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = PlaintextDocument(vec![100u8, 200u8]);
        let encrypted = encrypt_detached_document(&mut rng, key, plaintext.clone()).unwrap();
        let result = encrypted.decrypt(&key).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn detached_document_matches_known_bytes() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = PlaintextDocument((0u8..37).collect());
        let expected = hex!(
            "0049524f4efa51152873435062df7e6003f9bdae6a308e34ee00b9ad0c7ba23c5492184b8041a5b4aa18d4297e9685bb98a9b65c1d682ed9fad80231a99b2b6148643ed5493b"
        );
        let encrypted = encrypt_detached_document(
            &mut ChaCha20Rng::seed_from_u64(172u64),
            key,
            plaintext.clone(),
        )
        .unwrap();
        assert_eq!(encrypted.write_to_bytes(), expected);
        assert_eq!(encrypted.clone().into_bytes(), expected);
        assert_eq!(
            encrypted.clone().to_aes_value_with_attached_iv().as_ref(),
            &expected[DETACHED_HEADER_LEN..]
        );
        assert_eq!(encrypted.clone().decrypt(&key).unwrap(), plaintext);

        let from_attached_iv = EncryptedPayload::from(
            crate::aes::encrypt_document_and_attach_iv(
                &mut ChaCha20Rng::seed_from_u64(172u64),
                key,
                plaintext.clone(),
            )
            .unwrap(),
        );
        assert_eq!(from_attached_iv.write_to_bytes(), expected);
        assert_eq!(from_attached_iv.clone().into_bytes(), expected);

        let parsed = EncryptedPayload::try_from(expected.to_vec()).unwrap();
        assert_eq!(parsed, encrypted);
        assert_eq!(parsed, from_attached_iv);
        assert_eq!(parsed.decrypt(&key).unwrap(), plaintext);
    }

    #[test]
    fn creation_fails_too_short() {
        let encrypted_payload_or_error: Result<EncryptedPayload> =
            hex!("00495241").to_vec().try_into();

        let result = encrypted_payload_or_error.unwrap_err();
        assert_eq!(result, Error::EdocTooShort(4));
    }

    #[test]
    fn creation_fails_wrong_bytes() {
        // Wrong first byte.
        let encrypted_payload_or_error: Result<EncryptedPayload> =
            hex!("0149524f4efa5111111111").to_vec().try_into();
        let result = encrypted_payload_or_error.unwrap_err();
        assert_eq!(
            result,
            Error::HeaderParseErr("`0IRON` magic expected on the encrypted document.".to_string())
        );

        // right first byte, but IRON magic wrong.
        let encrypted_payload_or_error: Result<EncryptedPayload> =
            hex!("0000524f4efa5111111111").to_vec().try_into();
        let result = encrypted_payload_or_error.unwrap_err();
        assert_eq!(result, Error::NoIronCoreMagic);
    }
}
