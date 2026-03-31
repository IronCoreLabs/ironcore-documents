// This file contains things related to the V4 AES edek, which is defined in the icl_v4_header.proto.

use crate::{
    Error,
    aes::{self, EncryptionKey, aes_decrypt_core, aes_encrypt},
    icl_header_v4::{
        self, V4DocumentHeader,
        v4document_header::{
            SignatureInformation, SignedPayload, signature_information::SignatureType,
        },
    },
    signing,
};
use bytes::Bytes;
use protobuf::Message;
use rand::CryptoRng;

type Result<T> = core::result::Result<T, crate::Error>;

/// If `maybe_dek` is None, generate a dek, otherwise use the one provided.
/// Encrypt the dek using the kek to make an aes edek. The provided id will be put into the Aes256GcmEncryptedDek.
/// Returns the dek and Aes256GcmEncryptedDek.
fn generate_aes_edek<R: CryptoRng>(
    rng: &mut R,
    kek: EncryptionKey,
    maybe_dek: Option<EncryptionKey>,
    id: &str,
) -> Result<(
    EncryptionKey,
    icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek,
)> {
    let dek = maybe_dek.unwrap_or_else(|| {
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        EncryptionKey(buffer)
    });
    let (iv, edek) = aes_encrypt(kek, &dek.0, &[], rng)?;
    let aes_edek = icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek {
        ciphertext: edek.0.into(),
        iv: Bytes::copy_from_slice(&iv),
        id: id.into(),
        ..Default::default()
    };
    Ok((dek, aes_edek))
}

/// Sign the payload using the key.
fn sign_header(key: aes::EncryptionKey, header_payload: &SignedPayload) -> SignatureInformation {
    //This unwrap can't actually ever happen because they create the coded stream with exactly the computed size before
    //serializing.
    let bytes = header_payload
        .write_to_bytes()
        .expect("Writing proto to bytes failed.");
    let signature = signing::sign_hs256(key.0, &bytes);

    SignatureInformation {
        signature: signature.0.to_vec().into(),
        signature_type: SignatureType::HS256.into(),
        ..Default::default()
    }
}

/// Creates a signed proto wrapper with a single edek wrapper in it using the signing key to do the signing.
pub fn create_signed_proto(
    edek_wrappers: Vec<icl_header_v4::v4document_header::EdekWrapper>,
    signing_key: aes::EncryptionKey,
) -> V4DocumentHeader {
    let signed_payload = icl_header_v4::v4document_header::SignedPayload {
        edeks: edek_wrappers,
        ..Default::default()
    };
    let signature_info = sign_header(signing_key, &signed_payload);
    icl_header_v4::V4DocumentHeader {
        signed_payload: Some(signed_payload).into(),
        signature_info: Some(signature_info).into(),
        ..Default::default()
    }
}

/// If `maybe_dek` is None, generate a dek, otherwise use the one provided.
/// Encrypt the dek using the kek to make an aes edek. The provided id will be put into the Aes256GcmEdek.
/// The edek will be placed into a V4DocumentHeader and the signature will be computed.
/// The aes dek is the key used to compute the signature.
pub fn generate_aes_edek_and_sign<R: CryptoRng>(
    rng: &mut R,
    kek: EncryptionKey,
    maybe_dek: Option<EncryptionKey>,
    id: &str,
) -> Result<(EncryptionKey, icl_header_v4::V4DocumentHeader)> {
    let (aes_dek, aes_edek) = generate_aes_edek(rng, kek, maybe_dek, id)?;
    Ok((
        aes_dek,
        create_signed_proto(
            vec![icl_header_v4::v4document_header::EdekWrapper {
                edek: Some(
                    icl_header_v4::v4document_header::edek_wrapper::Edek::Aes256GcmEdek(aes_edek),
                ),
                ..Default::default()
            }],
            aes_dek,
        ),
    ))
}

/// Decrypt the aes edek. Does not verify signature of the header or check that the id is appropriate.
/// You must do that as a separate step.
pub fn decrypt_aes_edek(
    kek: &EncryptionKey,
    aes_edek: &icl_header_v4::v4document_header::edek_wrapper::Aes256GcmEncryptedDek,
) -> Result<EncryptionKey> {
    let iv = aes_edek.iv.as_ref().try_into().map_err(|_| {
        Error::DecryptError("IV from the edek was not the correct length.".to_string())
    })?;
    aes_decrypt_core(kek, iv, &aes_edek.ciphertext, &[])
        .and_then(|dek_bytes| {
            dek_bytes.try_into().map_err(|_| {
                Error::DecryptError("Decrypted AES DEK was not of the correct size".to_string())
            })
        })
        .map(EncryptionKey)
}

/// Verify the signature inside the V4 header
pub fn verify_signature(key: aes::EncryptionKey, header: &V4DocumentHeader) -> bool {
    match header.signature_info.signature_type.enum_value() {
        Ok(SignatureType::NONE) => true,
        Ok(SignatureType::HS256) => {
            if let Ok(signature_bytes) = header.signature_info.signature.to_vec().try_into() {
                signing::verify_hs256(
                    key.0,
                    //This unwrap can't actually ever happen because they create the coded stream with exactly the computed size before
                    //serializing.
                    &header
                        .signed_payload
                        .write_to_bytes()
                        .expect("Writing proto to bytes failed."),
                    &signing::Signature(signature_bytes),
                )
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        icl_header_v4::v4document_header::{
            EdekWrapper,
            edek_wrapper::{Aes256GcmEncryptedDek, Edek},
        },
        signing::AES_KEY_LEN,
    };
    use hex_literal::hex;
    use protobuf::Message;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    #[test]
    fn generate_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "aabbccddeefaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, aes_edek) =
            generate_aes_edek(&mut rng, kek, None, id).unwrap();
        let result = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(result, aes_dek);
    }

    #[test]
    fn signed_aes_edek_verifies_and_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, v4_document) =
            generate_aes_edek_and_sign(&mut rng, kek, None, id).unwrap();
        let aes_edek =
            v4_document.signed_payload.0.clone().unwrap().edeks[0].take_aes_256_gcm_edek();
        let decrypted_aes_dek = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(decrypted_aes_dek, aes_dek);
        let verify_result = verify_signature(decrypted_aes_dek, &v4_document);
        assert!(verify_result)
    }

    #[test]
    fn signed_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, v4_document) =
            generate_aes_edek_and_sign(&mut rng, kek, None, id).unwrap();
        let aes_edek = v4_document.signed_payload.0.unwrap().edeks[0].take_aes_256_gcm_edek();
        let result = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(result, aes_dek);
    }

    #[test]
    fn bad_signature_still_decrypts() {
        let proto_bytes = hex!(
            "0a240a200049fac03b443a5f9d22dae5de3e45d23b2e5705db0843ead925118c59b171d11001124b12491a470a0cde60918359674bd7dc64756512304f4fdd03877ebe65decd71b57ea1cbb070b3fa4c9d29482dbd29a9112165e888e7a8d116be1c4d5e2162a0bb7fe9b03e1a0568656c6c6f"
        );
        let v4_document: icl_header_v4::V4DocumentHeader =
            Message::parse_from_bytes(&proto_bytes).unwrap();
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let aes_edek =
            v4_document.signed_payload.0.clone().unwrap().edeks[0].take_aes_256_gcm_edek();
        assert_eq!(aes_edek.id.to_string().as_str(), id);
        let decrypted_aes_dek = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        let verify_result = verify_signature(decrypted_aes_dek, &v4_document);
        // Verify fails because I messed the signature up in the proto_bytes
        assert!(!verify_result)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let dek = EncryptionKey([100u8; AES_KEY_LEN]);
        let aes_edek = Aes256GcmEncryptedDek {
            ciphertext: [42u8; 1024].as_ref().into(),
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

        let mut header = V4DocumentHeader {
            signed_payload: Some(signed_payload).into(),
            ..Default::default()
        };

        let sign_result = sign_header(dek, &header.signed_payload);

        header.signature_info = Some(sign_result).into();
        assert!(verify_signature(dek, &header));
    }

    #[test]
    fn verify_known_good_sig_in_v4_header() {
        let dek = EncryptionKey([100u8; AES_KEY_LEN]);
        let bytes = hex_literal::hex!(
            "0a240a2082e7f2abc390635636f59ea51f7736846d9b1e799f4e9b63733679a417a2c5cf10011289081286081a83081280082a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
        );
        let header = Message::parse_from_bytes(&bytes).unwrap();
        assert!(verify_signature(dek, &header))
    }
}
