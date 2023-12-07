use super::Error;
use crate::{
    create_signed_header,
    icl_header_v4::{self, v4document_header::edek_wrapper::Edek},
    AttachedEncryptedPayload, EncryptedPayload, MAGIC, V0,
};
use aes_gcm::{aead::Aead, aead::Payload, AeadCore, Aes256Gcm, KeyInit, Nonce};
use bytes::Bytes;
use rand::{CryptoRng, RngCore};

type Result<T> = core::result::Result<T, super::Error>;
const DETACHED_HEADER_LEN: usize = 5;
const IV_LEN: usize = 12;

/// Holds bytes of an aes encrypted value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedDocument(pub Vec<u8>);

/// Holds bytes which are decrypted (The actual document bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextDocument(pub Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKey(pub [u8; 32]);

/// If `maybe_dek` is None, generate a dek, otherwise use the one provided.
/// Encrypt the dek using the kek to make an aes edek. The provided id will be put into the Aes256GcmEncryptedDek.
/// Returns the dek and Aes256GcmEncryptedDek.
pub fn generate_aes_edek<R: CryptoRng + RngCore>(
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

/// If `maybe_dek` is None, generate a dek, otherwise use the one provided.
/// Encrypt the dek using the kek to make an aes edek. The provided id will be put into the Aes256GcmEdek.
/// The edek will be placed into a V4DocumentHeader and the signature will be computed.
/// The aes dek is the key used to compute the signature.
pub fn generate_aes_edek_and_sign<R: CryptoRng + RngCore>(
    rng: &mut R,
    kek: EncryptionKey,
    maybe_dek: Option<EncryptionKey>,
    id: &str,
) -> Result<(EncryptionKey, icl_header_v4::V4DocumentHeader)> {
    let (aes_dek, aes_edek) = generate_aes_edek(rng, kek, maybe_dek, id)?;
    Ok((
        aes_dek,
        create_signed_header(
            icl_header_v4::v4document_header::EdekWrapper {
                edek: Some(Edek::Aes256GcmEdek(aes_edek)),
                ..Default::default()
            },
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
    aes_decrypt(kek, iv, &aes_edek.ciphertext, &[])
        .and_then(|dek_bytes| {
            dek_bytes.try_into().map_err(|_| {
                Error::DecryptError("Decrypted AES DEK was not of the correct size".to_string())
            })
        })
        .map(EncryptionKey)
}

/// Decrypt a V4 detached document. The document should have the expected header
pub fn decrypt_detached_document(
    key: &EncryptionKey,
    payload: EncryptedPayload,
) -> Result<PlaintextDocument> {
    let payload_len = payload.0.len();
    if payload_len < DETACHED_HEADER_LEN + IV_LEN {
        Err(Error::EdocTooShort(payload_len))
    } else {
        let (header, iv_and_cipher) = payload.0.split_at(DETACHED_HEADER_LEN);
        if header != [&[V0], &MAGIC[..]].concat() {
            Err(Error::NoIronCoreMagic)
        } else {
            decrypt_attached_document_core(key, iv_and_cipher)
        }
    }
}

pub fn decrypt_attached_document(
    key: &EncryptionKey,
    payload: AttachedEncryptedPayload,
) -> Result<PlaintextDocument> {
    decrypt_attached_document_core(key, &payload.0)
}

pub(crate) fn decrypt_attached_document_core(
    key: &EncryptionKey,
    attached_encrypted_payload: &[u8],
) -> std::result::Result<PlaintextDocument, Error> {
    let (iv_slice, ciphertext) = attached_encrypted_payload.split_at(IV_LEN);
    let iv = iv_slice
        .try_into()
        .expect("IV conversion will always have 12 bytes.");
    aes_decrypt(key, iv, ciphertext, &[]).map(PlaintextDocument)
}

/// Encrypt a document to be used as a detached document. This means it will have a header of `0IRON` as the first
/// 5 bytes.
pub fn encrypt_detached_document<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: EncryptionKey,
    document: PlaintextDocument,
) -> Result<EncryptedPayload> {
    let (iv, enc_data) = aes_encrypt(key, &document.0, &[], rng)?;
    let payload = EncryptedPayload(
        [&[V0], &MAGIC[..], &iv[..], &enc_data.0[..]]
            .concat()
            .into(),
    );
    Ok(payload)
}

/// Encrypt a document to be used as an attached document.
pub fn encrypt_attached_document<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: EncryptionKey,
    document: PlaintextDocument,
) -> Result<AttachedEncryptedPayload> {
    let (iv, enc_data) = aes_encrypt(key, &document.0, &[], rng)?;
    Ok(AttachedEncryptedPayload(
        [&iv[..], &enc_data.0[..]].concat().into(),
    ))
}

pub(crate) fn aes_encrypt<R: RngCore + CryptoRng>(
    key: EncryptionKey,
    plaintext: &[u8],
    associated_data: &[u8],
    rng: &mut R,
) -> Result<([u8; 12], EncryptedDocument)> {
    let iv = Aes256Gcm::generate_nonce(rng);
    aes_encrypt_with_iv(key, plaintext, iv.into(), associated_data)
}

pub(crate) fn aes_encrypt_with_iv(
    key: EncryptionKey,
    plaintext: &[u8],
    iv: [u8; IV_LEN],
    associated_data: &[u8],
) -> Result<([u8; 12], EncryptedDocument)> {
    let cipher = Aes256Gcm::new(&key.0.into());
    let encrypted_bytes = cipher
        .encrypt(
            &iv.into(),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|e| Error::EncryptError(e.to_string()))?;
    Ok((iv, EncryptedDocument(encrypted_bytes)))
}

pub(crate) fn aes_decrypt(
    key: &EncryptionKey,
    iv: [u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key.0.into());

    cipher
        .decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|e| Error::DecryptError(e.to_string()))
}

#[cfg(test)]
mod test {
    use crate::verify_signature;

    use super::*;
    use hex_literal::hex;
    use protobuf::Message;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_probabilistic_roundtrip() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = hex!("112233445566778899aabbccddee");
        let (iv, encrypt_result) =
            aes_encrypt(key, &plaintext, &[], &mut rand::thread_rng()).unwrap();
        let decrypt_result = aes_decrypt(&key, iv, &encrypt_result.0, &[]).unwrap();
        assert_eq!(decrypt_result, plaintext);
    }

    #[test]
    fn generate_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "aabbccddeefaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, aes_edek) = generate_aes_edek(&mut rng, kek, None, id).unwrap();
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
        let (aes_dek, v4_document) = generate_aes_edek_and_sign(&mut rng, kek, None, id).unwrap();
        let aes_edek =
            v4_document.signed_payload.0.clone().unwrap().edeks[0].take_aes_256_gcm_edek();
        let decrypted_aes_dek = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(decrypted_aes_dek, aes_dek);
        let verify_result = verify_signature(decrypted_aes_dek.0, &v4_document);
        assert!(verify_result)
    }

    #[test]
    fn signed_aes_edek_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(203u64);
        let kek = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let id = "hello";
        let (aes_dek, v4_document) = generate_aes_edek_and_sign(&mut rng, kek, None, id).unwrap();
        let aes_edek = v4_document.signed_payload.0.unwrap().edeks[0].take_aes_256_gcm_edek();
        let result = decrypt_aes_edek(&kek, &aes_edek).unwrap();
        assert_eq!(result, aes_dek);
    }

    #[test]
    fn bad_signature_still_decrypts() {
        let proto_bytes = hex!("0a240a200049fac03b443a5f9d22dae5de3e45d23b2e5705db0843ead925118c59b171d11001124b12491a470a0cde60918359674bd7dc64756512304f4fdd03877ebe65decd71b57ea1cbb070b3fa4c9d29482dbd29a9112165e888e7a8d116be1c4d5e2162a0bb7fe9b03e1a0568656c6c6f");
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
        let verify_result = verify_signature(decrypted_aes_dek.0, &v4_document);
        // Verify fails because I messed the signature up in the proto_bytes
        assert!(!verify_result)
    }

    #[test]
    fn encrypt_decrypt_detached_document_roundtrips() {
        let mut rng = ChaCha20Rng::seed_from_u64(172u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = PlaintextDocument(vec![100u8, 200u8]);
        let encrypted = encrypt_detached_document(&mut rng, key, plaintext.clone()).unwrap();
        let result = decrypt_detached_document(&key, encrypted).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn decrypt_fails_no_magic() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let encrypted = EncryptedPayload(
            hex!("fa51152873435062df7e60039d744b248f2e0776d071450f3c879a5895b7")
                .to_vec()
                .into(),
        );

        let result = decrypt_detached_document(&key, encrypted).unwrap_err();
        assert_eq!(result, Error::NoIronCoreMagic);
    }

    #[test]
    fn decrypt_fails_too_short() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let encrypted = EncryptedPayload(hex!("0049524f4efa51").to_vec().into());

        let result = decrypt_detached_document(&key, encrypted).unwrap_err();
        assert_eq!(result, Error::EdocTooShort(7));
    }

    #[test]
    fn encrypt_decrypt_attached_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(13u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let document = vec![1u8];
        let encrypted =
            encrypt_attached_document(&mut rng, key, PlaintextDocument(document.clone())).unwrap();
        let result = decrypt_attached_document(&key, encrypted).unwrap();
        assert_eq!(result.0, document);
    }
}
