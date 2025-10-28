// This module is dedicated with things to do with aes encryption/decryption.
use super::Error;
use crate::{impl_secret_debug, take_lock};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
use bytes::Bytes;
use rand::{CryptoRng, RngCore};
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};

type Result<T> = core::result::Result<T, super::Error>;
pub(crate) const IV_LEN: usize = 12;

/// These bytes are the IV + CIPHERTEXT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvAndCiphertext(pub Bytes);

impl IvAndCiphertext {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for IvAndCiphertext {
    fn default() -> IvAndCiphertext {
        IvAndCiphertext(Bytes::new())
    }
}

impl AsRef<[u8]> for IvAndCiphertext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Bytes> for IvAndCiphertext {
    fn from(b: Bytes) -> Self {
        IvAndCiphertext(b)
    }
}

impl From<Vec<u8>> for IvAndCiphertext {
    fn from(v: Vec<u8>) -> Self {
        IvAndCiphertext(v.into())
    }
}

impl From<IvAndCiphertext> for Bytes {
    fn from(p: IvAndCiphertext) -> Self {
        p.0
    }
}

/// Holds bytes of an aes encrypted value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedDocument(pub Vec<u8>);

/// Holds bytes which are decrypted (The actual document bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextDocument(pub Vec<u8>);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKey(pub [u8; 32]);
impl_secret_debug!(EncryptionKey);

/// Decrypt the AES encrypted payload using the key. Note that the IV is on the front of the payload.
pub fn decrypt_document_with_attached_iv(
    key: &EncryptionKey,
    aes_encrypted_payload: &IvAndCiphertext,
) -> Result<PlaintextDocument> {
    let (iv_slice, ciphertext) = aes_encrypted_payload.0.split_at(IV_LEN);
    let iv = iv_slice
        .try_into()
        .expect("IV conversion will always have 12 bytes.");
    aes_decrypt_core(key, iv, ciphertext, &[]).map(PlaintextDocument)
}

/// Encrypt a document and put the iv on the front of it.
pub fn encrypt_document_and_attach_iv<R: RngCore + CryptoRng>(
    rng: Arc<Mutex<R>>,
    key: EncryptionKey,
    document: PlaintextDocument,
) -> Result<IvAndCiphertext> {
    let (iv, mut enc_data) = aes_encrypt(key, &document.0, &[], rng)?;
    let mut iv_vec = iv.to_vec();
    iv_vec.append(&mut enc_data.0);
    Ok(IvAndCiphertext(iv_vec.into()))
}

pub(crate) fn aes_encrypt<R: RngCore + CryptoRng>(
    key: EncryptionKey,
    plaintext: &[u8],
    associated_data: &[u8],
    rng: Arc<Mutex<R>>,
) -> Result<([u8; 12], EncryptedDocument)> {
    let iv = {
        let mut guard = take_lock(&rng);
        Aes256Gcm::generate_nonce(&mut *guard.deref_mut())
    };
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
        .map_err(|_| Error::EncryptError("Encryption failed.".to_string()))?;
    Ok((iv, EncryptedDocument(encrypted_bytes)))
}

pub(crate) fn aes_decrypt_core(
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
        .map_err(|_| {
            Error::DecryptError(
                "Decryption failed. Ensure the data and key are correct.".to_string(),
            )
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_probabilistic_roundtrip() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext = hex!("112233445566778899aabbccddee");
        let (iv, encrypt_result) = aes_encrypt(
            key,
            &plaintext,
            &[],
            Arc::new(Mutex::new(rand::thread_rng())),
        )
        .unwrap();
        let decrypt_result = aes_decrypt_core(&key, iv, &encrypt_result.0, &[]).unwrap();
        assert_eq!(decrypt_result, plaintext);
    }

    #[test]
    fn encrypt_decrypt_attached_roundtrip() {
        let rng = ChaCha20Rng::seed_from_u64(13u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let document = vec![1u8];
        let encrypted = encrypt_document_and_attach_iv(
            Arc::new(Mutex::new(rng)),
            key,
            PlaintextDocument(document.clone()),
        )
        .unwrap();
        let result = decrypt_document_with_attached_iv(&key, &encrypted).unwrap();
        assert_eq!(result.0, document);
    }
}
