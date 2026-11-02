// This module is dedicated with things to do with aes encryption/decryption.
use crate::{Error, Result, impl_secret_debug};
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, Nonce, aead::inout::InOutBuf};
use bytes::Bytes;
use rand::CryptoRng;
pub(crate) const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

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
pub fn encrypt_document_and_attach_iv<R: CryptoRng>(
    rng: &mut R,
    key: EncryptionKey,
    document: PlaintextDocument,
) -> Result<IvAndCiphertext> {
    encrypt_and_attach_iv_with_prefix(rng, key, &[], &document.0)
        .map(|iv_and_ciphertext| IvAndCiphertext(iv_and_ciphertext.into()))
}

/// Encrypt `plaintext` under a random IV into a new buffer laid out as `prefix` + IV + CIPHERTEXT.
pub(crate) fn encrypt_and_attach_iv_with_prefix<R: CryptoRng>(
    rng: &mut R,
    key: EncryptionKey,
    prefix: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut iv);
    let ciphertext_start = prefix.len() + IV_LEN;
    let mut output = vec![0u8; ciphertext_start + plaintext.len() + TAG_LEN];
    output[..prefix.len()].copy_from_slice(prefix);
    output[prefix.len()..ciphertext_start].copy_from_slice(&iv);
    aes_encrypt_into(key, iv, plaintext, &[], &mut output[ciphertext_start..])?;
    Ok(output)
}

pub(crate) fn aes_encrypt<R: CryptoRng>(
    key: EncryptionKey,
    plaintext: &[u8],
    associated_data: &[u8],
    rng: &mut R,
) -> Result<([u8; 12], EncryptedDocument)> {
    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut iv);
    aes_encrypt_with_iv(key, plaintext, iv, associated_data)
}

pub(crate) fn aes_encrypt_with_iv(
    key: EncryptionKey,
    plaintext: &[u8],
    iv: [u8; IV_LEN],
    associated_data: &[u8],
) -> Result<([u8; 12], EncryptedDocument)> {
    let mut output = vec![0u8; plaintext.len() + TAG_LEN];
    aes_encrypt_into(key, iv, plaintext, associated_data, &mut output)?;
    Ok((iv, EncryptedDocument(output)))
}

/// Write the ciphertext and tag of `plaintext` to `output`, which must be `TAG_LEN` bytes longer than `plaintext`.
fn aes_encrypt_into(
    key: EncryptionKey,
    iv: [u8; IV_LEN],
    plaintext: &[u8],
    associated_data: &[u8],
    output: &mut [u8],
) -> Result<()> {
    let (ciphertext, tag) = output.split_at_mut(plaintext.len());
    let buffer = InOutBuf::new(plaintext, ciphertext)
        .expect("Ciphertext was split off at the plaintext length.");
    Aes256Gcm::new(&key.0.into())
        .encrypt_inout_detached(&iv.into(), associated_data, buffer)
        .map(|computed_tag| tag.copy_from_slice(&computed_tag))
        .map_err(|_| Error::EncryptError("Encryption failed.".to_string()))
}

pub(crate) fn aes_decrypt_core(
    key: &EncryptionKey,
    iv: [u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let decryption_failed = || {
        Error::DecryptError("Decryption failed. Ensure the data and key are correct.".to_string())
    };
    let tag_start = ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or_else(decryption_failed)?;
    let (ciphertext, tag) = ciphertext.split_at(tag_start);
    let mut plaintext = vec![0u8; ciphertext.len()];
    let buffer = InOutBuf::new(ciphertext, &mut plaintext)
        .expect("Plaintext was allocated at the ciphertext length.");
    Aes256Gcm::new(&key.0.into())
        .decrypt_inout_detached(
            &Nonce::from(iv),
            associated_data,
            buffer,
            &tag.try_into().expect("Tag was split off at TAG_LEN bytes."),
        )
        .map(|()| plaintext)
        .map_err(|_| decryption_failed())
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
        let (iv, encrypt_result) = aes_encrypt(key, &plaintext, &[], &mut rand::rng()).unwrap();
        let decrypt_result = aes_decrypt_core(&key, iv, &encrypt_result.0, &[]).unwrap();
        assert_eq!(decrypt_result, plaintext);
    }

    #[test]
    fn encrypt_decrypt_attached_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(13u64);
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let document = vec![1u8];
        let encrypted =
            encrypt_document_and_attach_iv(&mut rng, key, PlaintextDocument(document.clone()))
                .unwrap();
        let result = decrypt_document_with_attached_iv(&key, &encrypted).unwrap();
        assert_eq!(result.0, document);
    }

    #[test]
    fn encrypt_document_and_attach_iv_matches_known_bytes() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let plaintext: Vec<u8> = (0u8..37).collect();
        let expected = hex!(
            "39ad0295c374c530fb0620834c59a0530e9799c3a40c2d9f2e3f5d6317126bf3b08adeaba05beed00916540ab9ce671a584a475ddbfdd986123b0c94c75e2faa4f"
        );
        let encrypted = encrypt_document_and_attach_iv(
            &mut ChaCha20Rng::seed_from_u64(13u64),
            key,
            PlaintextDocument(plaintext.clone()),
        )
        .unwrap();
        assert_eq!(encrypted.as_ref(), expected);
        let decrypted =
            decrypt_document_with_attached_iv(&key, &IvAndCiphertext::from(expected.to_vec()))
                .unwrap();
        assert_eq!(decrypted.0, plaintext);
    }

    #[test]
    fn encrypt_empty_document_and_attach_iv_matches_known_bytes() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let expected = hex!("39ad0295c374c530fb0620831b93b4ec8c4cb0fd5c4d594b96a1d1a3");
        let encrypted = encrypt_document_and_attach_iv(
            &mut ChaCha20Rng::seed_from_u64(13u64),
            key,
            PlaintextDocument(vec![]),
        )
        .unwrap();
        assert_eq!(encrypted.as_ref(), expected);
        let decrypted =
            decrypt_document_with_attached_iv(&key, &IvAndCiphertext::from(expected.to_vec()))
                .unwrap();
        assert!(decrypted.0.is_empty());
    }

    #[test]
    fn decrypt_attached_iv_shorter_than_tag_fails() {
        let key = EncryptionKey(hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let iv_and_short_tag = IvAndCiphertext::from(vec![0u8; IV_LEN + 15]);
        let result = decrypt_document_with_attached_iv(&key, &iv_and_short_tag);
        assert!(matches!(result, Err(Error::DecryptError(_))));
    }
}
