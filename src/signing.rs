use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
pub struct Signature(pub Vec<u8>);

pub const AES_KEY_LEN: usize = 32;

pub fn sign_hs256(key: [u8; AES_KEY_LEN], payload: &[u8]) -> Signature {
    let mut mac =
        HmacSha256::new_from_slice(&key).expect("The key has a fixed size which is good.");
    mac.update(payload);
    let result = mac.finalize();
    Signature(result.into_bytes().to_vec())
}

pub fn verify_hs256(key: [u8; AES_KEY_LEN], payload: &[u8], sig: &Signature) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(&key).expect("The key has a fixed size which is good.");
    mac.update(payload);
    mac.verify_slice(&sig.0).is_ok()
}
