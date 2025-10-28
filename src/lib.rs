pub mod aes;
mod signing;
pub mod v3;
pub mod v4;
pub mod v5;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    fmt::{Display, Formatter, Result as DisplayResult},
    sync::{Mutex, MutexGuard},
};
use thiserror::Error;
use v5::key_id_header::KEY_ID_HEADER_LEN;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Compile-time key with override support
const CRATE_DEBUG_KEY: &str = match option_env!("MY_CRATE_DEBUG_KEY") {
    Some(val) => val,
    // Default to a string that is unlikely to have a rainbow table or some prebuilt attack
    None => "2025-10-28T17:23:36",
};

/// Produce a short keyed hash for display in Debug impls.
pub fn redacted_hash(data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(CRATE_DEBUG_KEY.as_ref())
        .expect("HMAC can take key of any size");
    mac.update(data);
    // slicing this way will always work because HmacSha256 will always be over 8 bytes
    hex::encode(mac.finalize().into_bytes())[..8].to_string()
}

include!(concat!(env!("OUT_DIR"), "/mod.rs"));

#[derive(Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Error {
    /// EDOCs have a minimum size (at least the size of the pre-header)
    EdocTooShort(usize),
    /// Header could not be parsed as proto
    HeaderParseErr(String),
    /// EDOC version is not supported
    InvalidVersion(u8),
    /// 'IRON' as bytes
    NoIronCoreMagic,
    /// specified length of header is larger than the remaining data (proto header + payload)
    SpecifiedLengthTooLong(u32),
    /// Error occurred when serializing the header as proto
    ProtoSerializationErr(String),
    /// Serialized header is longer than allowed. Value is actual length in bytes.
    HeaderLengthOverflow(u64),
    /// Encryption of the edoc failed.
    EncryptError(String),
    /// Decryption of the edoc failed.
    DecryptError(String),
    // The next errors have to do with the key_id_header
    /// EdekType was not recognized
    EdekTypeError(String),
    /// PayloadType was not recognized
    PayloadTypeError(String),
    /// key_id_header to short
    KeyIdHeaderTooShort(usize),
    /// key_id_header malformed
    KeyIdHeaderMalformed(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Error::EdocTooShort(x) => write!(f, "EDOC too short. Found {x} bytes."),
            Error::HeaderParseErr(x) => write!(f, "Header parse error: '{x}'"),
            Error::InvalidVersion(x) => write!(f, "Invalid EDOC version: {x}"),
            Error::NoIronCoreMagic => write!(f, "Missing IronCore Magic bytes in header."),
            Error::SpecifiedLengthTooLong(x) => {
                write!(f, "Header too short for specified length: {x} bytes")
            }
            Error::ProtoSerializationErr(x) => write!(f, "Protobuf serialization error: '{x}'"),
            Error::HeaderLengthOverflow(x) => write!(f, "Header length too long: {x} bytes"),
            Error::EncryptError(x) => write!(f, "{x}"),
            Error::DecryptError(x) => write!(f, "{x}"),
            Error::KeyIdHeaderTooShort(x) => write!(
                f,
                "Key ID header too short. Found: {x} bytes. Required: {KEY_ID_HEADER_LEN} bytes."
            ),
            Error::EdekTypeError(x) => write!(f, "EDEK type error: '{x}'"),
            Error::PayloadTypeError(x) => write!(f, "Payload type error: '{x}'"),
            Error::KeyIdHeaderMalformed(x) => write!(f, "Malformed key ID header: '{x}'"),
        }
    }
}

/// Acquire mutex in a blocking fashion. If the Mutex is or becomes poisoned, write out an error
/// message and panic.
///
/// The lock is released when the returned MutexGuard falls out of scope.
///
/// # Usage:
/// single statement (mut)
/// `let result = take_lock(&t).deref_mut().call_method_on_t();`
///
/// multi-statement (mut)
/// ```ignore
/// let t = T {};
/// let result = {
///     let g = &mut *take_lock(&t);
///     g.call_method_on_t()
/// }; // lock released here
/// ```
///
pub fn take_lock<T>(m: &Mutex<T>) -> MutexGuard<T> {
    m.lock().unwrap_or_else(|e| {
        let error = format!("Error when acquiring lock: {e}");
        panic!("{error}");
    })
}

/// This macro will allow a newtype that has a single tuple field to use a fingerprint instead of
/// printing the secret value.
/// struct Foo([u8;32])
/// impl_secret_debug!(Foo);
/// Then the debug will print something like Foo(<redacted:bda33dd3...>).
#[macro_export]
macro_rules! impl_secret_debug {
    ($t:ty) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}(<redacted:{}...>)",
                    stringify!($t),
                    $crate::redacted_hash(self.0.as_ref())
                )
            }
        }
    };
}

/// This macro will allow a newtype that has a single named field to use a fingerprint instead of
/// printing the secret value.
/// struct Foo {secret:[u8;32]}
/// impl_secret_debug_named!(Foo, secret);
/// Then the debug will print something like Foo{<redacted:bda33dd3...>}.
#[macro_export]
macro_rules! impl_secret_debug_named {
    ($t:ty, $field:ident) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}{{<redacted:{}...>}}",
                    stringify!($t),
                    $crate::redacted_hash(self.$field.as_ref())
                )
            }
        }
    };
}

#[cfg(test)]
mod test {
    #[test]
    fn impl_secret_debug_works() {
        struct FooSecret([u8; 32]);
        impl_secret_debug!(FooSecret);
        let debug_str = format!("{:?}", FooSecret([1; 32]));
        assert_eq!(debug_str, "FooSecret(<redacted:633f9067...>)");
    }

    #[test]
    fn impl_secret_debug_named_works() {
        struct FooSecret {
            secret: String,
        }
        impl_secret_debug_named!(FooSecret, secret);
        let debug_str = format!(
            "{:?}",
            FooSecret {
                secret: "yes".to_string()
            }
        );
        assert_eq!(debug_str, "FooSecret{<redacted:bda33dd3...>}");
    }
}
