## 0.3.1

- Added `v3::encrypt_detached_document` for encrypting documents in the legacy TSC format.

## 0.3.0

Breaking changes:

- Updated `rand` from 0.8 to 0.10.
- Changed encrypt functions to take `&mut R` instead of `Arc<Mutex<R>>` for the RNG parameter, reverting the 0.2.0 change. Callers that need shared concurrent access can manage their own `Arc<Mutex<R>>` and pass `&mut *guard` after locking. This simplifies the common case and lets the caller choose the appropriate sharing strategy.

## 0.2.2

- Added `impl_secret_debug!` and `impl_secret_debug_named!` macros for implementing `Debug` on secret-containing types with redacted output.
- Added `redacted_hash` utility function.
- Updated to Rust 2024 edition (MSRV 1.85.0).
- Updated dependencies: `hex-literal` 1.0, `itertools` 0.14, `thiserror` 2.

## 0.2.1

- Added `validate_v4_header` function for validating parsed `V4DocumentHeader`.

## 0.2.0

Breaking changes:

- Changed several functions to take RNG as `Arc<Mutex<R>>` instead of `&mut R`. This allows for these functions to be called concurrently.

## 0.1.0

- Initial release
