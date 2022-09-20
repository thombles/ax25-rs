//! AX.25 packets in Rust.

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

extern crate alloc;

/// Encoding and decoding AX.25 v2.0 frames between raw bytes and strongly typed structures.
pub mod frame;
