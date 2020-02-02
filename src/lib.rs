//! Utilities for Packet Radio in Rust.

extern crate libc;

/// Encoding and decoding AX.25 v2.0 frames between raw bytes and strongly typed structures.
pub mod frame;

/// Interfacing with native AX.25 network interfaces on Linux. Works with frames of
/// raw bytes that can be used in tandem with the `frame` module.
pub mod linux;

pub mod kiss;

pub mod tnc;
