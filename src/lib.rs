//! Utilities for Packet Radio in Rust.

/// Encoding and decoding AX.25 v2.0 frames between raw bytes and strongly typed structures.
pub mod frame;

/// Connect to a TNC and use it to send and receive frames.
pub mod tnc;

/// Interfacing with native AX.25 network interfaces on Linux.
mod linux;

/// Interfacing with TCP KISS servers such as Dire Wolf.
mod kiss;

