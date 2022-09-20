//! Utilities for Packet Radio in Rust.
//!
//! This crate aims to provide tools for writing cross-platform packet radio software in Rust.
//!
//! See the related `ax25` crate for packet wrangling including `no_std` support.
//!
//! Main features:
//! * Connect to TNCs via multiple methods without needing to change your code
//! * KISS protocol
//!
//! Most developers will want to focus on `tnc::TncAddress` and `tnc::Tnc`.
//! 1. Generate or ask the user to supply an address string. This takes the form:  
//!    `tnc:tcpkiss:192.168.0.1:8001` or  
//!    `tnc:linuxif:vk7ntk-2`
//! 2. Parse this to an address: `let addr = string.parse::<TncAddress>()?;`
//! 3. Attempt to open the TNC: `let tnc = Tnc::open(&addr)?;`
//! 4. Use `send_frame()` and `receive_frame()` to communicate on the radio.
//! 5. The `Tnc` can be cloned for multithreaded use.
//!
//! Several sample programs are provided in the source code repository under `/examples`.

/// Connect to a TNC and use it to send and receive frames.
pub mod tnc;

/// Interfacing with native AX.25 network interfaces on Linux.
mod linux;

/// Interfacing with TCP KISS servers such as Dire Wolf.
mod kiss;
