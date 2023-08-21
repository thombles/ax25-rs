# ax25 changelog

## v0.3.0 - 21 Aug 2023

* Make `ax25` support no_std while having a default `std` feature
* Split TNC-related functionality into a separate `ax25_tnc` crate
* Update Rust edition to 2021
* Replace `chrono` with `time` and remove dependency on `thiserror`

## v0.2.0 - 2 Feb 2020

* Support for KISS TNCs exposed on a TCP port, such as Dire Wolf
* Unified `Tnc` interface with different TNC types selected by a configuration string
* Much more thorough error handling thanks to `snafu`
* Several new example applications
* Updated for Rust 2018 edition
* Removed the `linux` feature to make things simpler - on unsupported platforms a `linuxif` TNC will simply not work

## v0.1.0 - 19 Aug 2017

* Encoding and decoding AX.25 frames
* Send and receive frames using an AX.25 socket on linux, running as root
