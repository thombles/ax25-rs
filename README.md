# ax25

<a href="https://crates.io/crates/ax25">
    <img src="https://img.shields.io/crates/v/ax25.svg" alt="crates.io">
</a>

This rust library provides AX.25 frame encoding and decoding and offers support for
sending and receiving data from radio interfaces.

At this time native Linux AX.25 interface (ax0, ax1 etc.) are supported for sending
and receiving single packets. AX.25 version 2.0 is supported. Any application that
relies on UI frames such as APRS should be well supported at this stage.

73, Tom VK7NTK

## Structure

The `frame` module is responsible for converting frames between a collection of bytes
and a strongly typed data structure `Ax25Frame`.

The `linux` module provides a socket that sends and receives packets of type `Vec<u8>`.
These can be used directly with the `frame` module. If you wish to use the library
without linux support, disable the `linux` feature.

## Example

This is a basic complete program that will transmit a single hardcoded message on
all active AX.25 interfaces. (Various error handling omitted.)

    extern crate ax25;

    use ax25::frame::{Ax25Frame, Address, UnnumberedInformation,
        FrameContent, CommandResponse, ProtocolIdentifier};
    use ax25::linux::{Ax25RawSocket};
    use std::str::FromStr;

    fn main() {
        // Prepare a frame
        let sender: Address = Address::from_str("VK7NTK-4").unwrap();
        let dest: Address = Address::from_str("VK7NTK-5").unwrap();
        let frame = Ax25Frame {
            source: sender,
            destination: dest,
            route: Vec::new(),
            command_or_response: Some(CommandResponse::Command),
            content: FrameContent::UnnumberedInformation(UnnumberedInformation {
                pid: ProtocolIdentifier::None,
                info: "This is a test message".to_owned().into_bytes(),
                poll_or_final: false
            })
        };

        // Create a raw socket and send the frame. This requires root.
        let mut socket = Ax25RawSocket::new().unwrap();
        for iface in socket.list_ax25_interfaces().unwrap() {
            let _ = socket.send_frame(&frame.to_bytes(), iface.ifindex);
        }
        let _ = socket.close();
    }

## Roadmap

Planned features in the short term:

* Support for KISS TNCs and Windows/Mac - both serial-connected and TCP like Dire Wolf
* More ergonomic interface that abstracts over different types of interfaces and allows
  non-blocking sending and receiving.

Nice-to-haves (contributions welcome!):

* APRS content encoding/decoding
* TCP/IP content encoding/decoding
* AX.25 v2.2 support (as of 19 Aug 2017 the spec document is still being clarified)
* State machine for doing AX.25 connections from userspace
