# ax25

<a href="https://crates.io/crates/ax25">
    <img src="https://img.shields.io/crates/v/ax25.svg" alt="crates.io">
</a>
<a href="https://docs.rs/ax25">
    <img src="https://docs.rs/ax25/badge.svg" alt="docs.rs">
</a>

This crate aims to provide everything you need to write cross-platform packet radio
software in Rust.

* Encode and decode AX.25 frames (currently supporting v2.0)
* KISS protocol
* Connect to TNCs via multiple methods without needing to change your code

## Quick Start

Most developers will want to focus on `tnc::TncAddress` and `tnc::Tnc`.
1. Generate or ask the user to supply an address string. This takes the form:  
   `tnc:tcpkiss:192.168.0.1:8001` or  
   `tnc:linuxif:vk7ntk-2`
2. Parse this to an address: `let addr = string.parse::<TncAddress>()?;`
3. Attempt to open the TNC: `let tnc = Tnc::open(&addr)?;`
4. Use `send_frame()` and `receive_frame()` to communicate on the radio.
5. The `Tnc` can be cloned for multithreaded use.

If your application requires encoding/decoding AX.25 data directly, see the `frame` module.

## Example

This following is one of the included example programs, `listen.rs`. It is a poor
imitation of `axlisten`.

```rust
use ax25::tnc::{Tnc, TncAddress};
use chrono::prelude::*;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <tnc-address>", args[0]);
        println!("where tnc-address is something like");
        println!("  tnc:linuxif:vk7ntk-2");
        println!("  tnc:tcpkiss:192.168.0.1:8001");
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let tnc = Tnc::open(&addr)?;

    while let Ok(frame) = tnc.receive_frame() {
        println!("{}", Local::now());
        println!("{}", frame);
    }
    Ok(())
}
```

It produces output like the following. Note that it must be run with `sudo` when
using the Linux interface.

```
$ sudo ./target/debug/examples/listen tnc:linuxif:vk7ntk-2
2020-02-02 21:51:11.017220715 +11:00
Source		VK7NTK-1
Destination	IDENT
Data		"hello this is a test"
```

The above is the `Display` implementation for `Ax25Frame` - full protocol information
is available through its fields which are not printed here.

## Roadmap

Planned features:

* Support for serial KISS TNCs (physical, TNC-Pi, Dire Wolf pseudo-tty)
* Paclen management
* More convenient send/receive interfaces for messing around with UI frames
* Direct use of linux axports interfaces without `kissattach`
