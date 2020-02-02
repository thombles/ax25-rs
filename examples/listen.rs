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
