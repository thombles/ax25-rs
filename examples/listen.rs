use ax25::tnc::{TncAddress, Tnc};
use chrono::prelude::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <tnc-address>", args[0]);
        println!("where tnc-address is something like");
        println!("  tnc:linuxif:ax0");
        println!("  tnc:tcpkiss:192.168.0.1:8001");
        return;
    }

    let addr = match args[1].parse::<TncAddress>() {
        Ok(addr) => addr,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let tnc = match Tnc::open(&addr) {
        Ok(tnc) => tnc,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    while let Ok(frame) = tnc.receive_frame() {
        println!("{}", Local::now());
        println!("{}", frame);
    }
}
