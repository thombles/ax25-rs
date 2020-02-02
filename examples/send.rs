use ax25::frame::{Address, Ax25Frame, CommandResponse, FrameContent, UnnumberedInformation, ProtocolIdentifier};
use ax25::tnc::{TncAddress, Tnc};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        println!("Usage: {} <tnc-address> <source-callsign> <dest-callsign> <message>", args[0]);
        println!("where tnc-address is something like");
        println!("  tnc:linuxif:vk7ntk-2");
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

    let src = match args[2].parse::<Address>() {
        Ok(addr) => addr,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let dest = match args[3].parse::<Address>() {
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

    let frame = Ax25Frame {
        source: src,
        destination: dest,
        route: Vec::new(),
        command_or_response: Some(CommandResponse::Command),
        content: FrameContent::UnnumberedInformation(UnnumberedInformation {
            pid: ProtocolIdentifier::None,
            info: args[4].as_bytes().to_vec(),
            poll_or_final: false
        })
    };
    
    match tnc.send_frame(&frame) {
        Ok(_) => println!("Transmitted!"),
        Err(e) => println!("Send error: {}", e),
    };
}
