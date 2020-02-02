use ax25::frame::{
    Address, Ax25Frame, CommandResponse, FrameContent, ProtocolIdentifier, UnnumberedInformation,
};
use ax25::tnc::{Tnc, TncAddress};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        println!(
            "Usage: {} <tnc-address> <source-callsign> <dest-callsign> <message>",
            args[0]
        );
        println!("where tnc-address is something like");
        println!("  tnc:linuxif:vk7ntk-2");
        println!("  tnc:tcpkiss:192.168.0.1:8001");
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let src = args[2].parse::<Address>()?;
    let dest = args[3].parse::<Address>()?;
    let tnc = Tnc::open(&addr)?;

    let frame = Ax25Frame {
        source: src,
        destination: dest,
        route: Vec::new(),
        command_or_response: Some(CommandResponse::Command),
        content: FrameContent::UnnumberedInformation(UnnumberedInformation {
            pid: ProtocolIdentifier::None,
            info: args[4].as_bytes().to_vec(),
            poll_or_final: false,
        }),
    };

    tnc.send_frame(&frame)?;
    println!("Transmitted!");
    Ok(())
}
