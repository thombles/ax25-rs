use ax25::frame::{
    Address, Ax25Frame, CommandResponse, FrameContent, ProtocolIdentifier, UnnumberedInformation,
};
use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        println!(
            "Usage: {} <tnc-address> <callsign> <dest-callsign> <aprs-comment> <interval-seconds>",
            args[0]
        );
        println!(
            "Example: {} tnc:linuxif:vk7ntk-2 VK7NMK-1 APZRS0 \"Station Online\" 300",
            args[0]
        );
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let src = args[2].parse::<Address>()?;
    let dest = args[3].parse::<Address>()?;
    let comment = &args[4];
    let interval_secs: u64 = args[5].parse()?;

    let tnc = Tnc::open(&addr)?;

    // Standard APRS position format example:
    // Using a placeholder coordinate string or standard APRS data type identifier (! for uncompressed position)
    // Example payload format: !4259.00N/08100.00W# Station Online
    let aprs_payload = format!("!4259.00N/08100.00W# {}", comment);

    println!("Starting APRS beacon for {} -> target {}", src, dest);
    println!("Broadcasting every {} seconds...", interval_secs);

    loop {
        let frame = Ax25Frame {
            source: src.clone(),
            destination: dest.clone(),
            route: Vec::new(),
            command_or_response: Some(CommandResponse::Command),
            content: FrameContent::UnnumberedInformation(UnnumberedInformation {
                pid: ProtocolIdentifier::None,
                info: aprs_payload.as_bytes().to_vec(),
                poll_or_final: false,
            }),
        };

        match tnc.send_frame(&frame) {
            Ok(()) => println!("APRS beacon transmitted successfully."),
            Err(e) => eprintln!("Failed to transmit beacon: {}", e),
        }

        thread::sleep(Duration::from_secs(interval_secs));
    }
}
