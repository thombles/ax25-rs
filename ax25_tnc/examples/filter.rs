use ax25::frame::Address;
use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <tnc-address> <target-callsign>", args[0]);
        println!("Example: {} tnc:linuxif:vk7ntk-2 VK7HDM-6", args[0]);
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let target = args[2].parse::<Address>()?;
    let tnc = Tnc::open(&addr)?;

    println!("Filtering traffic for callsign: {}", target);

    let receiver = tnc.incoming();
    while let Ok(frame_result) = receiver.recv() {
        if let Ok(frame) = frame_result {
            // Match if source or destination matches the target callsign
            if frame.source == target || frame.destination == target {
                let payload = frame
                    .info_string_lossy()
                    .unwrap_or_else(|| "<binary data>".to_string());

                println!(
                    "[MATCH] {} -> {}: {}",
                    frame.source, frame.destination, payload
                );
            }
        }
    }

    Ok(())
}
