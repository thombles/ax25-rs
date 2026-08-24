use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <tnc-address>", args[0]);
        println!("Example: {} tnc:tcpkiss:192.168.0.1:8001", args[0]);
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let tnc = Tnc::open(&addr)?;

    println!("AX.25 Packet Logger started. Listening for frames...");
    println!(
        "{:<25} | {:<10} -> {:<10} | {:<}",
        "Timestamp", "Source", "Destination", "Payload"
    );
    println!("{}", "-".repeat(80));

    let receiver = tnc.incoming();
    while let Ok(frame_result) = receiver.recv() {
        match frame_result {
            Ok(frame) => {
                let timestamp = OffsetDateTime::now_utc();
                let payload = frame
                    .info_string_lossy()
                    .unwrap_or_else(|| "<binary data>".to_string());

                // Print a clean, structured log entry
                println!(
                    "{:<25} | {:<10} -> {:<10} | {:<}",
                    timestamp, frame.source, frame.destination, payload
                );
            }
            Err(e) => {
                eprintln!("Receiver error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
