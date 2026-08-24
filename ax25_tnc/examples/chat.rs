use ax25::frame::{
    Address, Ax25Frame, CommandResponse, FrameContent, ProtocolIdentifier, UnnumberedInformation,
};
use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;
use std::io::{self, Write};
use std::thread;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!(
            "Usage: {} <tnc-address> <my-callsign> <dest-callsign>",
            args[0]
        );
        println!("Example: {} tnc:linuxif:vk7ntk-2 VK7NMK-1 APRS", args[0]);
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let src = args[2].parse::<Address>()?;
    let dest = args[3].parse::<Address>()?;
    let tnc = Tnc::open(&addr)?;

    println!("Starting AX.25 chat as {} targeting {}", src, dest);
    println!("Type a message and press Enter to transmit over the air.\n");

    // Spawn a thread to handle incoming frames so we don't block typing
    let receiver_tnc = tnc.clone();
    thread::spawn(move || {
        let receiver = receiver_tnc.incoming();
        while let Ok(frame_result) = receiver.recv() {
            match frame_result {
                Ok(frame) => {
                    if let Some(text) = frame.info_string_lossy() {
                        println!(
                            "\n[{}] From {}: {}",
                            OffsetDateTime::now_utc(),
                            frame.source,
                            text
                        );
                        print!("> ");
                        let _ = io::stdout().flush();
                    }
                }
                Err(e) => {
                    eprintln!("Receiver disconnected: {}", e);
                    break;
                }
            }
        }
    });

    // Main thread handles stdin input and sending
    print!("> ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut line = String::new();
    while stdin.read_line(&mut line)? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let frame = Ax25Frame {
                source: src.clone(),
                destination: dest.clone(),
                route: Vec::new(),
                command_or_response: Some(CommandResponse::Command),
                content: FrameContent::UnnumberedInformation(UnnumberedInformation {
                    pid: ProtocolIdentifier::None,
                    info: trimmed.as_bytes().to_vec(),
                    poll_or_final: false,
                }),
            };

            if let Err(e) = tnc.send_frame(&frame) {
                eprintln!("Failed to send frame: {}", e);
            }
        }
        line.clear();
        print!("> ");
        io::stdout().flush()?;
    }

    Ok(())
}
