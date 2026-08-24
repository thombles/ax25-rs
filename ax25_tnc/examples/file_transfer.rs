use ax25::frame::{
    Address, Ax25Frame, CommandResponse, FrameContent, ProtocolIdentifier, UnnumberedInformation,
};
use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;
use std::thread;
use std::time::Duration;

const MAX_CHUNK_SIZE: usize = 128;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        println!(
            "Usage: {} <tnc-address> <source-callsign> <dest-callsign> <message-string>",
            args[0]
        );
        println!(
            "Example: {} tnc:linuxif:vk7ntk-2 VK7NMK-1 APRS \"Long message payload to chunk...\"",
            args[0]
        );
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let src = args[2].parse::<Address>()?;
    let dest = args[3].parse::<Address>()?;
    let message = &args[4];

    let tnc = Tnc::open(&addr)?;
    let bytes = message.as_bytes();
    let chunks: Vec<&[u8]> = bytes.chunks(MAX_CHUNK_SIZE).collect();

    println!(
        "Splitting message into {} chunks (max {} bytes each)...",
        chunks.len(),
        MAX_CHUNK_SIZE
    );

    for (i, chunk) in chunks.iter().enumerate() {
        let frame = Ax25Frame {
            source: src.clone(),
            destination: dest.clone(),
            route: Vec::new(),
            command_or_response: Some(CommandResponse::Command),
            content: FrameContent::UnnumberedInformation(UnnumberedInformation {
                pid: ProtocolIdentifier::None,
                info: chunk.to_vec(),
                poll_or_final: false,
            }),
        };

        tnc.send_frame(&frame)?;
        println!("Sent chunk {}/{}", i + 1, chunks.len());

        // Brief pause between sequential frames to avoid buffer flooding
        thread::sleep(Duration::from_millis(200));
    }

    println!("File/message transfer complete.");
    Ok(())
}
