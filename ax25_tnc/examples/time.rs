use ax25::frame::{
    Address, Ax25Frame, CommandResponse, FrameContent, ProtocolIdentifier, UnnumberedInformation,
};
use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <tnc-address> <my-callsign>", args[0]);
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let src = args[2].parse::<Address>()?;
    let tnc = Tnc::open(&addr)?;

    // Do periodic announcements on a second thread
    let broadcast_dest = "TIME-0".parse::<Address>().unwrap();
    let src_1 = src.clone();
    let tnc_1 = tnc.clone();
    thread::spawn(move || loop {
        if transmit_time(&tnc_1, &src_1, &broadcast_dest).is_err() {
            break;
        }
        thread::sleep(Duration::from_secs(60));
    });

    // Receive on the initial thread
    let receiver = tnc.incoming();
    while let Ok(frame) = receiver.recv().unwrap() {
        // If someone asks us what the time is, tell them immediately
        if let Some(text) = frame.info_string_lossy() {
            if text.contains("what is the time?") {
                transmit_time(&tnc, &src, &frame.source)?;
            }
        }
    }

    Ok(())
}

fn transmit_time(tnc: &Tnc, src: &Address, dest: &Address) -> Result<(), Box<dyn Error>> {
    let frame = Ax25Frame {
        source: src.clone(),
        destination: dest.clone(),
        route: Vec::new(),
        command_or_response: Some(CommandResponse::Command),
        content: FrameContent::UnnumberedInformation(UnnumberedInformation {
            pid: ProtocolIdentifier::None,
            info: format!("The time is: {}", OffsetDateTime::now_utc())
                .as_bytes()
                .to_vec(),
            poll_or_final: false,
        }),
    };
    tnc.send_frame(&frame)?;
    Ok(())
}
