use ax25::frame::Address;
use ax25_tnc::tnc::{Tnc, TncAddress};
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <tnc-address> <my-callsign>", args[0]);
        println!("Example: {} tnc:linuxif:vk7ntk-2 VK7NMK-1", args[0]);
        std::process::exit(1);
    }

    let addr = args[1].parse::<TncAddress>()?;
    let my_call = args[2].parse::<Address>()?;
    let tnc = Tnc::open(&addr)?;

    println!("Starting AX.25 digipeater as {}...", my_call);

    let receiver = tnc.incoming();
    while let Ok(frame_result) = receiver.recv() {
        if let Ok(frame) = frame_result {
            let mut should_repeat = false;
            let mut new_route = frame.route.clone();

            for hop in &mut new_route {
                // RouteEntry contains a `repeater` (which is an Address) and `has_repeated`
                if hop.repeater.callsign() == my_call.callsign()
                    && hop.repeater.ssid() == my_call.ssid()
                {
                    should_repeat = true;
                    break;
                }
            }

            if should_repeat {
                println!(
                    "Repeating frame from {} to {}",
                    frame.source, frame.destination
                );
                let mut outgoing = frame.clone();
                outgoing.route = new_route;

                if let Err(e) = tnc.send_frame(&outgoing) {
                    eprintln!("Failed to repeat frame: {}", e);
                }
            }
        }
    }

    Ok(())
}
