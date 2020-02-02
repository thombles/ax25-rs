use ax25::frame::Ax25Frame;
use ax25::linux::Ax25RawSocket;
use ax25::tnc::TncAddress;
use chrono::prelude::*;

fn main() {
    // Let's test this out...
    match "tnc:tcpkiss:192.168.0.1:4000".parse::<TncAddress>() {
        Ok(_) => println!("Parsed first address"),
        Err(e) => println!("Failed to parse first address: {}", e),
    };
    match "tnc:tcpkiss:192.168.0.1:4000:eleven".parse::<TncAddress>() {
        Ok(_) => println!("Parsed second address"),
        Err(e) => println!("Failed to parse second address: {}", e),
    };

    // For the moment default to the linux interface
    let socket = Ax25RawSocket::new().unwrap();
    while let Ok(frame) = socket.receive_frame() {
        println!("{}", Local::now());
        match Ax25Frame::from_bytes(&frame) {
            Ok(parsed) => println!("{}", parsed),
            Err(e) => println!("Could not parse frame: {}", e),
        };
    }
}
