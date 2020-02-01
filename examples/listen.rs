use ax25::frame::Ax25Frame;
use ax25::linux::Ax25RawSocket;
use chrono::prelude::*;

fn main() {
    // For the moment default to the linux interface
    let mut socket = Ax25RawSocket::new().unwrap();
    while let Ok(frame) = socket.receive_frame() {
        println!("{}", Local::now());
        match Ax25Frame::from_bytes(&frame) {
            Ok(parsed) => println!("{}", parsed),
            Err(e) => println!("Could not parse frame: {}", e),
        };
    }
    let _ = socket.close();
}
