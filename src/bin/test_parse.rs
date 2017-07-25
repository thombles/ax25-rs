extern crate ax25;

use ax25::frame::Ax25Frame;
use std::fs::{File, read_dir};
use std::io::Read;


fn main() {
    let mut paths: Vec<_> = read_dir("testdata/linux-ax0").unwrap()
                                              .map(|r| r.unwrap())
                                              .collect();
    paths.sort_by_key(|dir| dir.path());
    for entry in paths {
        let entry_path = entry.path();
        let filename = entry_path.to_str().unwrap();
        let mut file = File::open(filename).unwrap();
        let mut frame_data: Vec<u8> = Vec::new();
        let _ = file.read_to_end(&mut frame_data);

        println!("\nParse result for {}:", filename);
        match Ax25Frame::from_bytes(&frame_data) {
            Ok(parsed) => {
                println!("{:#?}", parsed);
                if let Some(info) = parsed.info_string_lossy() {
                    println!("String content: {}", info);
                }
                print!("\nReencoded: ");
                for byte in parsed.to_bytes() {
                   print!("{:X} ", byte);
                }
                println!("\n");
            },
            Err(e) => println!("Could not parse! {}", e)
        };
    }
}
