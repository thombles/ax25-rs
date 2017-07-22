use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct Address {
    callsign: String,
    ssid: u8
}

impl Default for Address {
    fn default() -> Address {
        Address { callsign: "NOCALL".to_string(), ssid: 0 }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.callsign, self.ssid)
    }
}

#[derive(Default, Debug)]
pub struct Ax25Frame {
    source: Address,
    destination: Address,
    info: Option<Vec<u8>>,
    info_str: Option<String>
}

impl fmt::Display for Ax25Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info_display = match &self.info_str {
            &Some(ref info) => info.clone(),
            &None => "".to_string()
        };
        write!(f, "Source\t\t{}\nDestination\t{}\nData\t\t\"{}\"", self.source, self.destination, info_display)
    }
}

#[derive(Debug, Default)]
pub struct ParseError {
    msg: String
}
impl ParseError {
    fn new() -> ParseError {
        ParseError { msg: "Parse error".to_string() }
    }
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl Error for ParseError {
    fn description(&self) -> &str {
        return &self.msg;
    }
}

fn parse_address(bytes: &[u8], address: &mut Address) -> Result<(), Box<Error>> {
    let mut dest_utf8: Vec<u8> = bytes[0..6].iter()
        .rev()
        .map(|&c| c >> 1)
        .skip_while(|&c| c == b' ')
        .collect::<Vec<u8>>();
    dest_utf8.reverse();
    address.callsign = String::from_utf8(dest_utf8)?;
    address.ssid = (bytes[6] >> 1) & 0x0f;
    Ok(())
}

pub fn parse_from_raw(bytes: Vec<u8>) -> Result<Ax25Frame, Box<Error>> {
    // Skip over leading null bytes
    let addr_start = bytes.iter().position(|&c| c != 0).ok_or(ParseError::new())?;
    let addr_end = bytes.iter().position(|&c| c & 0x01 == 0x01).ok_or(ParseError::new())?;
    let control = addr_end + 1;
    let pid = control + 1;
    let info_start = pid + 1;
    if addr_end - addr_start + 1 < 14 { // +1 because the "terminator" is actually within the last byte
        return Err(Box::new(ParseError { msg: format!("Address field too short: {} {}", addr_start, addr_end) }));
    }
    if info_start > bytes.len() { // technically allows empty info
        return Err(Box::new(ParseError { msg: format!("Packet is unreasonably short: {} bytes", bytes.len() )}));
    }
    
    let mut frame: Ax25Frame = Default::default();
    parse_address(&bytes[addr_start..addr_start+7], &mut frame.destination)?;
    parse_address(&bytes[addr_start+7..addr_start+14], &mut frame.source)?;

    if bytes[control] & 0b11101111 != 0b00000011 {
        // Not a UI frame. Just return it with what we have.
        return Ok(frame);
    }

    // Now extract the information content as a copy
    frame.info = Some(bytes[info_start..].iter().cloned().collect());
    // Create a best-effort string version for convenience
    frame.info_str = match frame.info {
        Some(ref bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        None => None
    };
    
    Ok(frame)
}
