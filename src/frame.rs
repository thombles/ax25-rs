use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct Address {
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
        let ssid_str = match self.ssid {
            0 => "".to_string(),
            ssid => format!("-{}", ssid)
        };
        write!(f, "{}{}", self.callsign, ssid_str)
    }
}

#[derive(Default, Debug)]
pub struct Ax25Frame {
    source: Address,
    destination: Address,
    pid: Option<ProtocolIdentifier>,
    info: Option<Vec<u8>>,
    info_str: Option<String>
}

impl fmt::Display for Ax25Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info_display = match &self.info_str {
            &Some(ref info) => info.clone(),
            &None => "-".to_string()
        };
        let pid_display = match &self.pid {
            &Some(ref pid) => format!("{:?}", pid),
            &None => "-".to_string()
        };
        write!(f, "Source\t\t{}\nDestination\t{}\n\
            Protocol\t{}\n\
            Data\t\t\"{}\"",
            self.source, self.destination,
            pid_display, info_display)
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

// Mostly from AX.25 2.2 spec which has far more examples than 2.0
#[derive(Debug, PartialEq)]
pub enum ProtocolIdentifier {
    Layer3Impl,
    X25Plp,
    CompressedTcpIp,
    UncompressedTcpIp,
    SegmentationFragment,
    TexnetDatagram,
    LinkQuality,
    Appletalk,
    AppletalkArp,
    ArpaIp,
    ArpaAddress,
    Flexnet,
    NetRom,
    None,
    Escape,
    Unknown(u8)
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

fn get_pid_from_byte(byte: &u8) -> ProtocolIdentifier {
    match *byte {
        pid if pid & 0b00110000 == 0b00010000
            || pid & 0b00110000 == 0b00100000 => ProtocolIdentifier::Layer3Impl,
        0x01 => ProtocolIdentifier::X25Plp,
        0x06 => ProtocolIdentifier::CompressedTcpIp,
        0x07 => ProtocolIdentifier::UncompressedTcpIp,
        0x08 => ProtocolIdentifier::SegmentationFragment,
        0xC3 => ProtocolIdentifier::TexnetDatagram,
        0xC4 => ProtocolIdentifier::LinkQuality,
        0xCA => ProtocolIdentifier::Appletalk,
        0xCB => ProtocolIdentifier::AppletalkArp,
        0xCC => ProtocolIdentifier::ArpaIp,
        0xCD => ProtocolIdentifier::ArpaAddress,
        0xCE => ProtocolIdentifier::Flexnet,
        0xCF => ProtocolIdentifier::NetRom,
        0xF0 => ProtocolIdentifier::None,
        0xFF => ProtocolIdentifier::Escape,
        pid => ProtocolIdentifier::Unknown(pid)
    }
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

    // PID is only ever 1 bit
    frame.pid = Some(get_pid_from_byte(&bytes[pid]));

    // Now extract the information content as a copy
    frame.info = Some(bytes[info_start..].iter().cloned().collect());
    // Create a best-effort string version for convenience
    frame.info_str = match frame.info {
        Some(ref bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        None => None
    };
    
    Ok(frame)
}

#[test]
fn pid_test() {
    assert_eq!(get_pid_from_byte(&0x01), ProtocolIdentifier::X25Plp);
    assert_eq!(get_pid_from_byte(&0xCA), ProtocolIdentifier::Appletalk);
    assert_eq!(get_pid_from_byte(&0xFF), ProtocolIdentifier::Escape);
    assert_eq!(get_pid_from_byte(&0x45), ProtocolIdentifier::Unknown(0x45));
    assert_eq!(get_pid_from_byte(&0x10), ProtocolIdentifier::Layer3Impl);
    assert_eq!(get_pid_from_byte(&0x20), ProtocolIdentifier::Layer3Impl);
    assert_eq!(get_pid_from_byte(&0xA5), ProtocolIdentifier::Layer3Impl);
}