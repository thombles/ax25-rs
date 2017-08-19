use std::error::Error;
use std::str::FromStr;
use std::fmt;

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

impl ProtocolIdentifier {
    fn from_byte(byte: &u8) -> ProtocolIdentifier {
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

    fn to_byte(&self) -> u8 {
        match self {
            &ProtocolIdentifier::Layer3Impl => 0b00010000,
            &ProtocolIdentifier::X25Plp => 0x01,
            &ProtocolIdentifier::CompressedTcpIp => 0x06,
            &ProtocolIdentifier::UncompressedTcpIp => 0x07,
            &ProtocolIdentifier::SegmentationFragment => 0x08,
            &ProtocolIdentifier::TexnetDatagram => 0xC3,
            &ProtocolIdentifier::LinkQuality => 0xC4,
            &ProtocolIdentifier::Appletalk => 0xCA,
            &ProtocolIdentifier::AppletalkArp => 0xCB,
            &ProtocolIdentifier::ArpaIp => 0xCC,
            &ProtocolIdentifier::ArpaAddress => 0xCD,
            &ProtocolIdentifier::Flexnet => 0xCE,
            &ProtocolIdentifier::NetRom => 0xCF,
            &ProtocolIdentifier::None => 0xF0,
            &ProtocolIdentifier::Escape => 0xFF,
            &ProtocolIdentifier::Unknown(pid) => pid
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CommandResponse {
    Command,
    Response
}

#[derive(Debug, PartialEq)]
pub enum FrameContent {
    /// Information (I) frame
    Information {
        pid: ProtocolIdentifier,
        info: Vec<u8>,
        receive_sequence: u8,
        send_sequence: u8,
        poll: bool
    },

    /// RR Supervisory (S) frame
    ReceiveReady {
        receive_sequence: u8,
        poll_or_final: bool
    },
    /// RNR Supervisory (S) frame
    ReceiveNotReady {
        receive_sequence: u8,
        poll_or_final: bool
    },
    /// REJ Supervisory (S) frame
    Reject {
        receive_sequence: u8,
        poll_or_final: bool
    },

    /// SABM Unnumbered (U) frame
    SetAsynchronousBalancedMode {
        poll: bool
    },
    /// DISC Unnumbered (U) frame
    Disconnect {
        poll: bool
    },
    /// DM Unnumbered (U) frame
    DisconnectedMode {
        final_bit: bool // 'final' is a rust keyword
    },
    /// UA Unnumbered (U) frame
    UnnumberedAcknowledge {
        final_bit: bool
    },
    /// FRMR Unnumbered (U) frame. Flags correspond to names in the AX.25 specification.
    FrameReject {
        final_bit: bool,
        /// A raw copy of the control field in the frame that was rejected
        rejected_control_field_raw: u8,
        /// The attached control field contained an invalid Receive Sequence Number
        z: bool,
        /// The information field of a received frame exceeded the maximum allowable length.
        y: bool,
        /// A U or S frame was received that contained an information field.
        x: bool,
        /// The received control field was invalid or not implemented.
        w: bool,
        receive_sequence: u8,
        send_sequence: u8,
        command_response: CommandResponse
    },
    /// UI Unnumbered Information frame
    UnnumberedInformation {
        pid: ProtocolIdentifier,
        info: Vec<u8>,
        poll_or_final: bool
    }
}

impl FrameContent {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        match self {
            &FrameContent::Information { ref pid, ref info, ref receive_sequence, ref send_sequence, ref poll } => {
                let mut c: u8 = 0;
                c |= (receive_sequence & 0b0000_0111) << 5;
                c |= if *poll { 1 << 4 } else { 0 };
                c |= (send_sequence & 0b0000_0111) << 1;
                encoded.push(c);
                encoded.push(pid.to_byte());
                encoded.extend(info);
            },
            &FrameContent::ReceiveReady { ref receive_sequence, ref poll_or_final } => {
                let mut c: u8 = 0b0000_0001;
                c |= if *poll_or_final { 1 << 4 } else { 0 };
                c |= (receive_sequence & 0b0000_0111) << 5;
                encoded.push(c);
            },
            &FrameContent::ReceiveNotReady { ref receive_sequence, ref poll_or_final } => {
                let mut c: u8 = 0b0000_0101;
                c |= if *poll_or_final { 1 << 4 } else { 0 };
                c |= (receive_sequence & 0b0000_0111) << 5;
                encoded.push(c);
            },
            &FrameContent::Reject { ref receive_sequence, ref poll_or_final } => {
                let mut c: u8 = 0b0000_1001;
                c |= if *poll_or_final { 1 << 4 } else { 0 };
                c |= (receive_sequence & 0b0000_0111) << 5;
                encoded.push(c);
            },
            &FrameContent::SetAsynchronousBalancedMode { ref poll } => {
                let mut c: u8 = 0b0010_1111;
                c |= if *poll { 1 << 4 } else { 0 };
                encoded.push(c);
            },
            &FrameContent::Disconnect { ref poll } => {
                let mut c: u8 = 0b0100_0011;
                c |= if *poll { 1 << 4 } else { 0 };
                encoded.push(c);
            },
            &FrameContent::DisconnectedMode { ref final_bit } => {
                let mut c: u8 = 0b0000_1111;
                c |= if *final_bit { 1 << 4 } else { 0 };
                encoded.push(c);
            },
            &FrameContent::UnnumberedAcknowledge { ref final_bit } => {
                let mut c: u8 = 0b0110_0011;
                c |= if *final_bit { 1 << 4 } else { 0 };
                encoded.push(c);
            },
            &FrameContent::FrameReject { ref final_bit, ref rejected_control_field_raw, ref z, ref y, ref x, ref w,
                    ref receive_sequence, ref send_sequence, ref command_response } => {
                let mut c: u8 = 0b1000_0111;
                c |= if *final_bit { 1 << 4 } else { 0 };
                encoded.push(c);
                let mut frmr1: u8 = 0;
                frmr1 |= if *z { 1 << 3 } else { 0 };
                frmr1 |= if *y { 1 << 2 } else { 0 };
                frmr1 |= if *x { 1 << 1 } else { 0 };
                frmr1 |= if *w { 1 << 0 } else { 0 };
                encoded.push(frmr1);
                let mut frmr2: u8 = 0;
                frmr2 |= (receive_sequence & 0b0000_0111) << 5;
                frmr2 |= if *command_response == CommandResponse::Response { 1 << 4 } else { 0 };
                frmr2 |= (send_sequence & 0b0000_0111) << 1;
                encoded.push(frmr2);
                encoded.push(*rejected_control_field_raw);
            },
            &FrameContent::UnnumberedInformation { ref pid, ref info, ref poll_or_final } => {
                let mut c: u8 = 0b0000_0011;
                c |= if *poll_or_final { 1 << 4 } else { 0 };
                encoded.push(c);
                encoded.push(pid.to_byte());
                encoded.extend(info);
            }
        }

        encoded
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

fn parse_err<T>(msg: &str) -> Result<T,Box<Error>> {
    Err(Box::new(ParseError { msg: msg.to_string() }))
}

#[derive(Debug, PartialEq)]
pub struct Address {
    callsign: String,
    ssid: u8,
    c_bit: bool
}

impl Address {
    fn to_bytes(&self, high_bit: bool, final_in_address: bool) -> Vec<u8> {
        let mut encoded = Vec::new();
        // Shift by one bit as required for AX.25 address encoding
        for b in self.callsign.as_bytes() {
            encoded.push(b << 1);
        }
        // Pad with spaces up to length 6
        while encoded.len() != 6 {
            encoded.push(b' ' << 1);
        }
        // Now do the SSID byte
        let high = if high_bit { 0b1000_0000 } else { 0 };
        let low = if final_in_address { 0b0000_0001 } else { 0 };
        let ssid_byte = (self.ssid << 1) | 0b0110_0000 | high | low; 
        encoded.push(ssid_byte);

        encoded
    }
}

impl Default for Address {
    fn default() -> Address {
        Address { callsign: "NOCALL".to_string(), ssid: 0, c_bit: false }
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

impl FromStr for Address {
    type Err = Box<Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("-").collect();
        if parts.len() != 2 {
            return parse_err("Address must be of the form CALL-#");
        }

        let callsign = parts[0].to_uppercase();
        if callsign.len() == 0 || callsign.len() > 6 {
            return parse_err("Callsign must be 1-6 letters/numbers");
        }
        for c in callsign.chars() {
            if !c.is_alphanumeric() {
                return parse_err("Callsign must be alphanumeric only (space padding is handled internally)");
            }
        }
        
        let ssid = parts[1].parse::<u8>()?;
        if ssid > 15 {
            return parse_err("SSID must be from 0 to 15");
        }

        // c_bit will be set on transmit
        Ok(Address { callsign: callsign, ssid: ssid, c_bit: false })
    }
}

#[derive(Debug)]
pub struct RouteEntry {
    pub repeater: Address,
    pub has_repeated: bool
}

#[derive(Debug)]
pub struct Ax25Frame {
    pub source: Address,
    pub destination: Address,
    /// The route the packet has taken/will take according to repeater entries in the address field
    pub route: Vec<RouteEntry>,
    /// AX.25 2.0-compliant stations will indicate in every frame whether it is a command
    /// or a response, as part of the address field.
    pub command_or_response: Option<CommandResponse>,
    pub content: FrameContent
}

impl Ax25Frame {
    /// Returns a UTF-8 string that is a "best effort" at displaying the information
    /// content of this frame. Returns None if there is no information field present.
    /// Most applications will need to work with the Vec<u8> info directly.
    pub fn info_string_lossy(&self) -> Option<String> {
        match self.content {
            FrameContent::Information { ref info, .. }
                => Some(String::from_utf8_lossy(&info).into_owned()),
            FrameContent::UnnumberedInformation { ref info, .. }
                => Some(String::from_utf8_lossy(&info).into_owned()),
            _ => None
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Ax25Frame, Box<Error>> {
        // Skip over leading null bytes
        // Linux AF_PACKET has oen of these - we will strip it out in the linux module
        // but also keep the protection here
        let addr_start = bytes.iter().position(|&c| c != 0).ok_or(ParseError::new())?;
        let addr_end = bytes.iter().position(|&c| c & 0x01 == 0x01).ok_or(ParseError::new())?;
        let control = addr_end + 1;
        if addr_end - addr_start + 1 < 14 { // +1 because the "terminator" is actually within the last byte
            return parse_err(&format!("Address field too short: {} {}", addr_start, addr_end));
        }
        if control >= bytes.len() {
            return parse_err(&format!("Packet is unreasonably short: {} bytes", bytes.len() ));
        }
        
        let dest = parse_address(&bytes[addr_start..addr_start+7])?;
        let src = parse_address(&bytes[addr_start+7..addr_start+14])?;
        let rpt_count = (addr_end + 1 - addr_start - 14) / 7;
        let mut route: Vec<RouteEntry> = Vec::new();
        for i in 0..rpt_count {
            let repeater = parse_address(&bytes[addr_start + 14 + i * 7 .. addr_start + 14 + (i+1) * 7])?;
            let entry = RouteEntry {
                has_repeated: repeater.c_bit, // The "C" bit in an address happens to be the repeated bit for a repeater
                repeater: repeater,
            };
            route.push(entry);
        }

        let content = parse_content(&bytes[control..])?;
        let command_or_response = match (dest.c_bit, src.c_bit) {
            (true, false) => Some(CommandResponse::Command),
            (false, true) => Some(CommandResponse::Response),
            _ => None
        };

        Ok(Ax25Frame {
            source: src,
            destination: dest,
            route: route,
            content: content,
            command_or_response: command_or_response
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut frame = Vec::new();
        let (dest_c_bit, src_c_bit) = match self.command_or_response {
            Some(CommandResponse::Command) => (true, false),
            Some(CommandResponse::Response) => (false, true),
            _ => (true, false) // assume Command
        };
        frame.extend(self.destination.to_bytes(dest_c_bit, false));
        frame.extend(self.source.to_bytes(src_c_bit, self.route.is_empty()));

        for (i, entry) in self.route.iter().enumerate() {
            frame.extend(entry.repeater.to_bytes(entry.has_repeated, i+1 == self.route.len()));
        }

        frame.extend(self.content.encode());
        frame
    }
}

impl fmt::Display for Ax25Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info_display = match self.info_string_lossy() {
            Some(ref info) => info.clone(),
            None => "-".to_string()
        };
        write!(f, "Source\t\t{}\nDestination\t{}\n\
            Data\t\t\"{}\"",
            self.source, self.destination, info_display)
    }
}

fn parse_address(bytes: &[u8]) -> Result<Address, Box<Error>> {
    let mut dest_utf8: Vec<u8> = bytes[0..6].iter()
        .rev()
        .map(|&c| c >> 1)
        .skip_while(|&c| c == b' ')
        .collect::<Vec<u8>>();
    dest_utf8.reverse();
    Ok(Address {
        callsign: String::from_utf8(dest_utf8)?,
        ssid: (bytes[6] >> 1) & 0x0f,
        c_bit: bytes[6] & 0b1000_0000 > 0
    })
}

fn parse_i_frame(bytes: &[u8]) -> Result<FrameContent, Box<Error>> {
    if bytes.len() < 2 {
        return parse_err("Missing PID field");
    }
    let c = bytes[0]; // control octet
    Ok(FrameContent::Information {
        receive_sequence: (c & 0b1110_0000) >> 5,
        send_sequence: (c & 0b0000_1110) >> 1,
        poll: (c & 0b0001_0000) > 0,
        pid: ProtocolIdentifier::from_byte(&bytes[1]),
        info: bytes[2..].iter().cloned().collect() // could be empty vec
    })
}

fn parse_s_frame(bytes: &[u8]) -> Result<FrameContent, Box<Error>> {
    // These all have the same general layout
    // There should be no PID or info following this control byte
    let c = bytes[0];
    let n_r = (c & 0b1110_0000) >> 5;
    let poll_or_final = (c & 0b0001_0000) > 0;

    match c & 0b0000_1111 {
        0b0000_0001 => Ok(FrameContent::ReceiveReady {
            receive_sequence: n_r,
            poll_or_final: poll_or_final
        }),
        0b0000_0101 => Ok(FrameContent::ReceiveNotReady {
            receive_sequence: n_r,
            poll_or_final: poll_or_final
        }),
        0b0000_1001 => Ok(FrameContent::Reject {
            receive_sequence: n_r,
            poll_or_final: poll_or_final
        }),
        _ => parse_err("Unrecognised S field type")
    }
}

fn parse_u_frame(bytes: &[u8]) -> Result<FrameContent, Box<Error>> {
    // The only moving part in control for U frames is the P/F bit
    // Two special cases to handle:
    // FRMR is followed by a 3-byte information field that must be parsed specially
    // UI is followed by PID and variable length information field
    let c = bytes[0];
    let poll_or_final = c & 0b0001_0000 > 0;

    // Ignore the P/F bit for identifying the command or response
    match c & 0b1110_1111 {
        0b0010_1111 => Ok(FrameContent::SetAsynchronousBalancedMode { poll: poll_or_final }),
        0b0100_0011 => Ok(FrameContent::Disconnect { poll: poll_or_final }),
        0b0000_1111 => Ok(FrameContent::DisconnectedMode { final_bit: poll_or_final }),
        0b0110_0011 => Ok(FrameContent::UnnumberedAcknowledge { final_bit: poll_or_final }),
        0b1000_0111 => parse_frmr_frame(bytes),
        0b0000_0011 => parse_ui_frame(bytes),
        _ => parse_err("Unrecognised U field type")
    }
}

fn parse_ui_frame(bytes: &[u8]) -> Result<FrameContent, Box<Error>> {
    if bytes.len() < 2 {
        return parse_err("Missing PID field");
    }
    // Control, then PID, then Info
    Ok(FrameContent::UnnumberedInformation {
        poll_or_final: bytes[0] & 0b0001_0000 > 0,
        pid: ProtocolIdentifier::from_byte(&bytes[1]),
        info: bytes[2..].iter().cloned().collect()
    })
}

fn parse_frmr_frame(bytes: &[u8]) -> Result<FrameContent, Box<Error>> {
    // Expect 24 bits following the control
    if bytes.len() != 4 {
        return parse_err("Wrong size for FRMR info");
    }
    Ok(FrameContent::FrameReject {
        final_bit: bytes[0] & 0b0001_0000 > 0,
        rejected_control_field_raw: bytes[3],
        z: bytes[1] & 0b0000_1000 > 0,
        y: bytes[1] & 0b0000_0100 > 0,
        x: bytes[1] & 0b0000_0010 > 0,
        w: bytes[1] & 0b0000_0001 > 0,
        receive_sequence: (bytes[2] & 0b1110_0000) >> 5,
        command_response: match bytes[2] & 0b0001_0000 > 0 {
            true => CommandResponse::Response,
            false => CommandResponse::Command
        },
        send_sequence: (bytes[2] & 0b0000_1110) >> 1
    })
}

/// Parse the content of the frame starting from the control field
fn parse_content(bytes: &[u8]) -> Result<FrameContent, Box<Error>> {
    if bytes.len() == 0 {
        return parse_err("Zero content length");
    }
    match bytes[0] {
        c if c & 0x01 == 0x00 => parse_i_frame(bytes),
        c if c & 0x03 == 0x01 => parse_s_frame(bytes),
        c if c & 0x03 == 0x03 => parse_u_frame(bytes),
        _ => parse_err("Unrecognised control field")
    }
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

#[test]
fn test_address_fromstr() {
    assert_eq!(Address::from_str("VK7NTK-1").unwrap(), Address { callsign: "VK7NTK".to_string(), ssid: 1, c_bit: false });
    assert_eq!(Address::from_str("ID-15").unwrap(), Address { callsign: "ID".to_string(), ssid: 15, c_bit: false });
    assert!(Address::from_str("vk7ntk-5").is_ok());

    assert!(Address::from_str("-1").is_err());
    assert!(Address::from_str("VK7NTK").is_err());
    assert!(Address::from_str("VK7N -5").is_err());
    assert!(Address::from_str("VK7NTK-16").is_err());
    assert!(Address::from_str("8").is_err());
    assert!(Address::from_str("vk7n--1").is_err());
}
