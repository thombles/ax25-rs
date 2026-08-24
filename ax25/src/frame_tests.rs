use super::*;
use alloc::string::ToString;
use alloc::vec::Vec;

#[test]
fn pid_test() {
    assert_eq!(
        ProtocolIdentifier::from_byte(0x01),
        ProtocolIdentifier::X25Plp
    );
    assert_eq!(
        ProtocolIdentifier::from_byte(0xCA),
        ProtocolIdentifier::Appletalk
    );
    assert_eq!(
        ProtocolIdentifier::from_byte(0xFF),
        ProtocolIdentifier::Escape
    );
    assert_eq!(
        ProtocolIdentifier::from_byte(0x45),
        ProtocolIdentifier::Unknown(0x45)
    );
    assert_eq!(
        ProtocolIdentifier::from_byte(0x10),
        ProtocolIdentifier::Layer3Impl
    );
    assert_eq!(
        ProtocolIdentifier::from_byte(0x20),
        ProtocolIdentifier::Layer3Impl
    );
    assert_eq!(
        ProtocolIdentifier::from_byte(0xA5),
        ProtocolIdentifier::Layer3Impl
    );
}

#[test]
fn test_address_fromstr() {
    // Simple cases
    assert_eq!(
        Address::from_str("VK7NTK-1").unwrap(),
        Address {
            callsign: "VK7NTK".to_string(),
            ssid: 1,
        }
    );
    assert_eq!(
        Address::from_str("ID-15").unwrap(),
        Address {
            callsign: "ID".to_string(),
            ssid: 15,
        }
    );

    // Skipping the SSID is allowed, assumed to be 0
    let addr_0 = Address::from_str("VK7NTK").unwrap();
    assert_eq!(addr_0.callsign(), "VK7NTK");
    assert_eq!(addr_0.ssid(), 0);

    // Works, converted to upper case automatically
    assert!(Address::from_str("vk7ntk-5").is_ok());

    // Valid edge case - `8` will be the callsign part with SSID assumed to be 0
    assert!(Address::from_str("8").is_ok());

    // SSID on its own fails
    assert!(Address::from_str("-1").is_err());

    // Various format errors
    assert!(Address::from_str("VK7N -5").is_err());
    assert!(Address::from_str("VK7NTK-16").is_err());
    assert!(Address::from_str("vk7n--1").is_err());
}

#[test]
fn test_round_trips() {
    use std::fs::{read_dir, File};
    use std::io::Read;

    let mut paths: Vec<_> = read_dir("testdata/linux-ax0")
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    paths.sort_by_key(|dir| dir.path());
    for entry in paths {
        let entry_path = entry.path();
        println!("Testing round trip on {}", entry_path.display());
        let filename = entry_path.to_str().unwrap();
        let mut file = File::open(filename).unwrap();
        let mut frame_data: Vec<u8> = Vec::new();
        let _ = file.read_to_end(&mut frame_data);
        // Skip the leading null byte. A quirk as they came from Linux AF_PACKET.
        let frame_data_fixed = &frame_data[1..];

        match Ax25Frame::from_bytes(frame_data_fixed) {
            Ok(parsed) => {
                // Should be identical when re-encoded
                assert_eq!(frame_data_fixed, &parsed.to_bytes()[..])
            }
            Err(e) => panic!("Could not parse! {}", e),
        };
    }
}

#[test]
fn address_parse_invalid_callsign_length() {
    assert!(matches!(
        Address::from_str("ABCDEFG-1"),
        Err(AddressParseError::CallsignTooLong)
    ));
}

#[test]
fn address_parse_invalid_characters() {
    assert!(matches!(
        Address::from_str("VK7N$K-1"),
        Err(AddressParseError::InvalidFormat)
    ));
}

#[test]
fn address_parse_invalid_ssid_non_numeric() {
    assert!(matches!(
        Address::from_str("VK7NTK-XX"),
        Err(AddressParseError::InvalidSsid { .. })
    ));
}

#[test]
fn address_parse_invalid_ssid_out_of_range() {
    assert!(matches!(
        Address::from_str("VK7NTK-99"),
        Err(AddressParseError::SsidOutOfRange)
    ));
}

#[test]
fn address_to_bytes_padding_and_shift() {
    let addr = Address::from_str("VK7NTK-1").unwrap();
    let bytes = addr.to_bytes(false, true);

    // Callsign must be 6 bytes, shifted left by 1
    assert_eq!(bytes[0], b'V' << 1);
    assert_eq!(bytes[5], b'K' << 1);

    // SSID byte structure: (ssid << 1) | 0b0110_0001
    assert_eq!(bytes[6] & 0b0000_1111, (1 << 1) | 0b0000_0001);
}

#[test]
fn pid_round_trip() {
    for pid in [
        ProtocolIdentifier::None,
        ProtocolIdentifier::Escape,
        ProtocolIdentifier::CompressedTcpIp,
        ProtocolIdentifier::Appletalk,
        ProtocolIdentifier::Unknown(0x45), // 0x45 does not match Layer3Impl mask
    ] {
        assert_eq!(ProtocolIdentifier::from_byte(pid.to_byte()), pid);
    }
}

#[test]
fn frame_parse_only_null_bytes() {
    let bytes = vec![0, 0, 0, 0];
    assert!(matches!(
        Ax25Frame::from_bytes(&bytes),
        Err(FrameParseError::OnlyNullBytes)
    ));
}

#[test]
fn frame_parse_no_end_to_address_field() {
    // No byte with low bit = 1
    let bytes = vec![b'V' << 1, b'K' << 1, b'7' << 1, 0x00];
    assert!(matches!(
        Ax25Frame::from_bytes(&bytes),
        Err(FrameParseError::NoEndToAddressField)
    ));
}

#[test]
fn frame_parse_address_field_too_short() {
    // End marker present but too few bytes
    let bytes = vec![b'V' << 1, b'K' << 1, b'7' << 1, 0x01];
    assert!(matches!(
        Ax25Frame::from_bytes(&bytes),
        Err(FrameParseError::AddressFieldTooShort { .. })
    ));
}

#[test]
fn frame_parse_missing_pid_field() {
    // Valid address field but missing PID
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));
    bytes.push(0b0000_0000); // I-frame control byte
                             // No PID → error
    assert!(matches!(
        Ax25Frame::from_bytes(&bytes),
        Err(FrameParseError::MissingPidField)
    ));
}

#[test]
fn parse_i_frame_basic() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    // Control byte: N(R)=3, P=1, N(S)=2
    bytes.push((3 << 5) | (1 << 4) | (2 << 1));
    bytes.push(0xF0); // PID = None
    bytes.extend(b"HELLO");

    let frame = Ax25Frame::from_bytes(&bytes).unwrap();
    match frame.content {
        FrameContent::Information(info) => {
            assert_eq!(info.receive_sequence, 3);
            assert!(info.poll);
            assert_eq!(info.send_sequence, 2);
            assert_eq!(info.info, b"HELLO");
        }
        _ => panic!("Expected I-frame"),
    }
}

#[test]
fn parse_s_frame_rr() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push((4 << 5) | 0b0000_0001); // RR, N(R)=4
    let frame = Ax25Frame::from_bytes(&bytes).unwrap();

    match frame.content {
        FrameContent::ReceiveReady(rr) => {
            assert_eq!(rr.receive_sequence, 4);
            assert!(!rr.poll_or_final);
        }
        _ => panic!("Expected RR frame"),
    }
}

#[test]
fn parse_s_frame_rnr() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push((2 << 5) | 0b0000_0101); // RNR
    let frame = Ax25Frame::from_bytes(&bytes).unwrap();

    match frame.content {
        FrameContent::ReceiveNotReady(rnr) => {
            assert_eq!(rnr.receive_sequence, 2);
        }
        _ => panic!("Expected RNR frame"),
    }
}

#[test]
fn parse_s_frame_rej() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push((1 << 5) | 0b0000_1001); // REJ
    let frame = Ax25Frame::from_bytes(&bytes).unwrap();

    match frame.content {
        FrameContent::Reject(rej) => {
            assert_eq!(rej.receive_sequence, 1);
        }
        _ => panic!("Expected REJ frame"),
    }
}

#[test]
fn parse_u_frame_sabm() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push(0b0010_1111); // SABM
    let frame = Ax25Frame::from_bytes(&bytes).unwrap();

    match frame.content {
        FrameContent::SetAsynchronousBalancedMode(_) => {}
        _ => panic!("Expected SABM"),
    }
}

#[test]
fn parse_u_frame_ui() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push(0b0000_0011); // UI
    bytes.push(0xF0); // PID
    bytes.extend(b"DATA");

    let frame = Ax25Frame::from_bytes(&bytes).unwrap();
    match frame.content {
        FrameContent::UnnumberedInformation(ui) => {
            assert_eq!(ui.info, b"DATA");
        }
        _ => panic!("Expected UI frame"),
    }
}

#[test]
fn parse_u_frame_frmr() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push(0b1000_0111); // FRMR
    bytes.push(0b0000_1111); // flags
    bytes.push(0b1010_0000); // seq + C/R
    bytes.push(0x55); // rejected control field

    let frame = Ax25Frame::from_bytes(&bytes).unwrap();
    match frame.content {
        FrameContent::FrameReject(fr) => {
            assert!(fr.z);
            assert!(fr.y);
            assert!(fr.x);
            assert!(fr.w);
            assert_eq!(fr.rejected_control_field_raw, 0x55);
        }
        _ => panic!("Expected FRMR"),
    }
}

#[test]
fn round_trip_simple_ui() {
    let src = Address::from_str("SRC-1").unwrap();
    let dst = Address::from_str("DST-0").unwrap();
    let frame = Ax25Frame::new_simple_ui_frame(src, dst, b"HELLO".to_vec());

    let encoded = frame.to_bytes();
    let decoded = Ax25Frame::from_bytes(&encoded).unwrap();

    assert_eq!(decoded, frame);
}

#[test]
fn round_trip_i_frame() {
    let src = Address::from_str("SRC-0").unwrap();
    let dst = Address::from_str("DST-0").unwrap();

    let content = FrameContent::Information(Information {
        pid: ProtocolIdentifier::None,
        info: b"PAYLOAD".to_vec(),
        receive_sequence: 3,
        send_sequence: 5,
        poll: true,
    });

    let frame = Ax25Frame {
        source: src,
        destination: dst,
        route: vec![],
        command_or_response: Some(CommandResponse::Command),
        content,
    };

    let encoded = frame.to_bytes();
    let decoded = Ax25Frame::from_bytes(&encoded).unwrap();

    assert_eq!(decoded, frame);
}

#[test]
fn parse_unknown_content() {
    let mut bytes = Vec::new();
    bytes.extend(Address::from_str("DEST-0").unwrap().to_bytes(true, false));
    bytes.extend(Address::from_str("SRC-0").unwrap().to_bytes(false, true));

    bytes.push(0x0D); // Truly unknown control field pattern that bypasses I, S, and U checks
    bytes.extend(b"XYZ");

    let frame = Ax25Frame::from_bytes(&bytes).unwrap();
    match frame.content {
        FrameContent::UnknownContent(uc) => {
            assert_eq!(uc.raw, b"\x0DXYZ");
        }
        _ => panic!("Expected UnknownContent"),
    }
}
