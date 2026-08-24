use super::*;

#[test]
fn parse_tnc_addresses() {
    assert_eq!(
        "tnc:tcpkiss:192.168.0.1:8001".parse::<TncAddress>(),
        Ok(TncAddress {
            config: ConnectConfig::TcpKiss(TcpKissConfig {
                host: "192.168.0.1".to_string(),
                port: 8001_u16,
            })
        })
    );
    assert_eq!(
        "tnc:linuxif:VK7NTK-2".parse::<TncAddress>(),
        Ok(TncAddress {
            config: ConnectConfig::LinuxIf(LinuxIfConfig {
                callsign: "VK7NTK-2".to_string(),
            })
        })
    );
    assert_eq!(
        "tnc:serialkiss:/dev/ttyUSB0:9200".parse::<TncAddress>(),
        Ok(TncAddress {
            config: ConnectConfig::SerialKiss(SerialKissConfig {
                device: "/dev/ttyUSB0".to_string(),
                baud: 9200,
            })
        })
    );
    assert!(matches!(
        "fish".parse::<TncAddress>(),
        Err(ParseError::NoTncPrefix { .. })
    ));
    assert!(matches!(
        "tnc:".parse::<TncAddress>(),
        Err(ParseError::UnknownType { tnc_type }) if tnc_type.is_empty()
    ));
    assert!(matches!(
        "tnc:fish".parse::<TncAddress>(),
        Err(ParseError::UnknownType { tnc_type }) if tnc_type == "fish"
    ));
    assert!(match "tnc:tcpkiss".parse::<TncAddress>() {
        Err(ParseError::WrongParameterCount {
            tnc_type,
            expected,
            actual,
        }) => {
            tnc_type == "tcpkiss" && expected == 2 && actual == 0
        }
        _ => false,
    });
    assert!(match "tnc:tcpkiss:".parse::<TncAddress>() {
        Err(ParseError::WrongParameterCount {
            tnc_type,
            expected,
            actual,
        }) => {
            tnc_type == "tcpkiss" && expected == 2 && actual == 1
        }
        _ => false,
    });
    assert!(match "tnc:tcpkiss:a:b:c".parse::<TncAddress>() {
        Err(ParseError::WrongParameterCount {
            tnc_type,
            expected,
            actual,
        }) => {
            tnc_type == "tcpkiss" && expected == 2 && actual == 3
        }
        _ => false,
    });
    assert!(match "tnc:tcpkiss:192.168.0.1".parse::<TncAddress>() {
        Err(ParseError::WrongParameterCount {
            tnc_type,
            expected,
            actual,
        }) => {
            tnc_type == "tcpkiss" && expected == 2 && actual == 1
        }
        _ => false,
    });
    assert!(
        match "tnc:tcpkiss:192.168.0.1:hello".parse::<TncAddress>() {
            Err(ParseError::InvalidPort { input, .. }) => input == "hello",
            _ => false,
        }
    );
    assert!(match "tnc:serialkiss:".parse::<TncAddress>() {
        Err(ParseError::WrongParameterCount {
            tnc_type,
            expected,
            actual,
        }) => {
            tnc_type == "serialkiss" && expected == 2 && actual == 1
        }
        _ => false,
    });
    assert!(match "tnc:serialkiss:a:b:c".parse::<TncAddress>() {
        Err(ParseError::WrongParameterCount {
            tnc_type,
            expected,
            actual,
        }) => {
            tnc_type == "serialkiss" && expected == 2 && actual == 3
        }
        _ => false,
    });
}

#[test]
fn parse_empty_string() {
    // [empty_string](ca://s?q=Test_parse_empty_string)
    assert!(matches!(
        "".parse::<TncAddress>(),
        Err(ParseError::NoTncPrefix { .. })
    ));
}

#[test]
fn parse_prefix_only() {
    // [prefix_only](ca://s?q=Test_parse_prefix_only)
    assert!(matches!(
        "tnc:".parse::<TncAddress>(),
        Err(ParseError::UnknownType { tnc_type }) if tnc_type.is_empty()
    ));
}

#[test]
fn parse_tcpkiss_missing_port() {
    // [tcpkiss_missing_port](ca://s?q=Test_parse_tcpkiss_missing_port)
    assert!(matches!(
        "tnc:tcpkiss:127.0.0.1".parse::<TncAddress>(),
        Err(ParseError::WrongParameterCount { tnc_type, expected, actual })
            if tnc_type == "tcpkiss" && expected == 2 && actual == 1
    ));
}

#[test]
fn parse_tcpkiss_empty_host() {
    // [tcpkiss_empty_host](ca://s?q=Test_parse_tcpkiss_empty_host)
    assert!(matches!(
        "tnc:tcpkiss::8001".parse::<TncAddress>(),
        Ok(TncAddress {
            config: ConnectConfig::TcpKiss(TcpKissConfig {
                host,
                port: 8001,
            })
        }) if host.is_empty()
    ));
}

#[test]
fn parse_tcpkiss_invalid_port_negative() {
    // [tcpkiss_invalid_port_negative](ca://s?q=Test_parse_tcpkiss_invalid_port_negative)
    assert!(matches!(
        "tnc:tcpkiss:localhost:-1".parse::<TncAddress>(),
        Err(ParseError::InvalidPort { input, .. }) if input == "-1"
    ));
}

#[test]
fn parse_tcpkiss_invalid_port_large() {
    // [tcpkiss_invalid_port_large](ca://s?q=Test_parse_tcpkiss_invalid_port_large)
    assert!(matches!(
        "tnc:tcpkiss:localhost:999999".parse::<TncAddress>(),
        Err(ParseError::InvalidPort { input, .. }) if input == "999999"
    ));
}

#[test]
fn parse_serialkiss_missing_baud() {
    // [serialkiss_missing_baud](ca://s?q=Test_parse_serialkiss_missing_baud)
    assert!(matches!(
        "tnc:serialkiss:/dev/ttyUSB0".parse::<TncAddress>(),
        Err(ParseError::WrongParameterCount { tnc_type, expected, actual })
            if tnc_type == "serialkiss" && expected == 2 && actual == 1
    ));
}

#[test]
fn parse_serialkiss_invalid_baud_non_numeric() {
    // [serialkiss_invalid_baud_non_numeric](ca://s?q=Test_parse_serialkiss_invalid_baud_non_numeric)
    assert!(matches!(
        "tnc:serialkiss:/dev/ttyUSB0:fast".parse::<TncAddress>(),
        Err(ParseError::InvalidBaud { input, .. }) if input == "fast"
    ));
}

#[test]
fn parse_serialkiss_invalid_baud_zero() {
    // [serialkiss_invalid_baud_zero](ca://s?q=Test_parse_serialkiss_invalid_baud_zero)
    assert!(matches!(
        "tnc:serialkiss:/dev/ttyUSB0:0".parse::<TncAddress>(),
        Ok(TncAddress {
            config: ConnectConfig::SerialKiss(SerialKissConfig { baud, .. })
        }) if baud == 0
    ));
}

#[test]
fn parse_linuxif_empty_callsign() {
    // [linuxif_empty_callsign](ca://s?q=Test_parse_linuxif_empty_callsign)
    assert!(matches!(
        "tnc:linuxif:".parse::<TncAddress>(),
        Ok(TncAddress {
            config: ConnectConfig::LinuxIf(LinuxIfConfig { callsign })
        }) if callsign.is_empty()
    ));
}

#[test]
fn parse_unknown_type_with_extra_fields() {
    // [unknown_type_extra_fields](ca://s?q=Test_parse_unknown_type_extra_fields)
    assert!(matches!(
        "tnc:weird:abc:def".parse::<TncAddress>(),
        Err(ParseError::UnknownType { tnc_type }) if tnc_type == "weird"
    ));
}

#[test]
fn parse_type_with_uppercase() {
    // [uppercase_type](ca://s?q=Test_parse_type_with_uppercase)
    assert!(matches!(
        "tnc:TCPKISS:localhost:8001".parse::<TncAddress>(),
        Err(ParseError::UnknownType { tnc_type }) if tnc_type == "TCPKISS"
    ));
}

#[test]
fn parse_whitespace_in_address() {
    // [whitespace_in_address]
    assert!(matches!(
        "tnc:tcpkiss:127.0.0.1: 8001 ".parse::<TncAddress>(),
        Err(ParseError::InvalidPort { .. })
    ));
}

#[test]
fn parse_trailing_colon() {
    // [trailing_colon](ca://s?q=Test_parse_trailing_colon)
    assert!(matches!(
        "tnc:tcpkiss:localhost:8001:".parse::<TncAddress>(),
        Err(ParseError::WrongParameterCount { tnc_type, expected, actual })
            if tnc_type == "tcpkiss" && expected == 2 && actual == 3
    ));
}

#[test]
fn parse_multiple_colons_in_device() {
    // [multiple_colons_in_device](ca://s?q=Test_parse_multiple_colons_in_device)
    assert!(matches!(
        "tnc:serialkiss:/dev/tty:USB0:9600".parse::<TncAddress>(),
        Err(ParseError::WrongParameterCount { .. })
    ));
}
