use std::str::FromStr;
use std::sync::Arc;
use snafu::{ensure, ResultExt, Snafu};
use crate::frame::Ax25Frame;
use crate::linux;

#[derive(Debug, Snafu)]
enum TncError {
    #[snafu(display("Unable to connect to TNC: {}", source))]
    OpenTnc { source: std::io::Error },
    #[snafu(display("Unable to send frame: {}", source))]
    SendFrame { source: std::io::Error },
    #[snafu(display("Unable to receive frame: {}", source))]
    ReceiveFrame { source: std::io::Error },
}

#[derive(Debug, Snafu, PartialEq)]
pub enum ParseError {
    #[snafu(display("TNC address '{}' is invalid - it should begin with 'tnc:'", string))]
    NoTncPrefix { string: String },
    #[snafu(display("Unknown TNC type {}", tnc_type))]
    UnknownType { tnc_type: String },
    #[snafu(display("TNC type '{}' expects {} parameters to follow but there are {}", tnc_type, expected, actual))]
    WrongParameterCount { tnc_type: String, expected: usize, actual: usize },
    #[snafu(display("Supplied port '{}' should be a number from 0 to 65535", input))]
    InvalidPort { input: String, source: std::num::ParseIntError }
}

#[derive(PartialEq, Debug)]
pub struct TcpKissConfig {
    // Use a String to accept domain names. Even for IP addresses we will typically
    // receive this in a textual format from a parameter or config file.
    host: String,
    port: u16,
}

#[derive(PartialEq, Debug)]
pub struct LinuxIfConfig {
    ifname: String, // e.g. "ax0"
}

#[derive(PartialEq, Debug)]
pub(crate) enum ConnectConfig {
    TcpKiss(TcpKissConfig),
    LinuxIf(LinuxIfConfig),
}

#[derive(PartialEq, Debug)]
pub struct TncAddress {
    pub(crate) config: ConnectConfig,
}

impl TncAddress {
    /// Programmatically create a `TncAddress` pointing to a Linux network interface.
    pub fn new_linuxif(linuxif: LinuxIfConfig) -> Self {
        TncAddress {
            config: ConnectConfig::LinuxIf(linuxif),
        }
    }

    /// Porgrammatically create a `TncAddress` pointing to a KISS TCP service.
    pub fn new_tcpkiss(tcpkiss: TcpKissConfig) -> Self {
        TncAddress {
            config: ConnectConfig::TcpKiss(tcpkiss),
        }
    }
}

impl FromStr for TncAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure!(s.starts_with("tnc:"), NoTncPrefix { string: s.to_string() });
        let components: Vec<&str> = s.split(':').collect();
        let len = components.len();
        Ok(match components[1] {
            "tcpkiss" => {
                ensure!(len == 4, WrongParameterCount { tnc_type: components[1], expected: 2usize, actual: len - 2 });
                TncAddress {
                    config: ConnectConfig::TcpKiss(TcpKissConfig {
                        host: components[2].to_string(),
                        port: components[3].parse().context(InvalidPort { input: components[3].to_string() })?,
                    }),
                }
            }
            "linuxif" => {
                ensure!(len == 3, WrongParameterCount { tnc_type: components[1], expected: 1usize, actual: len - 2 });
                TncAddress {
                    config: ConnectConfig::LinuxIf(LinuxIfConfig {
                        ifname: components[2].to_string(),
                    }),
                }
            }
            unknown => {
                UnknownType { tnc_type: unknown.to_string() }.fail()?
            }
        })
    }
}

trait TncImpl {
    fn send_frame(&self, frame: &Ax25Frame) -> Result<(), ()>;
    fn receive_frame(&self) -> Result<Ax25Frame, ()>;
    fn paclen(&self) -> u8;
    fn set_paclen(&self, len: u8) -> Result<(), ()>;
}

pub struct Tnc {
    imp: Box<dyn TncImpl>,
}

impl Tnc {
    pub fn open_tnc(address: &TncAddress) -> Result<Self, ()> {
        // match on the config type and call the right open()
        Err(())
    }
}

struct LinuxIfTnc {
    socket: Arc<linux::Ax25RawSocket>,
    ifindex: i32,
}

impl LinuxIfTnc {
    fn open(config: &LinuxIfConfig) -> Result<Self, ()> {
        let socket = linux::Ax25RawSocket::new().unwrap(); // TODO merge errors
        let ifindex = match socket.list_ax25_interfaces().unwrap().iter()
            .find(|nd| nd.name == config.ifname) {
                Some(nd) => nd.ifindex,
                None => return Err(()),
        };
        Ok(Self {
            socket: Arc::new(socket),
            ifindex,
        })
    }
}

impl TncImpl for LinuxIfTnc {
    fn send_frame(&self, frame: &Ax25Frame) -> Result<(), ()> {
        self.socket.send_frame(&frame.to_bytes(), self.ifindex).unwrap();
        Ok(())
    }

    fn receive_frame(&self) -> Result<Ax25Frame, ()> {
        Err(())
    }

    fn paclen(&self) -> u8 {
        255
    }

    fn set_paclen(&self, len: u8) -> Result<(), ()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
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
            "tnc:linuxif:ax0".parse::<TncAddress>(),
            Ok(TncAddress {
                config: ConnectConfig::LinuxIf(LinuxIfConfig {
                    ifname: "ax0".to_string(),
                })
            })
        );
        assert!(match "fish".parse::<TncAddress>() {
            Err(ParseError::NoTncPrefix { .. }) => true,
            _ => false,
        });
        assert!(match "tnc:".parse::<TncAddress>() {
            Err(ParseError::UnknownType { tnc_type }) => tnc_type == "",
            _ => false,
        });
        assert!(match "tnc:fish".parse::<TncAddress>() {
            Err(ParseError::UnknownType { tnc_type }) => tnc_type == "fish",
            _ => false,
        });
        assert!(match "tnc:tcpkiss".parse::<TncAddress>() {
            Err(ParseError::WrongParameterCount { tnc_type, expected, actual }) => {
                tnc_type == "tcpkiss" && expected == 2 && actual == 0
            },
            _ => false,
        });
        assert!(match "tnc:tcpkiss:".parse::<TncAddress>() {
            Err(ParseError::WrongParameterCount { tnc_type, expected, actual }) => {
                tnc_type == "tcpkiss" && expected == 2 && actual == 1
            },
            _ => false,
        });
        assert!(match "tnc:tcpkiss:a:b:c".parse::<TncAddress>() {
            Err(ParseError::WrongParameterCount { tnc_type, expected, actual }) => {
                tnc_type == "tcpkiss" && expected == 2 && actual == 3
            },
            _ => false,
        });
        assert!(match "tnc:tcpkiss:192.168.0.1".parse::<TncAddress>() {
            Err(ParseError::WrongParameterCount { tnc_type, expected, actual }) => {
                tnc_type == "tcpkiss" && expected == 2 && actual == 1
            },
            _ => false,
        });
        assert!(match "tnc:tcpkiss:192.168.0.1:hello".parse::<TncAddress>() {
            Err(ParseError::InvalidPort { input, .. }) => input == "hello",
            _ => false,
        });
    }
}
