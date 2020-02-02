use std::str::FromStr;
use std::sync::Arc;

use crate::frame::Ax25Frame;
use crate::linux;

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
    type Err = (); // TODO errors that are useful to the end user

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = s.split(':').collect();
        if components.len() < 2 {
            return Err(());
        }
        if components[0] != "tnc" {
            return Err(());
        }
        Ok(match components[1] {
            "tcpkiss" => {
                if components.len() != 4 {
                    return Err(());
                }
                TncAddress {
                    config: ConnectConfig::TcpKiss(TcpKissConfig {
                        host: components[2].to_string(),
                        port: match components[3].parse() {
                            Ok(port) => port,
                            _ => return Err(()),
                        },
                    }),
                }
            }
            "linuxif" => {
                if components.len() != 3 {
                    return Err(());
                }
                TncAddress {
                    config: ConnectConfig::LinuxIf(LinuxIfConfig {
                        ifname: components[2].to_string(),
                    }),
                }
            }
            _ => {
                return Err(());
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
        // Try each known implementation in turn to see if it likes our address
        Err(())
    }
}

struct LinuxIfTnc {
    socket: Arc<linux::Ax25RawSocket>,
    ifindex: i32,
}

impl LinuxIfTnc {
    fn handles_address(address: &TncAddress) -> bool {
        if let ConnectConfig::LinuxIf(_) = address.config {
            true
        } else {
            false
        }
    }

    fn open(address: &TncAddress) -> Result<Self, ()> {
        if let ConnectConfig::LinuxIf(config) = &address.config {
            let socket = linux::Ax25RawSocket::new().unwrap(); // TODO merge errors
            let ifindex = match socket.list_ax25_interfaces().unwrap().iter()
                .find(|nd| nd.name == config.ifname) {
                    Some(nd) => nd.ifindex,
                    None => return Err(()),
            };
            return Ok(Self {
                socket: Arc::new(socket),
                ifindex,
            })
        }
        Err(())
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
        assert_eq!("fish".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss:".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss:a:b:c".parse::<TncAddress>(), Err(()));
        assert_eq!("tnc:tcpkiss:192.168.0.1".parse::<TncAddress>(), Err(()));
        assert_eq!(
            "tnc:tcpkiss:192.168.0.1:hello".parse::<TncAddress>(),
            Err(())
        );
    }
}
