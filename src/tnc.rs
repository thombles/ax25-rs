use crate::frame::Ax25Frame;
use crate::kiss;
use crate::linux;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::collections::VecDeque;
use std::thread;

/// Errors that can occur when interacting with a `Tnc`.
#[derive(Debug, Error)]
pub enum TncError {
    #[error("Unable to connect to TNC: {}", source)]
    OpenTnc { source: std::io::Error },
    #[error("Interface with specified callsign '{}' does not exist", callsign)]
    InterfaceNotFound { callsign: String },
    #[error("Unable to send frame: {}", source)]
    SendFrame { source: std::io::Error },
    #[error("Unable to receive frame: {}", source)]
    ReceiveFrame { source: std::io::Error },
    #[error("Unable to make configuration change: {}", source)]
    ConfigFailed { source: std::io::Error },
}

/// Errors that can occur when parsing a `TncAddress` from a string.
#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("TNC address '{}' is invalid - it should begin with 'tnc:'", string)]
    NoTncPrefix { string: String },
    #[error("Unknown TNC type {}", tnc_type)]
    UnknownType { tnc_type: String },
    #[error(
        "TNC type '{}' expects {} parameters to follow but there are {}",
        tnc_type,
        expected,
        actual
    )]
    WrongParameterCount {
        tnc_type: String,
        expected: usize,
        actual: usize,
    },
    #[error("Supplied port '{}' should be a number from 0 to 65535", input)]
    InvalidPort {
        input: String,
        source: std::num::ParseIntError,
    },
}

/// Configuration details for a TCP KISS TNC. This structure can be created directly
/// or indirectly by parsing a string into a `TncAddress`.
#[derive(PartialEq, Debug)]
pub struct TcpKissConfig {
    /// Hostname or IP address of the computer with the TNC
    pub host: String,
    /// Port number
    pub port: u16,
}

/// Configuration details for a TNC attached as a Linux network interface using
/// `kissattach`. This structure can be created directly or indirectly by parsing
/// a string into a `TncAddress`.
#[derive(PartialEq, Debug)]
pub struct LinuxIfConfig {
    /// The hardware address associated with the interface, e.g. "VK7NTK-2"
    pub callsign: String,
}

#[derive(PartialEq, Debug)]
pub(crate) enum ConnectConfig {
    TcpKiss(TcpKissConfig),
    LinuxIf(LinuxIfConfig),
}

/// A parsed TNC address that can be used to open a `Tnc`.
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
        if !s.starts_with("tnc:") {
            return Err(ParseError::NoTncPrefix {
                string: s.to_string(),
            });
        }
        let components: Vec<&str> = s.split(':').collect();
        let len = components.len();
        Ok(match components[1] {
            "tcpkiss" => {
                if len != 4 {
                    return Err(ParseError::WrongParameterCount {
                        tnc_type: components[1].to_string(),
                        expected: 2usize,
                        actual: len - 2,
                    });
                }
                TncAddress {
                    config: ConnectConfig::TcpKiss(TcpKissConfig {
                        host: components[2].to_string(),
                        port: components[3].parse().map_err(|e| ParseError::InvalidPort {
                            input: components[3].to_string(),
                            source: e,
                        })?,
                    }),
                }
            }
            "linuxif" => {
                if len != 3 {
                    return Err(ParseError::WrongParameterCount {
                        tnc_type: components[1].to_string(),
                        expected: 1usize,
                        actual: len - 2,
                    });
                }
                TncAddress {
                    config: ConnectConfig::LinuxIf(LinuxIfConfig {
                        callsign: components[2].to_string(),
                    }),
                }
            }
            unknown => {
                return Err(ParseError::UnknownType {
                    tnc_type: unknown.to_string(),
                })
            }
        })
    }
}

trait TncImpl: Send + Sync {
    fn send_frame(&self, frame: &Ax25Frame) -> Result<(), TncError>;
    fn receive_frame(&self) -> Result<Ax25Frame, TncError>;
    fn clone(&self) -> Box<dyn TncImpl>;
}

/// A local or remote TNC attached to a radio, which can send and receive frames.
pub struct Tnc {
    imp: Box<dyn TncImpl>,
    senders: Arc<Mutex<Vec<Sender<Ax25Frame>>>>,
    buffer: Arc<Mutex<VecDeque<Ax25Frame>>>,
}

impl Tnc {
    /// Attempt to obtain a `Tnc` connection using the provided address.
    pub fn open(address: &TncAddress) -> Result<Self, TncError> {
        let imp: Box<dyn TncImpl> = match &address.config {
            ConnectConfig::TcpKiss(config) => Box::new(TcpKissTnc::open(&config)?),
            ConnectConfig::LinuxIf(config) => Box::new(LinuxIfTnc::open(&config)?),
        };
        Ok(Tnc::new(imp))
    }

    fn new(imp: Box<dyn TncImpl>) -> Self {
        let tnc = Tnc {
            imp,
            senders: Arc::new(Mutex::new(Vec::new())),
            buffer: Arc::new(Mutex::new(VecDeque::new())),
        };
        {
            let tnc = tnc.clone();
            // TODO how to allow this thread to exit?
            thread::spawn(move || {
                loop {
                    // TODO what to do if this fails?
                    if let Ok(x) = tnc.imp.receive_frame() {
                        tnc.buffer.lock().unwrap().push_back(x.clone());
                        tnc.senders.lock().unwrap().retain(|s| {
                            let x = (&x).clone();
                            // If there's an error, remove sender from vec
                            s.send(x).is_ok()
                        });
                    }
                }
            });
        }
        tnc
    }

    /// Transmit a frame on the radio. Transmission is not guaranteed even if a
    /// `Ok` result is returned.
    pub fn send_frame(&self, frame: &Ax25Frame) -> Result<(), TncError> {
        self.imp.send_frame(frame)
    }

    /// Block to receive a frame from the radio. If you want to do this on
    /// a separate thread from sending, clone the `Tnc`.
    pub fn receive_frame(&self) -> Result<Ax25Frame, TncError> {
        self.imp.receive_frame()
    }

    /// Create a new `Receiver<Ax25Frame>`
    /// This will receive a copy of all incoming frames.
    pub fn incoming(&mut self) -> Receiver<Ax25Frame> {
        let (sender, receiver) = channel();
        self.senders.lock().unwrap().push(sender);
        receiver
    }
}

impl Clone for Tnc {
    fn clone(&self) -> Self {
        Tnc {
            imp: self.imp.clone(),
            senders: self.senders.clone(),
            buffer: self.buffer.clone()
        }
    }
}

struct LinuxIfTnc {
    socket: Arc<linux::Ax25RawSocket>,
    ifindex: i32,
}

impl LinuxIfTnc {
    fn open(config: &LinuxIfConfig) -> Result<Self, TncError> {
        let socket = linux::Ax25RawSocket::new().map_err(|e| TncError::OpenTnc { source: e })?;
        let ifindex = match socket
            .list_ax25_interfaces()
            .map_err(|e| TncError::OpenTnc { source: e })?
            .iter()
            .find(|nd| nd.name.to_uppercase() == config.callsign.to_uppercase())
        {
            Some(nd) => nd.ifindex,
            None => {
                return Err(TncError::InterfaceNotFound {
                    callsign: config.callsign.clone(),
                })
            }
        };
        Ok(Self {
            socket: Arc::new(socket),
            ifindex,
        })
    }
}

impl TncImpl for LinuxIfTnc {
    fn send_frame(&self, frame: &Ax25Frame) -> Result<(), TncError> {
        self.socket
            .send_frame(&frame.to_bytes(), self.ifindex)
            .map_err(|e| TncError::SendFrame { source: e })
    }

    fn receive_frame(&self) -> Result<Ax25Frame, TncError> {
        loop {
            let bytes = self
                .socket
                .receive_frame(self.ifindex)
                .map_err(|e| TncError::ReceiveFrame { source: e })?;
            if let Ok(parsed) = Ax25Frame::from_bytes(&bytes) {
                return Ok(parsed);
            }
        }
    }

    fn clone(&self) -> Box<dyn TncImpl> {
        Box::new(LinuxIfTnc {
            socket: self.socket.clone(),
            ifindex: self.ifindex,
        })
    }
}

struct TcpKissTnc {
    iface: Arc<kiss::TcpKissInterface>,
}

impl TcpKissTnc {
    fn open(config: &TcpKissConfig) -> Result<Self, TncError> {
        Ok(Self {
            iface: Arc::new(
                kiss::TcpKissInterface::new(format!("{}:{}", config.host, config.port))
                    .map_err(|e| TncError::OpenTnc { source: e })?,
            ),
        })
    }
}

impl TncImpl for TcpKissTnc {
    fn send_frame(&self, frame: &Ax25Frame) -> Result<(), TncError> {
        self.iface
            .send_frame(&frame.to_bytes())
            .map_err(|e| TncError::SendFrame { source: e })
    }

    fn receive_frame(&self) -> Result<Ax25Frame, TncError> {
        loop {
            let bytes = self
                .iface
                .receive_frame()
                .map_err(|e| TncError::ReceiveFrame { source: e })?;
            if let Ok(parsed) = Ax25Frame::from_bytes(&bytes) {
                return Ok(parsed);
            }
        }
    }

    fn clone(&self) -> Box<dyn TncImpl> {
        Box::new(TcpKissTnc {
            iface: self.iface.clone(),
        })
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
            "tnc:linuxif:VK7NTK-2".parse::<TncAddress>(),
            Ok(TncAddress {
                config: ConnectConfig::LinuxIf(LinuxIfConfig {
                    callsign: "VK7NTK-2".to_string(),
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
    }
}
