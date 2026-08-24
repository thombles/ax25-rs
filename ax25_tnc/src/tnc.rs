use crate::kiss;
use crate::linux;
use ax25::frame::Ax25Frame;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

/// Errors that can occur when interacting with a `Tnc`.
#[derive(Debug)]
pub enum TncError {
    OpenTnc { source: std::io::Error },
    InterfaceNotFound { callsign: String },
    PortNotFound { device: String },
    SendFrame { source: std::io::Error },
    ReceiveFrame { source: std::io::Error },
    ConfigFailed { source: std::io::Error },
}

impl Error for TncError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenTnc { source } => Some(source),
            Self::InterfaceNotFound { .. } => None,
            Self::PortNotFound { .. } => None,
            Self::SendFrame { source } => Some(source),
            Self::ReceiveFrame { source } => Some(source),
            Self::ConfigFailed { source } => Some(source),
        }
    }
}

impl fmt::Display for TncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenTnc { source } => write!(f, "Unable to connect to TNC: {}", source),
            Self::InterfaceNotFound { callsign } => write!(
                f,
                "Interface with specified callsign '{}' does not exist",
                callsign
            ),
            Self::PortNotFound { device } => write!(
                f,
                "Specified serial port device '{}' does not exist",
                device
            ),
            Self::SendFrame { source } => write!(f, "Unable to send frame: {}", source),
            Self::ReceiveFrame { source } => write!(f, "Unable to receive frame: {}", source),
            Self::ConfigFailed { source } => {
                write!(f, "Unable to make configuration change: {}", source)
            }
        }
    }
}

/// Errors that can occur when parsing a `TncAddress` from a string.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    NoTncPrefix {
        string: String,
    },
    UnknownType {
        tnc_type: String,
    },
    WrongParameterCount {
        tnc_type: String,
        expected: usize,
        actual: usize,
    },
    InvalidPort {
        input: String,
        source: std::num::ParseIntError,
    },
    InvalidBaud {
        input: String,
        source: std::num::ParseIntError,
    },
}

impl Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTncPrefix { string } => write!(
                f,
                "TNC address '{}' is invalid - it should begin with 'tnc:'",
                string
            ),
            Self::UnknownType { tnc_type } => write!(f, "Unknown TNC type {}", tnc_type),
            Self::WrongParameterCount {
                tnc_type,
                expected,
                actual,
            } => write!(
                f,
                "TNC type '{}' expects {} parameters to follow but there are {}",
                tnc_type, expected, actual
            ),
            Self::InvalidPort { input, .. } => write!(
                f,
                "Supplied port '{}' should be a number from 0 to 65535",
                input
            ),
            Self::InvalidBaud { input, .. } => write!(
                f,
                "Supplied baud rate '{}' should be a number like 4800 or 9600",
                input
            ),
        }
    }
}

/// Configuration details for a TCP KISS TNC. This structure can be created directly
/// or indirectly by parsing a string into a `TncAddress`.
#[derive(PartialEq, Debug, Eq)]
pub struct TcpKissConfig {
    /// Hostname or IP address of the computer with the TNC
    pub host: String,
    /// Port number
    pub port: u16,
}

/// Configuration details for a Serial Port KISS TNC. This structure can be created
/// directly or indirectly by parsing a string into a `TncAddress`.
#[derive(PartialEq, Debug, Eq)]
pub struct SerialKissConfig {
    /// Device name or path for the serial port interface
    pub device: String,
    /// Baud rate for the serial port
    pub baud: u32,
}

/// Configuration details for a TNC attached as a Linux network interface using
/// `kissattach`. This structure can be created directly or indirectly by parsing
/// a string into a `TncAddress`.
#[derive(PartialEq, Debug, Eq)]
pub struct LinuxIfConfig {
    /// The hardware address associated with the interface, e.g. "VK7NTK-2"
    pub callsign: String,
}

#[derive(PartialEq, Debug, Eq)]
pub(crate) enum ConnectConfig {
    TcpKiss(TcpKissConfig),
    LinuxIf(LinuxIfConfig),
    SerialKiss(SerialKissConfig),
}

/// A parsed TNC address that can be used to open a `Tnc`.
#[derive(PartialEq, Debug, Eq)]
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

    /// Programmatically create a `TncAddress` pointing to a KISS TCP service.
    pub fn new_tcpkiss(tcpkiss: TcpKissConfig) -> Self {
        TncAddress {
            config: ConnectConfig::TcpKiss(tcpkiss),
        }
    }

    /// Programmatically create a `TncAddress` pointing to a serial port KISS interface.
    pub fn new_serialkiss(serialkiss: SerialKissConfig) -> Self {
        TncAddress {
            config: ConnectConfig::SerialKiss(serialkiss),
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
            "serialkiss" => {
                if len != 4 {
                    return Err(ParseError::WrongParameterCount {
                        tnc_type: components[1].to_string(),
                        expected: 2usize,
                        actual: len - 2,
                    });
                }
                TncAddress {
                    config: ConnectConfig::SerialKiss(SerialKissConfig {
                        device: components[2].to_string(),
                        baud: components[3].parse().map_err(|e| ParseError::InvalidBaud {
                            input: components[3].to_string(),
                            source: e,
                        })?,
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
    fn shutdown(&self);
}

/// A local or remote TNC attached to a radio, which can send and receive frames.
#[derive(Clone)]
pub struct Tnc(Arc<Mutex<TncInner>>);

impl Tnc {
    /// Attempt to obtain a `Tnc` connection using the provided address.
    pub fn open(address: &TncAddress) -> Result<Self, TncError> {
        let imp: Box<dyn TncImpl> = match &address.config {
            ConnectConfig::TcpKiss(config) => Box::new(TcpKissTnc::open(config)?),
            ConnectConfig::LinuxIf(config) => Box::new(LinuxIfTnc::open(config)?),
            ConnectConfig::SerialKiss(config) => Box::new(SerialKissTnc::open(config)?),
        };
        Ok(Tnc(Arc::new(Mutex::new(TncInner::new(imp)))))
    }

    /// Transmit a frame on the radio. Transmission is not guaranteed even if a
    /// `Ok` result is returned.
    pub fn send_frame(&self, frame: &Ax25Frame) -> Result<(), TncError> {
        self.0.lock().unwrap().send_frame(frame)
    }

    /// Create a new `Receiver<Result<Ax25Frame, TncError>>`
    /// This will receive a copy of all incoming frames.
    pub fn incoming(&self) -> Receiver<Ax25FrameResult> {
        self.0.lock().unwrap().incoming()
    }
}

pub type Ax25FrameResult = Result<Ax25Frame, Arc<TncError>>;

struct TncInner {
    imp: Box<dyn TncImpl>,
    senders: Arc<Mutex<Vec<Sender<Ax25FrameResult>>>>,
}

impl TncInner {
    fn new(imp: Box<dyn TncImpl>) -> Self {
        let senders: Arc<Mutex<Vec<Sender<Ax25FrameResult>>>> = Arc::new(Mutex::new(Vec::new()));

        {
            let imp = imp.clone();
            let senders = senders.clone();

            thread::spawn(move || {
                loop {
                    let x = match imp.receive_frame() {
                        Ok(a) => Ok(a),
                        Err(e) => Err(Arc::new(e)),
                    };

                    let mut senders_lock = senders.lock().unwrap();
                    senders_lock.retain(|s| {
                        // If there's an error or closed receiver, remove sender from vec
                        s.send(x.clone()).is_ok()
                    });

                    if x.is_err() {
                        break;
                    }
                }

                senders.lock().unwrap().clear();
            });
        }

        TncInner { imp, senders }
    }

    /// Transmit a frame on the radio. Transmission is not guaranteed even if a
    /// `Ok` result is returned.
    pub fn send_frame(&self, frame: &Ax25Frame) -> Result<(), TncError> {
        self.imp.send_frame(frame)
    }

    /// Create a new `Receiver<Result<Ax25Frame, TncError>>`
    /// This will receive a copy of all incoming frames.
    pub fn incoming(&self) -> Receiver<Ax25FrameResult> {
        let (sender, receiver) = channel();
        self.senders.lock().unwrap().push(sender);
        receiver
    }
}

impl Drop for TncInner {
    fn drop(&mut self) {
        self.imp.shutdown();
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

    fn shutdown(&self) {
        self.socket.shutdown();
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

    fn shutdown(&self) {
        self.iface.shutdown();
    }
}

struct SerialKissTnc {
    iface: Arc<kiss::SerialKissInterface>,
}

impl SerialKissTnc {
    fn open(config: &SerialKissConfig) -> Result<Self, TncError> {
        Ok(Self {
            iface: Arc::new(
                kiss::SerialKissInterface::new(&config.device, config.baud)
                    .map_err(|e| TncError::OpenTnc { source: e })?,
            ),
        })
    }
}

impl TncImpl for SerialKissTnc {
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
        Box::new(SerialKissTnc {
            iface: self.iface.clone(),
        })
    }

    fn shutdown(&self) {
        self.iface.shutdown();
    }
}

#[cfg(test)]
#[path = "tnc_tests.rs"]
mod tnc_tests;
