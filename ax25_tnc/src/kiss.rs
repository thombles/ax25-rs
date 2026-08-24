use std::io;
use std::io::prelude::*;
use std::net::Shutdown;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[cfg(feature = "serial")]
use serialport::{self, SerialPort};

#[cfg(feature = "serial")]
use std::time::Duration;

#[cfg(not(feature = "serial"))]
use std::io::{Error, ErrorKind};

const FEND: u8 = 0xC0;
const FESC: u8 = 0xDB;
const TFEND: u8 = 0xDC;
const TFESC: u8 = 0xDD;

pub(crate) struct TcpKissInterface {
    // Interior mutability is desirable so that we can clone the TNC and have
    // different threads sending and receiving concurrently.
    tx_stream: Mutex<TcpStream>,
    rx_stream: Mutex<TcpStream>,
    buffer: Mutex<Vec<u8>>,
    is_shutdown: AtomicBool,
}

impl TcpKissInterface {
    pub(crate) fn new<A: ToSocketAddrs>(addr: A) -> io::Result<TcpKissInterface> {
        let tx_stream = TcpStream::connect(addr)?;
        let rx_stream = tx_stream.try_clone()?;
        Ok(TcpKissInterface {
            tx_stream: Mutex::new(tx_stream),
            rx_stream: Mutex::new(rx_stream),
            buffer: Mutex::new(Vec::new()),
            is_shutdown: AtomicBool::new(false),
        })
    }

    pub(crate) fn receive_frame(&self) -> io::Result<Vec<u8>> {
        loop {
            if self.is_shutdown.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TNC shutting down",
                ));
            }
            {
                let mut buffer = self.buffer.lock().unwrap();
                if let Some(frame) = make_frame_from_buffer(&mut buffer) {
                    return Ok(frame);
                }
            }
            let mut buf = vec![0u8; 1024];
            let n_bytes = {
                let mut rx_stream = self.rx_stream.lock().unwrap();
                rx_stream.read(&mut buf)?
            };
            if n_bytes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ));
            }
            {
                let mut buffer = self.buffer.lock().unwrap();
                // Prevent unbounded buffer growth if garbage bytes accumulate without a frame
                if buffer.len() > 65536 {
                    buffer.clear();
                }
                buffer.extend(buf.iter().take(n_bytes));
            }
        }
    }

    pub(crate) fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        if self.is_shutdown.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TNC is shut down",
            ));
        }
        let mut tx_stream = self.tx_stream.lock().unwrap();
        // 0x00 is the KISS command byte, which is two nybbles
        // port = 0
        // command = 0 (all following bytes are a data frame to transmit)
        tx_stream.write_all(&[FEND, 0x00])?;
        tx_stream.write_all(frame)?;
        tx_stream.write_all(&[FEND])?;
        tx_stream.flush()?;
        Ok(())
    }

    pub(crate) fn shutdown(&self) {
        if !self.is_shutdown.load(Ordering::SeqCst) {
            self.is_shutdown.store(true, Ordering::SeqCst);
            if let Ok(tx_stream) = self.tx_stream.lock() {
                let _ = tx_stream.shutdown(Shutdown::Both);
            }
        }
    }
}

impl Drop for TcpKissInterface {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) struct SerialKissInterface {
    // Interior mutability is desirable so that we can clone the TNC and have
    // different threads sending and receiving concurrently.
    #[cfg(feature = "serial")]
    tx_stream: Mutex<Box<dyn SerialPort>>,
    #[cfg(feature = "serial")]
    rx_stream: Mutex<Box<dyn SerialPort>>,
    #[cfg(feature = "serial")]
    buffer: Mutex<Vec<u8>>,
    is_shutdown: AtomicBool,
}

impl SerialKissInterface {
    #[allow(unused_variables)]
    pub(crate) fn new(device: &str, baud: u32) -> io::Result<SerialKissInterface> {
        #[cfg(feature = "serial")]
        {
            let tx_stream = serialport::new(device, baud)
                .timeout(Duration::MAX)
                .open()?;
            let rx_stream = tx_stream.try_clone()?;
            Ok(SerialKissInterface {
                tx_stream: Mutex::new(tx_stream),
                rx_stream: Mutex::new(rx_stream),
                buffer: Mutex::new(Vec::new()),
                is_shutdown: AtomicBool::new(false),
            })
        }

        #[cfg(not(feature = "serial"))]
        {
            Err(Error::new(
                ErrorKind::Unsupported,
                "Serial port devices are not supported.",
            ))
        }
    }

    pub(crate) fn receive_frame(&self) -> io::Result<Vec<u8>> {
        #[cfg(feature = "serial")]
        {
            loop {
                if self.is_shutdown.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "TNC shutting down",
                    ));
                }
                {
                    let mut buffer = self.buffer.lock().unwrap();
                    if let Some(frame) = make_frame_from_buffer(&mut buffer) {
                        return Ok(frame);
                    }
                }
                let mut buf = vec![0u8; 1024];
                let n_bytes = {
                    let mut rx_stream = self.rx_stream.lock().unwrap();
                    rx_stream.read(&mut buf)?
                };
                {
                    let mut buffer = self.buffer.lock().unwrap();
                    if buffer.len() > 65536 {
                        buffer.clear();
                    }
                    buffer.extend(buf.iter().take(n_bytes));
                }
            }
        }

        #[cfg(not(feature = "serial"))]
        {
            Err(Error::new(
                ErrorKind::NotConnected,
                "Serial port devices are not supported.",
            ))
        }
    }

    #[allow(unused_variables)]
    pub(crate) fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        #[cfg(feature = "serial")]
        {
            if self.is_shutdown.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "TNC is shut down",
                ));
            }
            let mut tx_stream = self.tx_stream.lock().unwrap();
            // 0x00 is the KISS command byte, which is two nybbles
            // port = 0
            // command = 0 (all following bytes are a data frame to transmit)
            tx_stream.write_all(&[FEND, 0x00])?;
            tx_stream.write_all(frame)?;
            tx_stream.write_all(&[FEND])?;
            tx_stream.flush()?;
            Ok(())
        }

        #[cfg(not(feature = "serial"))]
        {
            Err(Error::new(
                ErrorKind::NotConnected,
                "Serial port devices are not supported.",
            ))
        }
    }

    pub(crate) fn shutdown(&self) {
        if !self.is_shutdown.load(Ordering::SeqCst) {
            self.is_shutdown.store(true, Ordering::SeqCst);
        }
    }
}

impl Drop for SerialKissInterface {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn make_frame_from_buffer(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut possible_frame = Vec::new();

    enum Scan {
        LookingForStartMarker,
        Data,
        Escaped,
    }
    let mut state = Scan::LookingForStartMarker;
    let mut final_idx = 0;

    // Check for possible frame read-only until we know we have a complete frame
    // If we take one out, clear out buffer up to the final index
    for (idx, &c) in buffer.iter().enumerate() {
        match state {
            Scan::LookingForStartMarker => {
                if c == FEND {
                    state = Scan::Data;
                }
            }
            Scan::Data => {
                if c == FEND {
                    if !possible_frame.is_empty() {
                        // Successfully read a non-zero-length frame
                        final_idx = idx;
                        break;
                    }
                } else if c == FESC {
                    state = Scan::Escaped;
                } else {
                    possible_frame.push(c);
                }
            }
            Scan::Escaped => {
                if c == TFEND {
                    possible_frame.push(FEND);
                } else if c == TFESC {
                    possible_frame.push(FESC);
                } else if c == FEND && !possible_frame.is_empty() {
                    // Successfully read a non-zero-length frame
                    final_idx = idx;
                    break;
                }
                state = Scan::Data;
            }
        }
    }

    match final_idx {
        0 => {
            // Clear out old leading junk if the buffer is getting too full and no frame starts
            if buffer.len() > 65536 {
                buffer.clear();
            }
            None
        }
        n => {
            // Drain everything up to 'n', leaving the FEND at index 'n' in the buffer
            buffer.drain(0..n);
            Some(possible_frame)
        }
    }
}

#[cfg(test)]
#[path = "kiss_tests.rs"]
mod kiss_tests;
