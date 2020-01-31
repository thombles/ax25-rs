use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{self, Error};
use std::mem;

use libc::{
    c_char, c_int, c_ulong, c_void, close, recvfrom, sendto, sockaddr, sockaddr_ll, socket,
    socklen_t, AF_AX25, AF_PACKET, SOCK_RAW,
};

const ETH_P_AX25: u16 = 0x0002; // from if_ether.h for SOCK_RAW
const SIOCGIFHWADDR: c_ulong = 0x8927; // from sockios.h in the linux kernel
const SIOCGIFINDEX: c_ulong = 0x8933;

/// An active AX.25 network interface, e.g. "ax0"
pub struct NetDev {
    pub name: String,
    pub ifindex: i32,
}

/// An open socket for sending and receiving AX.25 frames
pub struct Ax25RawSocket {
    fd: i32,
}

impl Ax25RawSocket {
    /// Create a new socket for sending and receiving raw AX.25 frames. This requires root or CAP_NET_ADMIN.
    pub fn new() -> io::Result<Ax25RawSocket> {
        match unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_AX25.to_be() as i32) } {
            -1 => Err(Error::last_os_error()),
            fd => Ok(Ax25RawSocket { fd }),
        }
    }

    /// Close an open AX.25 socket.
    pub fn close(&mut self) -> io::Result<()> {
        match unsafe { close(self.fd) } {
            -1 => Err(Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Find all AX.25 interfaces on the system
    pub fn list_ax25_interfaces(&self) -> io::Result<Vec<NetDev>> {
        let dev_file = File::open("/proc/net/dev")?;
        let mut devices: Vec<NetDev> = Vec::new();
        let reader = BufReader::new(dev_file);
        let lines = reader.lines();
        for l in lines.skip(2) {
            match l {
                Ok(line) => {
                    let device_name = line.trim().split(":").next().unwrap();
                    if let Some(net_dev) = get_ax25_netdev(&device_name, self.fd) {
                        devices.push(net_dev);
                    }
                }
                Err(_) => (),
            }
        }
        Ok(devices)
    }

    /// Send a frame to a particular interface, specified by its index
    pub fn send_frame(&self, frame: &[u8], ifindex: i32) -> io::Result<()> {
        // The Linux interface demands a single null byte prefix on the actual packet
        let mut prefixed_frame: Vec<u8> = Vec::with_capacity(frame.len() + 1);
        prefixed_frame.push(0);
        prefixed_frame.extend(frame.iter().cloned());

        let sa = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_AX25.to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        match unsafe {
            let sa_ptr = mem::transmute::<*const sockaddr_ll, *const sockaddr>(&sa);
            sendto(
                self.fd,
                prefixed_frame.as_ptr() as *const c_void,
                prefixed_frame.len(),
                0,
                sa_ptr,
                mem::size_of_val(&sa) as socklen_t,
            )
        } {
            -1 => Err(Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Block to receive an incoming AX.25 frame from any interface
    pub fn receive_frame(&self) -> io::Result<Vec<u8>> {
        let mut buf: [u8; 1024] = [0; 1024];
        // Not sure we need the address but it might come in handy someday
        let mut addr_struct: sockaddr_ll = unsafe { mem::zeroed() };
        let len: usize;
        unsafe {
            let sa_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut addr_struct);
            let mut sa_in_sz: socklen_t = mem::size_of::<sockaddr_ll>() as socklen_t;
            len = match recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                sa_ptr,
                &mut sa_in_sz,
            ) {
                -1 => return Err(Error::last_os_error()),
                len => len as usize,
            };
        }
        let ref valid_buf = buf[0..len];

        // In practice AF_PACKET gives us one leading one null byte
        // These are unhelpful so we will skip all leading null bytes
        let filtered: Vec<u8> = valid_buf
            .into_iter()
            .skip_while(|&c| *c == 0)
            .cloned()
            .collect();
        Ok(filtered)
    }
}

fn get_ax25_netdev(name: &str, fd: i32) -> Option<NetDev> {
    let mut req = ifreq::default();
    let if_name = name.to_owned();
    for (d, s) in req.ifr_name.iter_mut().zip(if_name.as_bytes()) {
        *d = *s as c_char;
    }

    if unsafe { ioctl(fd, SIOCGIFHWADDR, &mut req) } == -1 {
        return None;
    }
    if req.data.address_family() as i32 != AF_AX25 {
        return None;
    }
    let hw_addr = match req.data.ax25_address() {
        Some(addr) => addr,
        None => return None,
    };

    if unsafe { ioctl(fd, SIOCGIFINDEX, &mut req) } == -1 {
        return None;
    }
    let ifindex = req.data.ifindex();

    Some(NetDev {
        name: hw_addr,
        ifindex,
    })
}

extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ifreq: *mut ifreq) -> c_int;
}

#[repr(C)]
struct ifreq {
    ifr_name: [c_char; 16],
    data: ifreq_union,
}

impl Default for ifreq {
    fn default() -> ifreq {
        ifreq {
            ifr_name: [0; 16],
            data: ifreq_union::default(),
        }
    }
}

#[repr(C)]
struct ifreq_union {
    data: [u8; 24],
}

impl Default for ifreq_union {
    fn default() -> ifreq_union {
        ifreq_union { data: [0; 24] }
    }
}

impl ifreq_union {
    fn ifindex(&self) -> c_int {
        c_int::from_be(
            ((self.data[0] as c_int) << 24)
                + ((self.data[1] as c_int) << 16)
                + ((self.data[2] as c_int) << 8)
                + (self.data[3] as c_int),
        )
    }

    fn address_family(&self) -> u16 {
        u16::from_be(((self.data[0] as u16) << 8) + (self.data[1] as u16))
    }

    fn ax25_address(&self) -> Option<String> {
        let mut addr_utf8: Vec<u8> = self.data[2..8]
            .iter()
            .rev()
            .map(|&c| c >> 1)
            .skip_while(|&c| c == 0)
            .collect::<Vec<u8>>();
        addr_utf8.reverse();
        let ssid = (self.data[8] >> 1) & 0x0f;
        if let Some(addr) = String::from_utf8(addr_utf8).ok() {
            return Some(format!("{}-{}", addr, ssid));
        }
        None
    }
}
