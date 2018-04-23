#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::raw::c_char;
use std::ptr;
use libc::{sockaddr, sockaddr_in, c_int, AF_INET, AF_INET6};
use std::ffi::CString;


include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(ptr).to_str().ok().map(|x| x.to_owned()) }
    }
}

unsafe fn sockaddr_to_socketaddress(sa: *mut sockaddr) -> Result<SocketAddr, String> {
    if sa.is_null() {
        return Err(format!("Is NULL!"));
    }
    match (*sa).sa_family as c_int {
        AF_INET => {
            let sin: &sockaddr_in = mem::transmute(sa);
            let ip_parts: [u8; 4] = mem::transmute(sin.sin_addr);
            Ok(SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::new(
                    ip_parts[0],
                    ip_parts[1],
                    ip_parts[2],
                    ip_parts[3],
                ), u16::from_be(sin.sin_port))))
        }
        AF_INET6 => {
            Err(format!("Ipv6 not support"))
        }
        _ => {
            Err(format!("sa_family {} not support", (*sa).sa_family))
        }
    }
}

unsafe fn parse_pcap_addr_t(addrs: *mut pcap_addr_t) -> Vec<Address> {
    let mut addresses = Vec::new();
    let mut it = addrs;
    while !it.is_null() {
        let curr_addr = *it;
        sockaddr_to_socketaddress(curr_addr.addr).ok().map(|addr|
            addresses.push(Address {
                addr,
                netmask: sockaddr_to_socketaddress(curr_addr.netmask).ok(),
                broadaddr: sockaddr_to_socketaddress(curr_addr.broadaddr).ok(),
                dstaddr: sockaddr_to_socketaddress(curr_addr.dstaddr).ok(),
            })
        );
        it = curr_addr.next;
    }
    addresses
}

unsafe fn parse_pcap_if_t(devs: *mut pcap_if_t) -> Vec<Device> {
    let mut devices = Vec::new();
    let mut it = devs;
    while !it.is_null() {
        let curr = &*it;
        let device = Device {
            name: cstr_to_string(curr.name).unwrap(),
            description: cstr_to_string(curr.description),
            addresses: parse_pcap_addr_t(curr.addresses),
        };
        devices.push(device);
        it = curr.next;
    }
    devices
}

#[derive(Debug)]
pub struct Address {
    pub addr: SocketAddr,
    pub netmask: Option<SocketAddr>,
    pub broadaddr: Option<SocketAddr>,
    pub dstaddr: Option<SocketAddr>,
}

#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<Address>,
}

pub struct PacketCapture {
    handle: *mut pcap_t
}

impl PacketCapture {
    fn new(dev: Device) -> PacketCapture {
        let mut err = [0i8; PCAP_ERRBUF_SIZE as usize];
        unsafe {
            let handle = pcap_create(CString::new(dev.name).unwrap().as_ptr(), err.as_mut_ptr());
            PacketCapture {
                handle
            }
        }
    }

    fn activate(self) {
        unsafe {
            pcap_activate(self.handle);
        }
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        unsafe {
            pcap_close(self.handle);
        }
    }
}

fn _pcap_findalldevs() -> Vec<Device> {
    let mut devs: *mut pcap_if_t = ptr::null_mut();
    let mut err = [0i8; PCAP_ERRBUF_SIZE as usize];
    unsafe {
        pcap_findalldevs(&mut devs, err.as_mut_ptr());
        let devices = parse_pcap_if_t(devs);
        pcap_freealldevs(devs);
        return devices;
    };
}

fn _pcap_dispatch() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_findalldevs_works() {
        _pcap_findalldevs().iter().for_each(|d| println!("{:#?}", d));
    }
}
