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
use libc::{ sockaddr, sockaddr_in, c_int, AF_INET, AF_INET6 };

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));



#[derive(Debug)]
pub struct NetworkAddr {
    pub addr: SocketAddr,
    pub netmask: Option<SocketAddr>,
    pub broadaddr: Option<SocketAddr>,
    pub dstaddr: Option<SocketAddr>,
}

#[derive(Debug)]
pub struct NetworkDevice {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<NetworkAddr>,
}

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

unsafe fn parse_pcap_addr_t(addrs: *mut pcap_addr_t) -> Vec<NetworkAddr> {
    let mut addresses = Vec::new();
    let mut it = addrs;
    while !it.is_null() {
        let curr_addr = *it;
        sockaddr_to_socketaddress(curr_addr.addr).ok().map(|addr|
            addresses.push(NetworkAddr {
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

unsafe fn parse_pcap_if_t(devs: *mut pcap_if_t) -> Vec<NetworkDevice> {
    let mut devices = Vec::new();
    let mut it = devs;
    while !it.is_null() {
        let curr = &*it;
        let device = NetworkDevice {
            name: cstr_to_string(curr.name).unwrap(),
            description: cstr_to_string(curr.description),
            addresses: parse_pcap_addr_t(curr.addresses),
        };
        devices.push(device);
        it = curr.next;
    }
    devices
}

fn _pcap_findalldevs() -> Vec<NetworkDevice> {
    let mut devs: *mut pcap_if_t = ptr::null_mut();
    let mut err = [0i8; 256];
    unsafe {
        pcap_findalldevs(&mut devs, err.as_mut_ptr());
        return parse_pcap_if_t(devs);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcap_findalldevs_works() {
        _pcap_findalldevs().iter().for_each(|d| println!("{:#?}", d));
        assert_eq!(2 + 2, 4);
    }
}
