use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_long};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use pcap::{Capture, Device};
use etherparse::{SlicedPacket, TransportSlice, NetSlice};

#[repr(C)]
pub struct PacketEventC {
    pub timestamp_sec: c_long,
    pub timestamp_usec: c_long,
    pub source_ip: *mut c_char,
    pub dest_ip: *mut c_char,
    pub protocol: *mut c_char,
    pub length: c_int,
    pub info: *mut c_char,
}

pub type PacketCallback = extern "C" fn(*mut PacketEventC);

static STOP_FLAG: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
pub extern "C" fn start_sniffing(
    device_name: *const c_char,
    callback: PacketCallback,
) -> c_int {
    if device_name.is_null() {
        return -1;
    }

    let dev_name = unsafe {
        match CStr::from_ptr(device_name).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -2,
        }
    };

    STOP_FLAG.store(false, Ordering::Relaxed);

    thread::spawn(move || {
        let mut cap = match Capture::from_device(dev_name.as_str()) {
            Ok(d) => match d.promisc(true).snaplen(65535).timeout(100).open() {
                Ok(c) => c,
                Err(_) => return,
            },
            Err(_) => return,
        };

        while !STOP_FLAG.load(Ordering::Relaxed) {
             if let Ok(packet) = cap.next_packet() {
                 let mut src_ip = String::from("Unknown");
                 let mut dst_ip = String::from("Unknown");
                 let mut proto = String::from("Unknown");
                 let mut info = String::from("");

                 if let Ok(sliced) = SlicedPacket::from_ethernet(&packet.data) {
                     if let Some(net) = sliced.net {
                         match net {
                             NetSlice::Ipv4(v4) => {
                                 let src = v4.header().source();
                                 let dst = v4.header().destination();
                                 src_ip = format!("{}.{}.{}.{}", src[0], src[1], src[2], src[3]);
                                 dst_ip = format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]);
                             }
                             NetSlice::Ipv6(_v6) => {
                                 src_ip = "IPv6".to_string();
                                 dst_ip = "IPv6".to_string();
                             }
                             NetSlice::Arp(_) => {}
                         }
                     }

                     if let Some(transport) = sliced.transport {
                         match transport {
                             TransportSlice::Tcp(tcp) => {
                                 proto = String::from("TCP");
                                 info = format!(
                                     "{} -> {} Seq={} Ack={} Win={}",
                                     tcp.source_port(),
                                     tcp.destination_port(),
                                     tcp.sequence_number(),
                                     tcp.acknowledgment_number(),
                                     tcp.window_size()
                                 );
                             }
                             TransportSlice::Udp(udp) => {
                                 proto = String::from("UDP");
                                 info = format!(
                                     "{} -> {} Len={}",
                                     udp.source_port(),
                                     udp.destination_port(),
                                     udp.length()
                                 );
                             }
                             TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                                 proto = String::from("ICMP");
                             }
                         }
                     }
                 }

                 let event = Box::new(PacketEventC {
                     timestamp_sec: packet.header.ts.tv_sec as c_long,
                     timestamp_usec: packet.header.ts.tv_usec as c_long,
                     source_ip: CString::new(src_ip).unwrap().into_raw(),
                     dest_ip: CString::new(dst_ip).unwrap().into_raw(),
                     protocol: CString::new(proto).unwrap().into_raw(),
                     length: packet.header.len as c_int,
                     info: CString::new(info).unwrap().into_raw(),
                 });

                 callback(Box::into_raw(event));
             }
        }
    });

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn stop_sniffing() {
    STOP_FLAG.store(true, Ordering::Relaxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn free_packet_event(event: *mut PacketEventC) {
    if event.is_null() {
        return;
    }

    unsafe {
        let f = Box::from_raw(event);
        if !f.source_ip.is_null() {
            let _ = CString::from_raw(f.source_ip);
        }
        if !f.dest_ip.is_null() {
            let _ = CString::from_raw(f.dest_ip);
        }
        if !f.protocol.is_null() {
            let _ = CString::from_raw(f.protocol);
        }
        if !f.info.is_null() {
            let _ = CString::from_raw(f.info);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn get_default_device() -> *mut c_char {
    if let Ok(Some(dev)) = Device::lookup() {
        if let Ok(c_str) = CString::new(dev.name) {
             return c_str.into_raw();
        }
    }
    std::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { let _ = CString::from_raw(s); }
}
