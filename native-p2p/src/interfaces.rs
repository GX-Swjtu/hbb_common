use super::candidates::Interface;
use anyhow::Result;

#[cfg(target_os = "windows")]
pub fn physical() -> Result<Vec<Interface>> {
    use windows_sys::Win32::{
        Foundation::ERROR_BUFFER_OVERFLOW,
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        Networking::WinSock::{AF_INET, SOCKADDR_IN},
    };
    let mut bytes = 16_384u32;
    for _ in 0..3 {
        anyhow::ensure!(bytes <= 1024 * 1024, "adapter buffer limit");
        // u64 backing preserves the alignment required by the adapter structures.
        let mut storage = vec![0u64; (bytes as usize + 7) / 8];
        let head = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe { GetAdaptersAddresses(AF_INET as u32,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            std::ptr::null(), head, &mut bytes) };
        if result == ERROR_BUFFER_OVERFLOW { continue; }
        anyhow::ensure!(result == 0, "adapter enumeration failed: {result}");
        let mut out = Vec::new();
        let mut current = head;
        // All pointers are supplied by Windows and remain within the live backing buffer.
        unsafe {
            while let Some(adapter) = current.as_ref() {
                current = adapter.Next;
                if adapter.OperStatus != IfOperStatusUp || !matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211) { continue; }
                let mut row: MIB_IF_ROW2 = std::mem::zeroed();
                row.InterfaceLuid = adapter.Luid;
                // HardwareInterface is bit 0 of MIB_IF_ROW2.InterfaceAndOperStatusFlags.
                if GetIfEntry2(&mut row) != 0 || row.InterfaceAndOperStatusFlags._bitfield & 1 == 0 { continue; }
                let mut address = adapter.FirstUnicastAddress;
                while let Some(unicast) = address.as_ref() {
                    address = unicast.Next;
                    let socket = unicast.Address.lpSockaddr;
                    if socket.is_null() || (*socket).sa_family != AF_INET || unicast.Address.iSockaddrLength < std::mem::size_of::<SOCKADDR_IN>() as i32 { continue; }
                    let v4 = &*socket.cast::<SOCKADDR_IN>();
                    out.push(Interface { address: v4.sin_addr.S_un.S_addr.to_ne_bytes().into(), prefix: unicast.OnLinkPrefixLength });
                    if out.len() == crate::MAX_LOCAL { return Ok(out); }
                }
            }
        }
        return Ok(out);
    }
    anyhow::bail!("adapter list changed repeatedly")
}

#[cfg(target_os = "linux")]
pub fn physical() -> Result<Vec<Interface>> {
    use std::{ffi::CStr, net::Ipv4Addr};
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses { fn drop(&mut self) { unsafe { libc::freeifaddrs(self.0); } } }
    let mut head = std::ptr::null_mut();
    anyhow::ensure!(unsafe { libc::getifaddrs(&mut head) } == 0, "interface enumeration failed: {}", std::io::Error::last_os_error());
    let addresses = Addresses(head);
    let mut current = addresses.0;
    let mut out = Vec::new();
    // getifaddrs owns the linked list until Addresses drops, including address/netmask.
    unsafe {
        while let Some(i) = current.as_ref() {
            current = i.ifa_next;
            if i.ifa_addr.is_null() || i.ifa_netmask.is_null() || i.ifa_name.is_null()
                || (*i.ifa_addr).sa_family != libc::AF_INET as u16
                || i.ifa_flags & libc::IFF_UP as u32 == 0 || i.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 { continue; }
            let name = CStr::from_ptr(i.ifa_name).to_string_lossy();
            if !std::path::Path::new("/sys/class/net").join(name.as_ref()).join("device").exists() { continue; }
            let address = &*i.ifa_addr.cast::<libc::sockaddr_in>();
            let mask = &*i.ifa_netmask.cast::<libc::sockaddr_in>();
            let mask = u32::from_be(mask.sin_addr.s_addr);
            let prefix = mask.leading_ones();
            if prefix == 0 || mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) { continue; }
            out.push(Interface { address: Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()), prefix: prefix as u8 });
            if out.len() == crate::MAX_LOCAL { break; }
        }
    }
    Ok(out)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn physical() -> Result<Vec<Interface>> { Ok(Vec::new()) }
