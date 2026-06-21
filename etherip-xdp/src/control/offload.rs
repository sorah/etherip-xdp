//! Disable TX checksum offload on a virtual interface via the `SIOCETHTOOL`
//! ioctl (ports `pkg/xdptool/apply.go:disableTxOffload`).
//!
//! The veth peers don't benefit from checksum offload and it can confuse the
//! stack for XDP-redirected frames. We query `ETHTOOL_GFEATURES` to learn the
//! feature word count, then clear the IP/HW/IPv6 checksum bits via
//! `ETHTOOL_SFEATURES`. `nix` provides the ioctl wrapper so we avoid raw libc
//! calls; only the kernel struct layouts (absent from `libc`) are declared here.

const ETHTOOL_GFEATURES: u32 = 0x0000_003a;
const ETHTOOL_SFEATURES: u32 = 0x0000_003b;
const SIOCETHTOOL: nix::libc::c_ulong = 0x8946;

// NETIF_F_* feature bit indices (all in feature word 0). HW_CSUM supersedes the
// protocol-specific IP/IPv6 checksum bits, so clear all three.
const NETIF_F_IP_CSUM: u32 = 1;
const NETIF_F_HW_CSUM: u32 = 3;
const NETIF_F_IPV6_CSUM: u32 = 4;

const MAX_FEATURE_WORDS: usize = 8;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EthtoolGetFeaturesBlock {
    available: u32,
    requested: u32,
    active: u32,
    never_changed: u32,
}

#[repr(C)]
struct EthtoolGfeatures {
    cmd: u32,
    size: u32,
    features: [EthtoolGetFeaturesBlock; MAX_FEATURE_WORDS],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EthtoolSetFeaturesBlock {
    valid: u32,
    requested: u32,
}

#[repr(C)]
struct EthtoolSfeatures {
    cmd: u32,
    size: u32,
    features: [EthtoolSetFeaturesBlock; MAX_FEATURE_WORDS],
}

// struct ifreq with the ETHTOOL command pointer in the ifr_data union member.
// Laid out to the kernel's 40-byte size (name[16] + union[24]).
#[repr(C)]
struct Ifreq {
    ifr_name: [std::ffi::c_char; 16],
    ifr_data: *mut std::ffi::c_void,
    _pad: [u8; 16],
}

impl Ifreq {
    fn new(ifname: &str, data: *mut std::ffi::c_void) -> anyhow::Result<Self> {
        if ifname.len() >= 16 {
            anyhow::bail!("interface name {ifname:?} too long");
        }
        // SAFETY: `Ifreq` is a `#[repr(C)]` plain-data struct (a byte array, a
        // raw pointer, and padding); an all-zero bit pattern is a valid, inert
        // value (empty name, null `ifr_data`). The real fields are set below
        // before the struct is used.
        let mut ifr: Ifreq = unsafe { core::mem::zeroed() };
        for (dst, &src) in ifr.ifr_name.iter_mut().zip(ifname.as_bytes()) {
            *dst = src as std::ffi::c_char;
        }
        ifr.ifr_data = data;
        Ok(ifr)
    }
}

nix::ioctl_readwrite_bad!(siocethtool, SIOCETHTOOL, Ifreq);

/// Disable TX IP/IPv6/HW checksum offload on `ifname`. Requires `CAP_NET_ADMIN`.
pub fn disable_tx_offload(ifname: &str) -> anyhow::Result<()> {
    let fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::empty(),
        None,
    )
    .map_err(|e| anyhow::anyhow!("open ethtool socket: {e}"))?;

    // 1) Query the number of feature words.
    let mut g = EthtoolGfeatures {
        cmd: ETHTOOL_GFEATURES,
        size: MAX_FEATURE_WORDS as u32,
        features: [EthtoolGetFeaturesBlock::default(); MAX_FEATURE_WORDS],
    };
    let mut ifr = Ifreq::new(ifname, (&mut g as *mut EthtoolGfeatures).cast())?;
    // SAFETY: `fd` is a live AF_INET socket; `ifr` is a correctly-sized `Ifreq`
    // whose `ifr_data` points at the live, correctly-sized `g` buffer. Both
    // outlive the call. SIOCETHTOOL/ETHTOOL_GFEATURES reads into `g`.
    unsafe { siocethtool(std::os::fd::AsRawFd::as_raw_fd(&fd), &mut ifr) }
        .map_err(|e| anyhow::anyhow!("ETHTOOL_GFEATURES on {ifname}: {e}"))?;
    let words = (g.size as usize).min(MAX_FEATURE_WORDS);

    // 2) Clear the checksum bits in feature word 0.
    let mut s = EthtoolSfeatures {
        cmd: ETHTOOL_SFEATURES,
        size: words as u32,
        features: [EthtoolSetFeaturesBlock::default(); MAX_FEATURE_WORDS],
    };
    s.features[0].valid =
        (1 << NETIF_F_IP_CSUM) | (1 << NETIF_F_HW_CSUM) | (1 << NETIF_F_IPV6_CSUM);
    s.features[0].requested = 0;
    let mut ifr = Ifreq::new(ifname, (&mut s as *mut EthtoolSfeatures).cast())?;
    // SAFETY: as above — `fd` is live and `ifr.ifr_data` points at the live `s`
    // buffer; SIOCETHTOOL/ETHTOOL_SFEATURES applies the requested feature bits.
    unsafe { siocethtool(std::os::fd::AsRawFd::as_raw_fd(&fd), &mut ifr) }
        .map_err(|e| anyhow::anyhow!("ETHTOOL_SFEATURES on {ifname}: {e}"))?;

    Ok(())
}
