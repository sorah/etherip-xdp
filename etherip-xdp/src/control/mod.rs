//! Per-daemon control plane: the modules that drive the eBPF data path (load,
//! attach, tunnel lifecycle, netlink, next-hop resolution) and the daemon run
//! loop ([`daemon`]).

pub mod bpf;
pub mod config;
pub mod daemon;
pub mod netlink;
pub mod netns;
pub mod offload;
pub mod resolver;
pub mod tunnel;
