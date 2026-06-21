//! Per-daemon control plane: the modules that drive the eBPF data path (load,
//! attach, tunnel lifecycle, netlink, next-hop resolution), the daemon run loop
//! ([`daemon`]), and the embedded varlink management server ([`server`]) with
//! its actor-channel bridge ([`types`]).
//!
//! [`server`] implements the [`crate::manage::generated`] interface by querying
//! the live tunnel manager; `manage` does not depend on `control`.

pub mod bpf;
pub mod config;
pub mod daemon;
pub mod netlink;
pub mod netns;
pub mod offload;
pub mod resolver;
pub mod server;
pub mod tunnel;
pub mod types;
