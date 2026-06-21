//! Shared library for the `etherip-xdp` daemon (and, in later modules, the
//! `etherip-xdp-manager` proxy and the `etheripctl` CLI).
//!
//! [`control`] is the per-daemon control plane: the modules that drive the eBPF
//! data path (load/attach, tunnel lifecycle, netlink, resolution) and the daemon
//! run loop. The thin `etherip-xdp` binary just calls [`control::daemon::run`].
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod control;
