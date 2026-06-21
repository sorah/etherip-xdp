//! Shared library for the `etherip-xdp` daemon, the `etherip-xdp-manager` proxy,
//! and the `etheripctl` CLI.
//!
//! - [`manage`] is the management plane: the generated
//!   `co.0w0.etheripxdp.Management` varlink bindings, the manager proxy, and the
//!   ctl CLI. It does not depend on the daemon internals.
//! - [`control`] is the per-daemon control plane: the modules that drive the
//!   eBPF data path (load/attach, tunnel lifecycle, netlink, resolution), the
//!   daemon run loop, and the embedded varlink server (with its actor-channel
//!   bridge) that implements the management interface against the live manager.
//!
//! `control` depends on [`manage::generated`]; `manage` does not depend on
//! `control`.
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod control;
pub mod manage;
