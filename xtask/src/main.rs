//! etherip-xdp integration-test orchestrator (aya-style `cargo xtask`).
//!
//! Two subcommands under `integration-test`:
//!
//! * `local` — wires two network namespaces on the host with a veth "uplink"
//!   and runs the scenario in each (root required; uses the host kernel).
//! * `vm` — boots two `qemu-system-x86_64` guests connected by a `-netdev
//!   stream` UNIX socket (no host networking privileges) and runs the scenario
//!   in each, once per supplied kernel.
#![deny(clippy::undocumented_unsafe_blocks)]

mod build;
mod cpio;
mod deb;
mod local;
mod vm;

#[derive(clap::Parser)]
#[command(about = "etherip-xdp dev tasks")]
struct Xtask {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Build and run the end-to-end integration tests.
    IntegrationTest {
        #[command(subcommand)]
        env: Environment,
    },
}

#[derive(clap::Subcommand)]
enum Environment {
    /// Run on the host using two network namespaces (requires root).
    Local(local::Options),
    /// Run in two QEMU VMs connected by a `-netdev stream` socket.
    Vm(vm::Options),
}

fn main() -> anyhow::Result<()> {
    let xtask = <Xtask as clap::Parser>::parse();

    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| anyhow::anyhow!("cargo metadata: {e}"))?;
    let workspace_root = metadata.workspace_root.clone().into_std_path_buf();

    match xtask.command {
        Command::IntegrationTest { env } => match env {
            Environment::Local(opts) => local::run(opts, &workspace_root),
            Environment::Vm(opts) => vm::run(opts, &workspace_root),
        },
    }
}

/// Run a command, returning an error (with the command in context) on non-zero
/// exit.
pub(crate) fn exec(cmd: &mut std::process::Command) -> anyhow::Result<()> {
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("spawn {cmd:?}: {e}"))?;
    if !status.success() {
        anyhow::bail!("{cmd:?} failed: {status}");
    }
    Ok(())
}
