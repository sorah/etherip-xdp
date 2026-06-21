//! `etheripctl` command logic: connect to the manager (or a specific socket),
//! call `List`, and render the host-wide status or one tunnel's detail.

#[derive(clap::Parser)]
#[command(
    name = "etheripctl",
    version,
    about = "Inspect etherip-xdp tunnels via the manager"
)]
struct Cli {
    /// Connect to this varlink socket instead of the manager (e.g. a single
    /// daemon's socket, for debugging).
    #[arg(long, global = true)]
    socket: Option<std::path::PathBuf>,

    /// Limit output to this external interface (device).
    #[arg(long, short = 'i', global = true)]
    interface: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// List every interface and its tunnels (the default).
    List,
    /// Show full detail for one tunnel.
    #[command(alias = "status")]
    Show {
        /// Tunnel name.
        tunnel: String,
    },
}

/// Parse arguments, query the manager, and print the result.
pub async fn run() -> anyhow::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    let interfaces = fetch(&cli).await?;
    match cli.command.unwrap_or(Command::List) {
        Command::List => print!("{}", crate::manage::render::render_interfaces(&interfaces)),
        Command::Show { tunnel } => {
            for iface in &interfaces {
                if let Some(t) = iface.tunnels.iter().find(|t| t.name == tunnel) {
                    print!("{}", crate::manage::render::render_detail(iface, t));
                    return Ok(());
                }
            }
            anyhow::bail!("tunnel {tunnel:?} not found");
        }
    }
    Ok(())
}

/// Turn a connect failure into an actionable message — chiefly so a permission
/// error on the 0660 control socket isn't reported as "not running".
fn connect_error(cli: &Cli, e: &varlink::Error) -> String {
    let path = match &cli.socket {
        Some(p) => p.clone(),
        None => crate::manage::discovery::manager_socket_path(),
    };
    match e.kind() {
        varlink::ErrorKind::Io(std::io::ErrorKind::PermissionDenied) => format!(
            "permission denied on {}: run etheripctl as root or as a member of the \
             etherip-xdp-sock group",
            path.display()
        ),
        varlink::ErrorKind::Io(std::io::ErrorKind::NotFound) if cli.socket.is_none() => format!(
            "etherip-xdp-manager not running: no socket at {} \
             (systemctl enable --now etherip-xdp-manager.socket)",
            path.display()
        ),
        varlink::ErrorKind::Io(std::io::ErrorKind::NotFound) => {
            format!(
                "no socket at {}: is its etherip-xdp daemon running?",
                path.display()
            )
        }
        varlink::ErrorKind::Io(std::io::ErrorKind::ConnectionRefused) => format!(
            "{} is not accepting connections (the service may be unhealthy)",
            path.display()
        ),
        _ => format!("connect to {}: {e:#}", path.display()),
    }
}

/// Connect and fetch the interfaces, applying the `--interface` filter.
async fn fetch(cli: &Cli) -> anyhow::Result<Vec<crate::manage::generated::InterfaceStatus>> {
    let address = match &cli.socket {
        Some(p) => format!("unix:{}", p.display()),
        None => crate::manage::discovery::manager_socket_address(),
    };

    let connection = match varlink::AsyncConnection::with_address(address.clone()).await {
        Ok(c) => c,
        Err(e) => anyhow::bail!("{}", connect_error(cli, &e)),
    };

    let client = crate::manage::generated::VarlinkClient::new(connection);
    let reply = {
        use crate::manage::generated::VarlinkClientInterface as _;
        client
            .list()
            .call()
            .await
            .map_err(|e| anyhow::anyhow!("List failed: {e:#}"))?
    };

    let mut interfaces = reply.interfaces;
    if let Some(device) = &cli.interface {
        interfaces.retain(|i| &i.external.name == device);
    }
    Ok(interfaces)
}
