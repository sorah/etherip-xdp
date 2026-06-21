//! The `etherip-xdp-manager` proxy: a varlink server that, on `List`, fans out
//! to every per-device daemon socket (as a varlink client) and merges their
//! single-interface replies into the host-wide aggregate. The wire interface is
//! identical to a daemon's, so the manager is a transparent aggregator.

/// Serves the host-wide aggregate. Stateless — discovery happens per request.
pub struct ManagerImpl;

#[async_trait::async_trait]
impl crate::manage::generated::VarlinkInterface for ManagerImpl {
    async fn list(
        &self,
        call: &mut dyn crate::manage::generated::Call_List,
    ) -> varlink::Result<()> {
        call.reply(fanout().await)
    }
}

/// Discover every running daemon socket and query each concurrently, returning
/// the merged set of interfaces. A daemon that fails to connect or reply is
/// skipped (logged), so one stale socket never fails the whole aggregate.
pub async fn fanout() -> Vec<crate::manage::generated::InterfaceStatus> {
    let sockets = crate::manage::discovery::discover();
    let queries = sockets
        .into_iter()
        .map(|(device, path)| async move { query_daemon(device, path).await });
    merge(futures_util::future::join_all(queries).await)
}

/// Query one daemon socket, returning its interfaces (always one element on
/// success) or an empty vec on any connect/call error.
async fn query_daemon(
    device: String,
    path: std::path::PathBuf,
) -> Vec<crate::manage::generated::InterfaceStatus> {
    use crate::manage::generated::VarlinkClientInterface as _;
    let address = format!("unix:{}", path.display());
    let connection = match varlink::AsyncConnection::with_address(address).await {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "manager: connect to {device} ({}) failed: {e:#}",
                path.display()
            );
            return Vec::new();
        }
    };
    let client = crate::manage::generated::VarlinkClient::new(connection);
    match client.list().call().await {
        Ok(reply) => reply.interfaces,
        Err(e) => {
            log::warn!("manager: List on {device} failed: {e:#}");
            Vec::new()
        }
    }
}

/// Flatten the per-daemon replies and sort by interface name for stable output.
/// Pure, so it is unit-tested without sockets.
fn merge(
    results: Vec<Vec<crate::manage::generated::InterfaceStatus>>,
) -> Vec<crate::manage::generated::InterfaceStatus> {
    let mut all: Vec<crate::manage::generated::InterfaceStatus> =
        results.into_iter().flatten().collect();
    all.sort_by(|a, b| a.external.name.cmp(&b.external.name));
    all
}

/// Run the manager's varlink server until `stop` is set. Adopts a
/// systemd-passed socket when socket-activated; otherwise self-binds the
/// host-wide manager socket under the runtime directory.
pub async fn serve_manager(stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let address = crate::manage::discovery::manager_socket_address();

    if std::env::var_os("LISTEN_FDS").is_none() {
        let path = crate::manage::discovery::manager_socket_path();
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            log::error!("manager: create {}: {e}", parent.display());
        }
        let _ = std::fs::remove_file(&path);
    }

    let handler = std::sync::Arc::new(crate::manage::generated::new(std::sync::Arc::new(
        ManagerImpl,
    )));
    let service = std::sync::Arc::new(varlink::AsyncVarlinkService::new(
        "co.0w0",
        "etherip-xdp-manager",
        env!("CARGO_PKG_VERSION"),
        "https://github.com/sorah/etherip-xdp",
        vec![handler],
    ));
    let config = varlink::ListenAsyncConfig {
        idle_timeout: std::time::Duration::from_secs(1),
        stop_listening: Some(stop),
    };
    if let Err(e) = varlink::listen_async(service, address.clone(), &config).await {
        log::error!("manager: varlink listener on {address} exited: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    fn iface(name: &str) -> crate::manage::generated::InterfaceStatus {
        crate::manage::generated::InterfaceStatus {
            external: crate::manage::generated::ExternalInterface {
                name: name.to_string(),
                ifindex: 1,
                mac: "02:00:00:00:00:01".to_string(),
                mtu: 1500,
            },
            counters: Vec::new(),
            tunnels: Vec::new(),
        }
    }

    #[test]
    fn merge_flattens_and_sorts_by_interface_name() {
        let results = vec![
            vec![iface("wan0")],
            vec![], // a daemon that errored
            vec![iface("eth1")],
        ];
        let merged = super::merge(results);
        let names: Vec<&str> = merged.iter().map(|i| i.external.name.as_str()).collect();
        assert_eq!(names, vec!["eth1", "wan0"]);
    }

    #[test]
    fn merge_empty_is_empty() {
        assert!(super::merge(vec![]).is_empty());
        assert!(super::merge(vec![vec![], vec![]]).is_empty());
    }
}
