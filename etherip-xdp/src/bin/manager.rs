//! `etherip-xdp-manager`: a single host-wide varlink proxy that aggregates the
//! status of every running per-device `etherip-xdp` daemon. It is the well-known
//! endpoint `etheripctl` (and `varlinkctl`) connect to.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Translate SIGINT/SIGTERM into the listener's stop flag; the listener exits
    // within its accept idle-timeout once the flag is set.
    let signal_stop = stop.clone();
    tokio::spawn(async move {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("manager: install SIGTERM handler: {e}");
                    return;
                }
            };
        let mut sigint =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("manager: install SIGINT handler: {e}");
                    return;
                }
            };
        tokio::select! {
            _ = sigterm.recv() => log::info!("SIGTERM: shutting down"),
            _ = sigint.recv() => log::info!("SIGINT: shutting down"),
        }
        signal_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    log::info!(
        "etherip-xdp-manager ready on {}",
        etherip_xdp::manage::discovery::manager_socket_path().display()
    );
    etherip_xdp::manage::proxy::serve_manager(stop).await;
    Ok(())
}
