//! `etheripctl`: CLI to inspect etherip-xdp tunnels via the host-wide manager.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Warn)
        .parse_default_env()
        .init();
    etherip_xdp::manage::ctl::run().await
}
