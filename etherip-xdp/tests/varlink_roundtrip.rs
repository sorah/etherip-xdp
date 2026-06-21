//! End-to-end round-trip of the generated `co.0w0.etheripxdp.Management` server
//! and client over a real unix socket: a stub interface replies with one
//! `InterfaceStatus`, the generated async client connects and reads it back.
//! Exercises `AsyncVarlinkService` / `listen_async` / `AsyncConnection` wiring
//! that the pure unit tests cannot.

struct Stub;

#[async_trait::async_trait]
impl etherip_xdp::manage::generated::VarlinkInterface for Stub {
    async fn list(
        &self,
        call: &mut dyn etherip_xdp::manage::generated::Call_List,
    ) -> varlink::Result<()> {
        call.reply(vec![etherip_xdp::manage::generated::InterfaceStatus {
            external: etherip_xdp::manage::generated::ExternalInterface {
                name: "test0".to_string(),
                ifindex: 42,
                mac: "02:00:00:00:00:01".to_string(),
                mtu: 1500,
            },
            counters: Vec::new(),
            tunnels: Vec::new(),
        }])
    }
}

#[tokio::test]
async fn list_round_trips_over_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("co.0w0.etheripxdp.Management");
    let address = format!("unix:{}", sock.display());

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler = std::sync::Arc::new(etherip_xdp::manage::generated::new(std::sync::Arc::new(
        Stub,
    )));
    let service = std::sync::Arc::new(varlink::AsyncVarlinkService::new(
        "co.0w0",
        "test",
        "0",
        "https://github.com/sorah/etherip-xdp",
        vec![handler],
    ));
    let config = varlink::ListenAsyncConfig {
        idle_timeout: std::time::Duration::from_millis(200),
        stop_listening: Some(stop.clone()),
    };
    let server_address = address.clone();
    let server =
        tokio::spawn(async move { varlink::listen_async(service, server_address, &config).await });

    // Wait for the listener to bind the socket.
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(sock.exists(), "server never bound the socket");

    let connection = varlink::AsyncConnection::with_address(address)
        .await
        .expect("connect");
    let client = etherip_xdp::manage::generated::VarlinkClient::new(connection);
    let reply = {
        use etherip_xdp::manage::generated::VarlinkClientInterface as _;
        client.list().call().await.expect("list call")
    };

    assert_eq!(reply.interfaces.len(), 1);
    assert_eq!(reply.interfaces[0].external.name, "test0");
    assert_eq!(reply.interfaces[0].external.ifindex, 42);

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = server.await;
}
