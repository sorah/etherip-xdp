//! Addressing and discovery of the per-device daemon sockets and the manager
//! socket under the shared runtime directory.

/// Runtime directory shared by all daemons and the manager (systemd
/// `RuntimeDirectory=etherip-xdp`).
pub const RUNTIME_DIR: &str = "/run/etherip-xdp";

/// The varlink interface name, also used verbatim as the socket file name (per
/// systemd convention, e.g. `io.systemd.Resolve`).
pub const INTERFACE: &str = "co.0w0.etheripxdp.Management";

/// Path of a per-device daemon's varlink socket:
/// `<RUNTIME_DIR>/<device>/<INTERFACE>`.
pub fn socket_path(device: &str) -> std::path::PathBuf {
    std::path::Path::new(RUNTIME_DIR)
        .join(device)
        .join(INTERFACE)
}

/// varlink `unix:` address for a per-device daemon socket.
pub fn socket_address(device: &str) -> String {
    format!("unix:{}", socket_path(device).display())
}

/// Path of the manager's host-wide varlink socket: `<RUNTIME_DIR>/<INTERFACE>`
/// (a top-level file, distinct from the per-device subdirectory sockets).
pub fn manager_socket_path() -> std::path::PathBuf {
    std::path::Path::new(RUNTIME_DIR).join(INTERFACE)
}

/// varlink `unix:` address for the manager socket.
pub fn manager_socket_address() -> String {
    format!("unix:{}", manager_socket_path().display())
}

/// Discover every running per-device daemon socket under [`RUNTIME_DIR`],
/// returning `(device, socket_path)` pairs sorted by device name.
pub fn discover() -> Vec<(String, std::path::PathBuf)> {
    discover_in(std::path::Path::new(RUNTIME_DIR))
}

/// Discover daemon sockets under `dir`. A daemon socket lives at
/// `<dir>/<device>/<INTERFACE>`, so only immediate subdirectories that contain
/// the interface socket are returned — the top-level manager socket file and
/// directories without the socket (e.g. `interfaces.d/`) are skipped. Sorted by
/// device for stable output; a missing/unreadable `dir` yields an empty list.
fn discover_in(dir: &std::path::Path) -> Vec<(String, std::path::PathBuf)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Ok(device) = entry.file_name().into_string() else {
            continue;
        };
        let sock = entry.path().join(INTERFACE);
        if std::fs::symlink_metadata(&sock).is_ok() {
            out.push((device, sock));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[cfg(test)]
mod tests {
    fn touch(path: &std::path::Path) {
        std::fs::write(path, b"").unwrap();
    }

    #[test]
    fn socket_paths_are_under_runtime_dir() {
        assert_eq!(
            super::socket_path("eth1"),
            std::path::PathBuf::from("/run/etherip-xdp/eth1/co.0w0.etheripxdp.Management")
        );
        assert_eq!(
            super::socket_address("eth1"),
            "unix:/run/etherip-xdp/eth1/co.0w0.etheripxdp.Management"
        );
        assert_eq!(
            super::manager_socket_path(),
            std::path::PathBuf::from("/run/etherip-xdp/co.0w0.etheripxdp.Management")
        );
        assert_eq!(
            super::manager_socket_address(),
            "unix:/run/etherip-xdp/co.0w0.etheripxdp.Management"
        );
    }

    #[test]
    fn discover_returns_only_device_subdirs_with_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Two daemons, each with its interface socket (faked as a plain file).
        for dev in ["wan0", "eth1"] {
            let d = root.join(dev);
            std::fs::create_dir(&d).unwrap();
            touch(&d.join(super::INTERFACE));
        }
        // A subdirectory without the socket -> skipped.
        std::fs::create_dir(root.join("interfaces.d")).unwrap();
        // The manager socket as a top-level file -> skipped (not a directory).
        touch(&root.join(super::INTERFACE));

        let found = super::discover_in(root);
        let devices: Vec<&str> = found.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(devices, vec!["eth1", "wan0"]); // sorted by device
        assert_eq!(found[0].1, root.join("eth1").join(super::INTERFACE));
    }

    #[test]
    fn discover_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(super::discover_in(&dir.path().join("does-not-exist")).is_empty());
    }
}
