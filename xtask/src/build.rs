//! Build the harness binaries and collect their paths by crate-target name.

/// Build `packages` in release mode (optionally cross-compiled to `target`) and
/// return a map from binary name to its built path.
pub(crate) fn build(
    target: Option<&str>,
    packages: &[&str],
) -> anyhow::Result<std::collections::HashMap<String, std::path::PathBuf>> {
    let mut cmd = std::process::Command::new(std::env::var("CARGO").as_deref().unwrap_or("cargo"));
    cmd.args(["build", "--release", "--message-format=json"]);
    if let Some(target) = target {
        cmd.args(["--target", target]);
    }
    for p in packages {
        cmd.args(["--package", p]);
    }
    cmd.stdout(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn {cmd:?}: {e}"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = std::io::BufReader::new(stdout);

    let mut binaries = std::collections::HashMap::new();
    for message in cargo_metadata::Message::parse_stream(reader) {
        match message.map_err(|e| anyhow::anyhow!("parse cargo output: {e}"))? {
            cargo_metadata::Message::CompilerArtifact(artifact) => {
                if let Some(exe) = artifact.executable {
                    binaries.insert(artifact.target.name, exe.into_std_path_buf());
                }
            }
            cargo_metadata::Message::CompilerMessage(msg) => {
                if let Some(rendered) = msg.message.rendered {
                    eprint!("{rendered}");
                }
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .map_err(|e| anyhow::anyhow!("wait {cmd:?}: {e}"))?;
    if !status.success() {
        anyhow::bail!("{cmd:?} failed: {status}");
    }
    Ok(binaries)
}

/// Fetch a binary path from a [`build`] result, erroring if absent.
pub(crate) fn require<'a>(
    binaries: &'a std::collections::HashMap<String, std::path::PathBuf>,
    name: &str,
) -> anyhow::Result<&'a std::path::PathBuf> {
    binaries
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("expected binary {name:?} was not built"))
}
