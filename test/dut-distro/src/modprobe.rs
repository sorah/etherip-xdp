//! A minimal `modprobe` for the test VM: resolves a module's dependency chain
//! and `init_module(2)`s each module bottom-up.
//!
//! Unlike aya's original (which loaded a single module with no dependency
//! handling), this reads each module's `depends=` modinfo and recursively loads
//! prerequisites first — required for e.g. `virtio_net`, which depends on
//! `net_failover`/`failover`. Modules that resolve to no `.ko` file are assumed
//! to be built into the kernel and skipped. Not for production use.
#![deny(clippy::undocumented_unsafe_blocks)]

#[derive(clap::Parser)]
struct Args {
    /// Suppress output and never fail (used for best-effort / optional loads).
    #[clap(short, long, default_value = "false")]
    quiet: bool,

    /// Module name (e.g. `virtio_net`) or an alias from `modules.alias`.
    name: String,
}

fn main() {
    let args = <Args as clap::Parser>::parse();
    match try_main(&args.name) {
        Ok(()) => {}
        Err(e) => {
            if !args.quiet {
                eprintln!("modprobe {}: {e:#}", args.name);
                std::process::exit(1);
            }
        }
    }
}

fn try_main(name: &str) -> anyhow::Result<()> {
    let modules_dir = dut_distro::resolve_modules_dir()?;
    // Index every module by its base name so dependency names resolve to paths.
    let index = build_index(&modules_dir)?;
    let module = resolve_alias(&modules_dir, name)?.unwrap_or_else(|| name.to_string());
    let mut loaded = std::collections::HashSet::new();
    load(&module, &index, &mut loaded)
}

/// Walk `modules_dir` once, mapping each module's base name to its file path.
fn build_index(
    modules_dir: &std::path::Path,
) -> anyhow::Result<std::collections::HashMap<String, std::path::PathBuf>> {
    let mut index = std::collections::HashMap::new();
    for entry in walkdir::WalkDir::new(modules_dir) {
        let entry = entry.map_err(|e| anyhow::anyhow!("walk {}: {e}", modules_dir.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str() else {
            continue;
        };
        if let Some((_, stem)) = dut_distro::Compression::classify(file_name) {
            index.insert(stem.to_string(), entry.path().to_path_buf());
        }
    }
    Ok(index)
}

/// Recursively load `module` and its dependencies (depth-first, deps first).
fn load(
    module: &str,
    index: &std::collections::HashMap<String, std::path::PathBuf>,
    loaded: &mut std::collections::HashSet<String>,
) -> anyhow::Result<()> {
    if !loaded.insert(module.to_string()) {
        return Ok(());
    }
    let Some(path) = index.get(module) else {
        // No `.ko` for this name: it is built into the kernel (or genuinely
        // absent). Either way there is nothing to insert.
        return Ok(());
    };
    let contents =
        dut_distro::read_module(path).map_err(|e| anyhow::anyhow!("read {module}: {e}"))?;
    for dep in
        module_dependencies(&contents).map_err(|e| anyhow::anyhow!("read deps of {module}: {e}"))?
    {
        load(&dep, index, loaded)?;
    }
    if !contents.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        anyhow::bail!("{} is not a valid ELF module", path.display());
    }
    match nix::kmod::init_module(&contents, c"") {
        Ok(()) => {
            println!("loaded module {module}");
            Ok(())
        }
        // Already loaded (e.g. a shared dependency, or loaded by a prior call).
        Err(nix::errno::Errno::EEXIST) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("init_module({module}): {e}")),
    }
}

/// Parse the comma-separated `depends=` entry from a module's `.modinfo`.
fn module_dependencies(elf: &[u8]) -> anyhow::Result<Vec<String>> {
    use object::{Object as _, ObjectSection as _};
    let obj = object::read::File::parse(elf).map_err(|e| anyhow::anyhow!("parse ELF: {e}"))?;
    let Some(section) = obj.section_by_name(".modinfo") else {
        return Ok(Vec::new());
    };
    let data = section
        .data()
        .map_err(|e| anyhow::anyhow!(".modinfo data: {e}"))?;
    for entry in data.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        if let Ok(s) = std::str::from_utf8(entry)
            && let Some(deps) = s.strip_prefix("depends=")
        {
            return Ok(deps
                .split(',')
                .filter(|d| !d.is_empty())
                .map(str::to_string)
                .collect());
        }
    }
    Ok(Vec::new())
}

/// Look up `name` in `modules.alias`; returns the resolved module name if found.
fn resolve_alias(modules_dir: &std::path::Path, name: &str) -> anyhow::Result<Option<String>> {
    use std::io::BufRead as _;
    let alias_path = modules_dir.join("modules.alias");
    let file = match std::fs::File::open(&alias_path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| anyhow::anyhow!("read {}: {e}", alias_path.display()))?;
        let mut parts = line.split_whitespace();
        if parts.next() != Some("alias") {
            continue;
        }
        let (Some(alias), Some(module)) = (parts.next(), parts.next()) else {
            continue;
        };
        if alias == name {
            return Ok(Some(module.to_string()));
        }
    }
    Ok(None)
}
