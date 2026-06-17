//! A minimal `depmod`: regenerates `modules.alias` from each module's `alias=`
//! modinfo entries. Run at build time (host-side) against the extracted
//! `/lib/modules/<release>` tree so `modprobe` can resolve aliases.
//!
//! Dependency resolution is handled live by our `modprobe` (from each module's
//! `depends=` modinfo), so — unlike real depmod — this does not emit
//! `modules.dep`. Ported from aya's `test-distro` `depmod`, extended to read
//! zstd-compressed modules. Not for production use.
#![deny(clippy::undocumented_unsafe_blocks)]

#[derive(clap::Parser)]
struct Args {
    /// Operate on this `/lib/modules/<release>` directory instead of resolving
    /// it from the running kernel (used by the build-time invocation).
    #[clap(long, short)]
    base_dir: Option<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = <Args as clap::Parser>::parse();
    let modules_dir: std::borrow::Cow<'_, std::path::Path> = match args.base_dir {
        Some(d) => d.into(),
        None => test_distro::resolve_modules_dir()?,
    };

    let alias_path = modules_dir.join("modules.alias");
    let file = std::fs::File::create(&alias_path)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", alias_path.display()))?;
    let mut out = std::io::BufWriter::new(file);

    for entry in walkdir::WalkDir::new(&modules_dir) {
        let entry = entry.map_err(|e| anyhow::anyhow!("walk {}: {e}", modules_dir.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str() else {
            continue;
        };
        let Some((_, module)) = test_distro::Compression::classify(file_name) else {
            continue;
        };
        let contents = test_distro::read_module(entry.path())
            .map_err(|e| anyhow::anyhow!("read {}: {e}", entry.path().display()))?;
        write_aliases(&contents, module, &mut out)
            .map_err(|e| anyhow::anyhow!("aliases from {}: {e}", entry.path().display()))?;
    }
    Ok(())
}

/// Emit `alias <alias> <module>` for every `alias=` entry in `.modinfo`.
fn write_aliases(elf: &[u8], module: &str, out: &mut impl std::io::Write) -> anyhow::Result<()> {
    use object::{Object as _, ObjectSection as _};
    let obj = object::read::File::parse(elf).map_err(|e| anyhow::anyhow!("parse ELF: {e}"))?;
    let Some(section) = obj.section_by_name(".modinfo") else {
        return Ok(());
    };
    let data = section
        .data()
        .map_err(|e| anyhow::anyhow!(".modinfo data: {e}"))?;
    for entry in modinfo_entries(data)? {
        if let Some(alias) = entry.strip_prefix("alias=") {
            writeln!(out, "alias {alias} {module}").map_err(|e| anyhow::anyhow!("write: {e}"))?;
        }
    }
    Ok(())
}

fn modinfo_entries(data: &[u8]) -> anyhow::Result<Vec<&str>> {
    data.split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .map(|e| std::str::from_utf8(e).map_err(|e| anyhow::anyhow!("non-UTF-8 modinfo: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn modinfo_entries_reads_nul_delimited_records() {
        let entries = super::modinfo_entries(
            b"description=test module\0alias=net-sch-clsact\0alias=net-sch-ingress\0",
        )
        .unwrap();
        assert_eq!(
            entries,
            vec![
                "description=test module",
                "alias=net-sch-clsact",
                "alias=net-sch-ingress",
            ]
        );
    }

    #[test]
    fn modinfo_entries_rejects_invalid_utf8() {
        assert_matches::assert_matches!(super::modinfo_entries(b"alias=\xff\0"), Err(_));
    }

    #[test]
    fn write_aliases_requires_valid_elf() {
        // `.modinfo` extraction needs a real ELF; a non-ELF input must error
        // rather than silently producing no aliases.
        let mut out = Vec::new();
        super::write_aliases(b"not-elf", "sch_ingress", &mut out).unwrap_err();
    }

    #[test]
    fn modinfo_alias_lines_are_extracted() {
        use std::io::Write as _;
        let modinfo =
            b"description=test\0alias=net-sch-clsact\0alias=net-sch-ingress\0name=sch_ingress\0";
        let mut out = Vec::new();
        for entry in super::modinfo_entries(modinfo).unwrap() {
            if let Some(alias) = entry.strip_prefix("alias=") {
                writeln!(&mut out, "alias {alias} sch_ingress").unwrap();
            }
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "alias net-sch-clsact sch_ingress\nalias net-sch-ingress sch_ingress\n",
        );
    }
}
