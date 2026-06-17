//! Extract Debian `.deb` archives (an `ar` wrapping `data.tar[.xz|.zst]`).
//!
//! Ubuntu mainline-PPA kernel debs ship an uncompressed `data.tar`, but older
//! builds may use xz or zstd, so all three are handled. We extract the whole
//! data member into `dest`; callers then locate `boot/vmlinuz-*` and
//! `lib/modules/<release>/` within it.

/// Extract the data member of `deb` into `dest`.
pub(crate) fn extract(deb: &std::path::Path, dest: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest).map_err(|e| anyhow::anyhow!("create {}: {e}", dest.display()))?;
    let file =
        std::fs::File::open(deb).map_err(|e| anyhow::anyhow!("open {}: {e}", deb.display()))?;
    let mut archive = ar::Archive::new(file);

    while let Some(entry) = archive.next_entry() {
        let entry = entry.map_err(|e| anyhow::anyhow!("read {}: {e}", deb.display()))?;
        let id = String::from_utf8_lossy(entry.header().identifier()).into_owned();
        match id.as_str() {
            "data.tar" => {
                tar::Archive::new(entry)
                    .unpack(dest)
                    .map_err(|e| anyhow::anyhow!("untar {}: {e}", deb.display()))?;
                return Ok(());
            }
            "data.tar.xz" => {
                let mut buf = Vec::new();
                lzma_rs::xz_decompress(&mut std::io::BufReader::new(entry), &mut buf)
                    .map_err(|e| anyhow::anyhow!("xz {}: {e}", deb.display()))?;
                tar::Archive::new(buf.as_slice())
                    .unpack(dest)
                    .map_err(|e| anyhow::anyhow!("untar {}: {e}", deb.display()))?;
                return Ok(());
            }
            "data.tar.zst" => {
                let decoder = ruzstd::StreamingDecoder::new(entry)
                    .map_err(|e| anyhow::anyhow!("zstd {}: {e}", deb.display()))?;
                tar::Archive::new(decoder)
                    .unpack(dest)
                    .map_err(|e| anyhow::anyhow!("untar {}: {e}", deb.display()))?;
                return Ok(());
            }
            _ => {}
        }
    }
    anyhow::bail!("no data.tar[.xz|.zst] member in {}", deb.display())
}

/// Find the single entry under `dir` whose file name starts with `prefix`.
pub(crate) fn find_prefixed(
    dir: &std::path::Path,
    prefix: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let mut matches = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("read_dir {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| anyhow::anyhow!("read_dir {}: {e}", dir.display()))?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(prefix))
        {
            matches.push(entry.path());
        }
    }
    match matches.as_slice() {
        [one] => Ok(one.clone()),
        [] => anyhow::bail!("no {prefix}* found in {}", dir.display()),
        many => anyhow::bail!("multiple {prefix}* found in {}: {many:?}", dir.display()),
    }
}
