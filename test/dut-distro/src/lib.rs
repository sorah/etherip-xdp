//! Shared helpers for the dut-distro binaries (`init`, `modprobe`, `depmod`).
//!
//! Ported from aya's `test-distro`. The notable addition over the original is
//! [`read_module`], which transparently decompresses `.ko`, `.ko.xz` and
//! `.ko.zst` modules — current mainline (Ubuntu-built) kernels compress modules
//! with zstd, so xz-only support is not enough.

/// Kernel modules live under `/lib/modules`, either directly or in a
/// subdirectory named after the running kernel release.
pub fn resolve_modules_dir() -> anyhow::Result<std::borrow::Cow<'static, std::path::Path>> {
    let modules_dir = std::path::Path::new("/lib/modules");
    if !modules_dir.is_dir() {
        anyhow::bail!("{} is not a directory", modules_dir.display());
    }
    // The build-time `depmod` is pointed directly at the extracted
    // `/lib/modules/<release>` directory; in the VM the modules sit under a
    // release-named subdirectory. Prefer the release subdir when present.
    let release = nix::sys::utsname::uname()
        .map_err(|e| anyhow::anyhow!("uname(): {e}"))?
        .release()
        .to_owned();
    let release_dir = modules_dir.join(release);
    if release_dir.is_dir() {
        return Ok(release_dir.into());
    }
    Ok(modules_dir.into())
}

/// The on-disk compression of a kernel module, inferred from its file name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Xz,
    Zstd,
}

impl Compression {
    /// Classify a module file name, returning the compression and the name with
    /// any compression suffix stripped, or `None` if it is not a `.ko*` file.
    pub fn classify(file_name: &str) -> Option<(Self, &str)> {
        if let Some(stem) = file_name.strip_suffix(".ko") {
            Some((Compression::None, stem))
        } else if let Some(stem) = file_name.strip_suffix(".ko.xz") {
            Some((Compression::Xz, stem))
        } else if let Some(stem) = file_name.strip_suffix(".ko.zst") {
            Some((Compression::Zstd, stem))
        } else {
            None
        }
    }
}

/// Read a kernel module from `path`, decompressing per its file extension, and
/// return the raw ELF bytes ready for `init_module(2)`.
pub fn read_module(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 module file name: {}", path.display()))?;
    let (compression, _) = Compression::classify(file_name)
        .ok_or_else(|| anyhow::anyhow!("not a kernel module: {}", path.display()))?;

    let bytes =
        std::fs::read(path).map_err(|e| anyhow::anyhow!("read({}): {e}", path.display()))?;
    match compression {
        Compression::None => Ok(bytes),
        Compression::Xz => {
            let mut out = Vec::with_capacity(bytes.len() * 3);
            let mut reader = std::io::BufReader::new(bytes.as_slice());
            lzma_rs::xz_decompress(&mut reader, &mut out)
                .map_err(|e| anyhow::anyhow!("xz_decompress({}): {e}", path.display()))?;
            Ok(out)
        }
        Compression::Zstd => {
            use std::io::Read as _;
            let mut out = Vec::with_capacity(bytes.len() * 3);
            let mut decoder = ruzstd::StreamingDecoder::new(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("zstd decoder for {}: {e}", path.display()))?;
            decoder
                .read_to_end(&mut out)
                .map_err(|e| anyhow::anyhow!("zstd decompress {}: {e}", path.display()))?;
            Ok(out)
        }
    }
}
