//! Minimal "newc" cpio writer for building the initramfs in-process (no `cpio`
//! binary or `gen_init_cpio` download required).
//!
//! Entry names are stored relative to the archive root (no leading `/`); the
//! kernel unpacks them into the initramfs rootfs. Parent directories are emitted
//! before their contents.

const MAGIC: &[u8] = b"070701";
const TRAILER: &str = "TRAILER!!!";

/// Accumulates directories and files, then serialises them as a newc cpio.
#[derive(Default)]
pub(crate) struct Cpio {
    dirs: std::collections::BTreeSet<String>,
    files: Vec<(String, u32, Vec<u8>)>,
}

impl Cpio {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a directory (and all of its ancestors).
    pub(crate) fn add_dir(&mut self, path: &str) {
        let path = normalize(path);
        let mut acc = String::new();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(comp);
            self.dirs.insert(acc.clone());
        }
    }

    /// Register a regular file with the given octal permission `perm` (e.g.
    /// `0o755`), creating its ancestor directories.
    pub(crate) fn add_file(&mut self, path: &str, perm: u32, data: Vec<u8>) {
        let path = normalize(path);
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.add_dir(parent);
        }
        self.files.push((path, perm, data));
    }

    /// Serialise to a newc cpio byte stream.
    pub(crate) fn finish(self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut ino: u32 = 1;

        // Directories shallowest-first so a parent always precedes its children.
        let mut dirs: Vec<&String> = self.dirs.iter().collect();
        dirs.sort_by_key(|d| (d.matches('/').count(), (*d).clone()));
        for dir in dirs {
            write_entry(&mut out, ino, 0o040000 | 0o755, 2, dir, &[]);
            ino += 1;
        }
        for (path, perm, data) in &self.files {
            write_entry(&mut out, ino, 0o100000 | perm, 1, path, data);
            ino += 1;
        }
        write_entry(&mut out, ino, 0, 1, TRAILER, &[]);
        out
    }
}

/// Strip leading `./` and `/` so names are archive-root-relative.
fn normalize(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn write_entry(out: &mut Vec<u8>, ino: u32, mode: u32, nlink: u32, name: &str, data: &[u8]) {
    let name_bytes = name.as_bytes();
    let namesize = name_bytes.len() + 1; // include trailing NUL

    out.extend_from_slice(MAGIC);
    for field in [
        ino,
        mode,
        0, // uid
        0, // gid
        nlink,
        0,                 // mtime
        data.len() as u32, // filesize
        0,                 // devmajor
        0,                 // devminor
        0,                 // rdevmajor
        0,                 // rdevminor
        namesize as u32,
        0, // check (unused for newc)
    ] {
        out.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    out.extend_from_slice(name_bytes);
    out.push(0);
    // The header (110 bytes) + name is padded to a 4-byte boundary.
    pad4(out, 110 + namesize);
    out.extend_from_slice(data);
    pad4(out, data.len());
}

/// Append NUL padding so that `len` bytes (just written) end on a 4-byte boundary.
fn pad4(out: &mut Vec<u8>, len: usize) {
    let rem = len % 4;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, 4 - rem));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn archive_has_magic_trailer_and_4byte_alignment() {
        let mut cpio = super::Cpio::new();
        cpio.add_dir("dev");
        cpio.add_file("bin/foo", 0o755, b"hello".to_vec());
        cpio.add_file(
            "lib/modules/1.0/kernel/net/veth.ko.zst",
            0o644,
            vec![0u8; 7],
        );
        let bytes = cpio.finish();

        // Every newc header begins on a 4-byte boundary, so the whole stream is
        // a multiple of 4 long.
        assert_eq!(bytes.len() % 4, 0, "archive not 4-byte aligned");
        assert_eq!(&bytes[..6], super::MAGIC);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains(super::TRAILER), "missing TRAILER entry");
        // Ancestor directories are synthesised for nested files.
        assert!(text.contains("lib/modules/1.0/kernel/net"));
        assert!(text.contains("bin/foo"));
        // File contents are present.
        assert!(text.contains("hello"));
    }

    #[test]
    fn normalize_strips_leading_slashes() {
        assert_eq!(super::normalize("/bin/foo"), "bin/foo");
        assert_eq!(super::normalize("./init"), "init");
        assert_eq!(super::normalize("lib/x"), "lib/x");
    }
}
