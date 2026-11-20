//! Small file system helpers shared by the wrapper and the runtime builder.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A private (mode 0700) directory that disappears when dropped unless it was kept.
pub struct TempDir {
    path: Option<PathBuf>,
}

impl TempDir {
    pub fn new_in(parent: &Path, prefix: &str) -> io::Result<Self> {
        fs::create_dir_all(parent)?;
        loop {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos());
            let name = format!(
                "{prefix}{:x}{:x}{nanos:x}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let path = parent.join(name);
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path: Some(path) }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    pub fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("the directory is kept or dropped only once")
    }

    /// Keeps the directory and gives up the automatic removal.
    pub fn into_path(mut self) -> PathBuf {
        self.path
            .take()
            .expect("the directory is kept or dropped only once")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Points `link` at `target`, replacing a symlink that is already there.
pub fn replace_symlink(link: &Path, target: &Path) -> io::Result<()> {
    if is_symlink(link) {
        fs::remove_file(link)?;
    }
    symlink(target, link)
}

/// Lexical normalization with `posixpath.normpath` semantics.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let slashes = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else {
        usize::from(path.starts_with('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part != ".." || (slashes == 0 && parts.is_empty()) || parts.last() == Some(&"..") {
            parts.push(part);
        } else {
            parts.pop();
        }
    }
    let joined = format!("{}{}", "/".repeat(slashes), parts.join("/"));
    if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

/// `os.path.relpath` for absolute, normalized paths.
pub fn relpath(target: &Path, start: &Path) -> PathBuf {
    let parts = |path: &Path| -> Vec<std::ffi::OsString> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_os_string()),
                _ => None,
            })
            .collect()
    };
    let (target, start) = (parts(target), parts(start));
    let common = target
        .iter()
        .zip(&start)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..start.len() {
        relative.push("..");
    }
    for part in &target[common..] {
        relative.push(part);
    }
    if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_matches_posixpath() {
        assert_eq!(normpath("/usr/lib/../lib32//x/./y"), "/usr/lib32/x/y");
        assert_eq!(normpath("usr/lib/../../.."), "..");
        assert_eq!(normpath("/.."), "/");
        assert_eq!(normpath("//a"), "//a");
        assert_eq!(normpath(""), ".");
        assert_eq!(normpath("a/.."), ".");
    }

    #[test]
    fn relpath_walks_up_and_down() {
        assert_eq!(
            relpath(Path::new("/r/usr/lib/libc.so.6"), Path::new("/r/usr/lib64")),
            PathBuf::from("../lib/libc.so.6")
        );
        assert_eq!(
            relpath(Path::new("/r/usr/lib/a"), Path::new("/r/usr/lib")),
            PathBuf::from("a")
        );
        assert_eq!(
            relpath(Path::new("/r"), Path::new("/r")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn temp_dirs_are_private_and_removed() {
        let parent = crate::scratch("fsutil-temp");
        let path = {
            let directory = TempDir::new_in(&parent, "x-").unwrap();
            assert!(directory.path().is_dir());
            directory.path().to_path_buf()
        };
        assert!(!path.exists());
    }
}
