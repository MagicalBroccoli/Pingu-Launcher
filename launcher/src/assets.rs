//! Files that are built into the binary and written out on demand.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct Asset {
    pub path: &'static str,
    pub mode: u32,
    pub data: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

/// The lock file shipped for `gpu`.
pub fn lock(gpu: &str) -> Option<&'static [u8]> {
    LOCKS
        .iter()
        .find(|(name, _)| *name == gpu)
        .map(|(_, data)| *data)
}

pub fn module_file(path: &str) -> Option<&'static Asset> {
    MODULE_FILES.iter().find(|asset| asset.path == path)
}

/// Package version from the embedded DKMS config.
pub fn module_version() -> String {
    dkms_version(MODULE_FILES)
}

fn dkms_version(files: &[Asset]) -> String {
    files
        .iter()
        .find(|asset| asset.path == "dkms.conf")
        .and_then(|asset| std::str::from_utf8(asset.data).ok())
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("PACKAGE_VERSION=")
                    .map(|value| value.trim().trim_matches('"').to_string())
            })
        })
        .unwrap_or_default()
}

/// Writes `data` to `destination` unless it already holds exactly that. Returns whether it wrote.
pub fn install(destination: &Path, data: &[u8], mode: u32) -> io::Result<bool> {
    if let Ok(existing) = fs::read(destination)
        && existing == data
        && fs::metadata(destination)?.permissions().mode() & 0o777 == mode
    {
        return Ok(false);
    }
    let parent = destination.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(data)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&temporary, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map(|()| true)
}

/// Writes the pingu-policy DKMS package below `destination`.
pub fn export_module(destination: &Path) -> Result<Vec<PathBuf>, String> {
    export_files(MODULE_FILES, destination)
}

/// Whether `destination` holds exactly the embedded pingu-policy sources and nothing else.
pub fn module_sources_match(destination: &Path) -> bool {
    sources_match(MODULE_FILES, destination)
}

fn sources_match(files: &[Asset], destination: &Path) -> bool {
    fn collect(directory: &Path, prefix: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).into_iter().flatten().flatten() {
            let relative = prefix.join(entry.file_name());
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => collect(&entry.path(), &relative, found),
                _ => found.push(relative),
            }
        }
    }
    let mut found = Vec::new();
    collect(destination, Path::new(""), &mut found);
    found.sort();
    let mut expected: Vec<PathBuf> = files
        .iter()
        .map(|asset| PathBuf::from(asset.path))
        .collect();
    expected.sort();
    found == expected
        && files.iter().all(|asset| {
            fs::read(destination.join(asset.path)).is_ok_and(|data| data == asset.data)
        })
}

/// An existing tree with other content is refused, because the sources of an installed module
/// version must not change.
fn export_files(files: &[Asset], destination: &Path) -> Result<Vec<PathBuf>, String> {
    for asset in files {
        let path = destination.join(asset.path);
        if let Ok(existing) = fs::read(&path)
            && existing != asset.data
        {
            return Err(format!(
                "{} differs from the embedded module sources; remove it first or choose another directory",
                path.display()
            ));
        }
    }
    let mut written = Vec::new();
    for asset in files {
        let path = destination.join(asset.path);
        install(&path, asset.data, asset.mode)
            .map_err(|error| format!("Cannot write {}: {error}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkms_config_is_embedded() {
        assert!(!module_version().is_empty());
        assert!(module_file("dkms.conf").is_some());
        assert!(module_file("validation/manifest.json").is_some());
    }

    #[test]
    fn the_module_package_carries_the_merged_sources() {
        for path in [
            "Makefile",
            "umip.c",
            "cpuid_fault.c",
            "svm_run_vm.S",
            "inc/vmcb_layout.h",
        ] {
            assert!(module_file(path).is_some(), "{path}");
        }
    }

    #[test]
    fn every_gpu_has_a_lock_with_glibc() {
        for gpu in ["nvidia", "amd", "intel"] {
            let lock: serde_json::Value = serde_json::from_slice(lock(gpu).unwrap()).unwrap();
            assert_eq!(lock["gpu"], gpu);
            assert!(
                lock["packages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|package| package["name"] == "glibc")
            );
        }
    }

    #[test]
    fn helpers_and_hook_are_elf_files() {
        for data in [HOOK, AVX2_RUN, XSTATE_PROBE, POLICY_TEST] {
            assert_eq!(&data[..4], b"\x7fELF");
        }
    }
}
