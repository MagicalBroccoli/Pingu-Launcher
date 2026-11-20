pub mod assets;
pub mod builder;
pub mod checks;
pub mod cli;
pub mod cmd;
pub mod elf;
pub mod fsutil;
pub mod home;
pub mod hook;
pub mod install;
pub mod launch;
pub mod mode;
pub mod runtime;
pub mod shlex;
pub mod sys;
pub mod tools;
pub mod ui;
pub mod vdf;
pub mod wrapper;

/// A fresh scratch directory below the crate's target directory.
#[cfg(test)]
pub(crate) fn scratch(name: &str) -> std::path::PathBuf {
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/tmp")
        .join(name);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}
