//! The per-user data directory (`~/.local/share/pingu-runtime`).

use std::path::PathBuf;

use crate::sys::Sys;

#[derive(Clone, Debug)]
pub struct Home {
    pub root: PathBuf,
}

impl Home {
    /// `--data-dir`, then `$PINGU_RUNTIME_DIR`, then `$XDG_DATA_HOME` or `~/.local/share`.
    pub fn locate(sys: &Sys, explicit: Option<PathBuf>) -> Self {
        let root = explicit
            .or_else(|| sys.env_path("PINGU_RUNTIME_DIR"))
            .unwrap_or_else(
                || match (sys.env_path("XDG_DATA_HOME"), sys.env_path("HOME")) {
                    (Some(data), _) if data.is_absolute() => data.join("pingu-runtime"),
                    (_, Some(home)) => home.join(".local/share/pingu-runtime"),
                    _ => PathBuf::from(".pingu-runtime"),
                },
            );
        Self { root }
    }

    pub fn file(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// The installed copy of the preload library.
    pub fn hook(&self) -> PathBuf {
        self.file("pingu-hook.so")
    }

    pub fn variants(&self) -> PathBuf {
        self.file("variants")
    }

    /// Where the embedded helper programs are written.
    pub fn bin(&self) -> PathBuf {
        self.file("bin")
    }

    /// The patched copies of Proton that arm the policy.
    pub fn companions(&self) -> PathBuf {
        self.file("lutris")
    }

    pub fn generations(&self) -> PathBuf {
        self.file("runtime-generations")
    }

    /// Package downloads and scratch space of the runtime builder.
    pub fn builder_work(&self) -> PathBuf {
        self.file("runtime-builder")
    }

    /// A lock file written by an update; it takes precedence over the embedded one.
    pub fn lock_override(&self, gpu: &str) -> PathBuf {
        self.file(&format!("locks/{gpu}.lock.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sys(env: &[(&str, &str)]) -> Sys {
        let mut sys = Sys::real();
        sys.env = env
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>();
        sys
    }

    #[test]
    fn location_follows_the_documented_order() {
        let both = sys(&[
            ("HOME", "/home/u"),
            ("XDG_DATA_HOME", "/xdg"),
            ("PINGU_RUNTIME_DIR", "/env"),
        ]);
        assert_eq!(
            Home::locate(&both, Some("/flag".into())).root,
            PathBuf::from("/flag")
        );
        assert_eq!(Home::locate(&both, None).root, PathBuf::from("/env"));
        let xdg = sys(&[("HOME", "/home/u"), ("XDG_DATA_HOME", "/xdg")]);
        assert_eq!(
            Home::locate(&xdg, None).root,
            PathBuf::from("/xdg/pingu-runtime")
        );
        let home = sys(&[("HOME", "/home/u")]);
        assert_eq!(
            Home::locate(&home, None).root,
            PathBuf::from("/home/u/.local/share/pingu-runtime")
        );
        let relative = sys(&[("HOME", "/home/u"), ("XDG_DATA_HOME", "relative")]);
        assert_eq!(
            Home::locate(&relative, None).root,
            PathBuf::from("/home/u/.local/share/pingu-runtime")
        );
    }
}
