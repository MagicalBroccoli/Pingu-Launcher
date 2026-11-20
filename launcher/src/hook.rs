//! The preload library: installed from the binary, with optional variants for experiments.

use std::fs;
use std::path::{Path, PathBuf};

use crate::assets;
use crate::home::Home;
use crate::sys::{Sys, shell_quote};

/// A usable preload library, or why there is none.
#[derive(Clone, Debug)]
pub struct Library {
    pub path: PathBuf,
    pub variant: Option<String>,
    pub warning: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Missing {
    pub detail: String,
    pub fix: String,
}

fn variant_name(sys: &Sys, home: &Home) -> Option<String> {
    sys.env("PINGU_HOOK_VARIANT")
        .map(str::to_string)
        .or_else(|| {
            fs::read_to_string(home.file("variant")).ok().map(|text| {
                let first = text.lines().next().unwrap_or("");
                first.split_whitespace().collect::<String>()
            })
        })
        .filter(|variant| !variant.is_empty())
}

/// Writes the embedded library into the data directory and picks the one to preload.
/// `$PINGU_HOOK_VARIANT` (or the `variant` file) selects `variants/pingu-hook.<name>.so`.
pub fn resolve(sys: &Sys, home: &Home) -> Result<Library, Missing> {
    let default = home.hook();
    assets::install(&default, assets::HOOK, 0o644).map_err(|error| Missing {
        detail: format!("pingu-hook.so could not be installed to {}: {error}.", default.display()),
        fix: format!(
            "Make {} writable, or choose another data directory with --data-dir or PINGU_RUNTIME_DIR.",
            shell_quote(&home.root)
        ),
    })?;

    let (path, variant, warning) = match variant_name(sys, home) {
        Some(name) => {
            let candidate = home.variants().join(format!("pingu-hook.{name}.so"));
            if !name.contains('/') && fs::File::open(&candidate).is_ok() {
                (candidate, Some(name), None)
            } else {
                let warning = format!("variant not found: {} (using default)", candidate.display());
                (default, None, Some(warning))
            }
        }
        None => (default, None, None),
    };
    // LD_PRELOAD cannot carry a path with a colon.
    if path.to_string_lossy().contains(':') {
        return Err(Missing {
            detail: format!(
                "The library path {} contains ':', which LD_PRELOAD cannot hold.",
                path.display()
            ),
            fix: "Use a data directory without a colon (--data-dir or PINGU_RUNTIME_DIR).".into(),
        });
    }
    Ok(Library {
        path,
        variant,
        warning,
    })
}

/// LD_PRELOAD with the library first and the existing entries behind it.
pub fn compose_preload(existing: Option<&str>, library: &Path, command_name: &str) -> String {
    let library = library.to_string_lossy();
    let kept: Vec<&str> = existing
        .unwrap_or("")
        .split(':')
        .filter(|entry| !entry.is_empty() && *entry != library)
        .filter(|entry| !(command_name == "gamescope" && entry.contains("gameoverlayrenderer.so")))
        .collect();
    if kept.is_empty() {
        library.into_owned()
    } else {
        format!("{library}:{}", kept.join(":"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn setup(name: &str, env: &[(&str, &str)]) -> (Sys, Home) {
        let mut sys = Sys::real();
        sys.env = env
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>();
        (
            sys,
            Home {
                root: crate::scratch(name),
            },
        )
    }

    #[test]
    fn library_goes_first_and_is_not_repeated() {
        let library = Path::new("/lib/pingu-hook.so");
        assert_eq!(
            compose_preload(None, library, "umu-run"),
            "/lib/pingu-hook.so"
        );
        assert_eq!(
            compose_preload(Some("/a.so::/lib/pingu-hook.so:/b.so"), library, "umu-run"),
            "/lib/pingu-hook.so:/a.so:/b.so"
        );
    }

    #[test]
    fn steam_overlay_is_dropped_only_for_gamescope() {
        let library = Path::new("/lib/pingu-hook.so");
        let existing = Some("/steam/gameoverlayrenderer.so:/x.so");
        assert_eq!(
            compose_preload(existing, library, "gamescope"),
            "/lib/pingu-hook.so:/x.so"
        );
        assert_eq!(
            compose_preload(existing, library, "umu-run"),
            "/lib/pingu-hook.so:/steam/gameoverlayrenderer.so:/x.so"
        );
    }

    #[test]
    fn the_embedded_library_is_installed_and_repaired() {
        let (sys, home) = setup("hook-install", &[]);
        let library = resolve(&sys, &home).unwrap();
        assert_eq!(library.path, home.hook());
        assert_eq!(fs::read(home.hook()).unwrap(), assets::HOOK);

        fs::write(home.hook(), b"stale").unwrap();
        resolve(&sys, &home).unwrap();
        assert_eq!(fs::read(home.hook()).unwrap(), assets::HOOK);
    }

    #[test]
    fn variants_come_from_the_environment_or_the_file() {
        let (sys, home) = setup("hook-variant", &[("PINGU_HOOK_VARIANT", "pr58")]);
        fs::create_dir_all(home.variants()).unwrap();
        fs::write(home.variants().join("pingu-hook.pr58.so"), b"v").unwrap();
        let library = resolve(&sys, &home).unwrap();
        assert_eq!(library.variant.as_deref(), Some("pr58"));
        assert!(library.path.ends_with("variants/pingu-hook.pr58.so"));

        let (sys, home) = setup("hook-variant-file", &[]);
        fs::create_dir_all(home.variants()).unwrap();
        fs::write(home.variants().join("pingu-hook.x.so"), b"v").unwrap();
        fs::write(home.file("variant"), " x \nignored\n").unwrap();
        assert_eq!(resolve(&sys, &home).unwrap().variant.as_deref(), Some("x"));
    }

    #[test]
    fn a_missing_variant_falls_back_with_a_warning() {
        let (sys, home) = setup("hook-missing-variant", &[("PINGU_HOOK_VARIANT", "gone")]);
        let library = resolve(&sys, &home).unwrap();
        assert_eq!(library.path, home.hook());
        assert!(library.warning.unwrap().contains("variant not found"));
    }

    #[test]
    fn an_unwritable_data_directory_is_reported() {
        let (sys, mut home) = setup("hook-unwritable", &[]);
        let blocker = home.root.join("file");
        fs::write(&blocker, b"x").unwrap();
        home.root = blocker.join("below");
        let error = resolve(&sys, &home).unwrap_err();
        assert!(
            error.detail.contains("could not be installed"),
            "{}",
            error.detail
        );
    }
}
