use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::sys::Sys;

const ARTIFACT: &str = "artifact.dll";
const MAX_DEPTH: usize = 8;
const MAX_ENTRIES: usize = 400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameMode {
    Artifact,
    Legacy,
}

impl GameMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Artifact => "Artifact mode",
            Self::Legacy => "Legacy mode",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ModeSetting {
    #[default]
    Auto,
    Artifact,
    Legacy,
}

impl FromStr for ModeSetting {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "artifact" => Ok(Self::Artifact),
            "legacy" => Ok(Self::Legacy),
            other => Err(format!(
                "--mode must be auto, artifact or legacy, not {other}"
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Detection {
    pub mode: GameMode,
    pub note: String,
}

/// Directories that may hold the game, most specific first.
pub fn game_dirs(sys: &Sys, command: &[String]) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = ["STEAM_COMPAT_INSTALL_PATH", "GAMEDIR"]
        .iter()
        .filter_map(|key| sys.env_path(key))
        .collect();
    for argument in command {
        let path = Path::new(argument);
        let is_exe = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"));
        if is_exe
            && path.is_file()
            && let Some(parent) = path.parent()
        {
            candidates.push(parent.to_path_buf());
        }
    }
    // The working directory is only a fallback; Lutris and Steam normally start in the game
    // directory, but anything else may be an unrelated tree. The home directory and / say nothing.
    if candidates.is_empty() {
        let home = sys.env_path("HOME");
        if sys.cwd != Path::new("/") && Some(&sys.cwd) != home.as_ref() {
            candidates.push(sys.cwd.clone());
        }
    }

    let mut result: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        let Ok(resolved) = fs::canonicalize(&candidate) else {
            continue;
        };
        if resolved.is_dir() && !result.iter().any(|known| resolved.starts_with(known)) {
            result.push(resolved);
        }
    }
    result
}

/// Breadth first and case-insensitive; directory symlinks are not followed.
pub fn find_artifact(root: &Path) -> Option<PathBuf> {
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut seen = 0usize;
    while let Some((directory, depth)) = queue.pop_front() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if depth < MAX_DEPTH {
                    queue.push_back((entry.path(), depth + 1));
                }
            } else if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(ARTIFACT)
            {
                return Some(entry.path());
            }
        }
    }
    None
}

pub fn detect(sys: &Sys, command: &[String], setting: ModeSetting) -> Detection {
    match setting {
        ModeSetting::Artifact => {
            return Detection {
                mode: GameMode::Artifact,
                note: "forced with --mode artifact.".into(),
            };
        }
        ModeSetting::Legacy => {
            return Detection {
                mode: GameMode::Legacy,
                note: "forced with --mode legacy.".into(),
            };
        }
        ModeSetting::Auto => {}
    }
    // Opened on its own there is no game to scan, so show the full requirements.
    if command.is_empty() {
        return Detection {
            mode: GameMode::Artifact,
            note: "no command was given, so Artifact mode is assumed.".into(),
        };
    }
    let dirs = game_dirs(sys, command);
    if dirs.is_empty() {
        return Detection {
            mode: GameMode::Legacy,
            note: "no game directory could be determined, so artifact.dll was not looked for."
                .into(),
        };
    }
    for directory in &dirs {
        if let Some(found) = find_artifact(directory) {
            return Detection {
                mode: GameMode::Artifact,
                note: format!("artifact.dll found at {}.", found.display()),
            };
        }
    }
    let list: Vec<String> = dirs
        .iter()
        .map(|directory| directory.display().to_string())
        .collect();
    Detection {
        mode: GameMode::Legacy,
        note: format!("no artifact.dll in {}.", list.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_setting_parses() {
        assert_eq!("auto".parse(), Ok(ModeSetting::Auto));
        assert_eq!("artifact".parse(), Ok(ModeSetting::Artifact));
        assert_eq!("legacy".parse(), Ok(ModeSetting::Legacy));
        assert!("both".parse::<ModeSetting>().is_err());
    }
}
