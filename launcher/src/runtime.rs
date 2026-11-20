use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use serde_json::Value;

use crate::assets;
use crate::builder::{self, Builder, Tools};
use crate::checks::Check;
use crate::cmd::Cancel;
use crate::home::Home;
use crate::sys::{Sys, shell_quote};

const MANIFEST_SCHEMA: i64 = 2;
pub const GPUS: [&str; 3] = ["nvidia", "amd", "intel"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuntimeMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl FromStr for RuntimeMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "--runtime must be auto, always or never, not {other}"
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeState {
    NotRequired(String),
    Ready {
        glibc: String,
    },
    /// Works, but a newer package lock than the selected generation's is available.
    Outdated {
        glibc: String,
        reason: String,
    },
    Missing,
    Stale {
        selected: String,
        host: String,
    },
    Invalid(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Generate,
    Upgrade,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::Generate => "Generate runtime",
            Self::Upgrade => "Upgrade runtime",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeInfo {
    pub state: RuntimeState,
    pub gpu: String,
    pub host_glibc: Option<String>,
    pub home: PathBuf,
    /// This program, for the commands shown to the user.
    pub exe: PathBuf,
}

impl RuntimeInfo {
    /// A working runtime can be rebuilt from its lock.
    pub fn can_regenerate(&self) -> bool {
        matches!(self.state, RuntimeState::Ready { .. })
    }

    pub fn is_usable(&self) -> bool {
        matches!(
            self.state,
            RuntimeState::NotRequired(_)
                | RuntimeState::Ready { .. }
                | RuntimeState::Outdated { .. }
        )
    }

    pub fn action(&self) -> Option<Action> {
        match self.state {
            RuntimeState::Missing | RuntimeState::Invalid(_) if self.host_glibc.is_some() => {
                Some(Action::Generate)
            }
            RuntimeState::Stale { .. } | RuntimeState::Outdated { .. } => Some(Action::Upgrade),
            _ => None,
        }
    }

    pub fn as_check(&self) -> Check {
        const TITLE: &str = "Private runtime";
        let gpu = &self.gpu;
        let provision = format!("{} runtime provision --gpu {gpu}", shell_quote(&self.exe));
        match &self.state {
            RuntimeState::NotRequired(reason) => {
                Check::ok(TITLE, format!("Not required: {reason}."))
            }
            RuntimeState::Ready { glibc } => Check::ok(
                TITLE,
                format!("The selected {gpu} runtime matches the host glibc ({glibc})."),
            ),
            RuntimeState::Outdated { glibc, reason } => {
                let mut check = Check::ok(
                    TITLE,
                    format!("The selected {gpu} runtime matches the host glibc ({glibc})."),
                );
                check.warning = format!("{reason} Upgrade the runtime to use it.");
                check.fix = provision;
                check
            }
            RuntimeState::Missing => Check::problem(
                TITLE,
                format!(
                    "No {gpu} runtime has been generated. The host packages are built for AVX-512, so games need the generic runtime."
                ),
                provision,
            ),
            RuntimeState::Stale { selected, host } => Check::problem(
                TITLE,
                format!(
                    "The selected {gpu} runtime was built for glibc {selected}, but the host now has {host}."
                ),
                provision,
            ),
            RuntimeState::Invalid(reason) => Check::problem(TITLE, reason.clone(), provision),
        }
    }
}

/// Parses a pacman `desc` file into its first value per `%FIELD%`.
pub fn parse_desc(text: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.len() > 2 && line.starts_with('%') && line.ends_with('%') {
            current = Some(line[1..line.len() - 1].to_string());
        } else if !line.is_empty()
            && let Some(key) = current.take()
        {
            fields.insert(key, line.to_string());
        }
    }
    fields
}

/// Version and architecture of the installed glibc package, from the pacman database.
pub fn installed_glibc(sys: &Sys) -> Option<(String, String)> {
    let entries = fs::read_dir(sys.path("/var/lib/pacman/local")).ok()?;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("glibc-") {
            continue;
        }
        let Ok(text) = fs::read_to_string(entry.path().join("desc")) else {
            continue;
        };
        let fields = parse_desc(&text);
        if fields.get("NAME").map(String::as_str) == Some("glibc") {
            return Some((
                fields.get("VERSION")?.clone(),
                fields.get("ARCH").cloned().unwrap_or_default(),
            ));
        }
    }
    None
}

/// x86-64-v4 and znver4/5 builds use AVX-512 unconditionally.
pub fn is_avx512_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["v4", "znver4", "znver5"]
        .iter()
        .any(|marker| lower.contains(marker))
}

pub fn avx512_repositories(sys: &Sys) -> Vec<String> {
    sys.read("/etc/pacman.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().strip_prefix('[')?.strip_suffix(']'))
        .filter(|name| *name != "options" && is_avx512_name(name))
        .map(str::to_string)
        .collect()
}

pub fn detect_gpu(sys: &Sys) -> String {
    if let Some(gpu) = sys.env("AVX2_GPU").filter(|gpu| GPUS.contains(gpu)) {
        return gpu.to_string();
    }
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(sys.path("/sys/class/drm")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_card = name
                .strip_prefix("card")
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
            if !is_card {
                continue;
            }
            if let Ok(vendor) = fs::read_to_string(entry.path().join("device/vendor")) {
                found.push(vendor.trim().to_ascii_lowercase());
            }
        }
    }
    for (id, gpu) in [("0x10de", "nvidia"), ("0x1002", "amd"), ("0x8086", "intel")] {
        if found.iter().any(|vendor| vendor == id) {
            return gpu.to_string();
        }
    }
    "nvidia".to_string()
}

pub fn selected_runtime(sys: &Sys, home: &Home, gpu: &str) -> PathBuf {
    sys.env_path("AVX2_RUNTIME")
        .unwrap_or_else(|| home.generations().join(format!("{gpu}-current")))
}

pub fn detect(sys: &Sys, home: &Home, mode: RuntimeMode) -> RuntimeInfo {
    let glibc = installed_glibc(sys);
    let host_glibc = glibc.as_ref().map(|(version, _)| version.clone());
    let mut gpu = detect_gpu(sys);
    let info = |state, gpu: String| RuntimeInfo {
        state,
        gpu,
        host_glibc: host_glibc.clone(),
        home: home.root.clone(),
        exe: sys.exe.clone(),
    };

    let not_required = match mode {
        RuntimeMode::Never => Some("disabled with --runtime never".to_string()),
        _ if sys.env("AVX2_RUNTIME") == Some("none") => {
            Some("disabled with AVX2_RUNTIME=none".to_string())
        }
        RuntimeMode::Always => None,
        // An explicit AVX2_RUNTIME path means the user opted in.
        RuntimeMode::Auto if sys.env("AVX2_RUNTIME").is_some() => None,
        RuntimeMode::Auto => {
            let repos = avx512_repositories(sys);
            match &glibc {
                Some((_, arch)) if is_avx512_name(arch) => None,
                _ if !repos.is_empty() => None,
                Some((_, arch)) => Some(format!("the host packages are not AVX-512 optimized (glibc is {arch})")),
                None => Some("no pacman database found, assuming the host packages are not AVX-512 optimized".to_string()),
            }
        }
    };
    if let Some(reason) = not_required {
        return info(RuntimeState::NotRequired(reason), gpu);
    }
    let Some(host) = host_glibc.clone() else {
        return info(
            RuntimeState::Invalid(
                "The installed glibc version could not be read from the pacman database.".into(),
            ),
            gpu,
        );
    };

    let path = selected_runtime(sys, home, &gpu);
    if !path.exists() {
        return info(RuntimeState::Missing, gpu);
    }
    let manifest = fs::read_to_string(path.join("runtime.json"))
        .map_err(|error| {
            format!(
                "The selected runtime {} has no readable runtime.json ({error}).",
                path.display()
            )
        })
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text).map_err(|error| {
                format!("The selected runtime's runtime.json is invalid ({error}).")
            })
        });
    let manifest = match manifest {
        Ok(manifest) => manifest,
        Err(reason) => return info(RuntimeState::Invalid(reason), gpu),
    };
    if manifest["schema"].as_i64() != Some(MANIFEST_SCHEMA) {
        return info(
            RuntimeState::Invalid(
                "The selected runtime was built by an incompatible builder version.".into(),
            ),
            gpu,
        );
    }
    if let Some(declared) = manifest["gpu"]
        .as_str()
        .filter(|declared| GPUS.contains(declared))
    {
        gpu = declared.to_string();
    }
    let Some(selected) = manifest["glibc"].as_str() else {
        return info(
            RuntimeState::Invalid("The selected runtime does not record its glibc version.".into()),
            gpu,
        );
    };
    if selected != host {
        info(
            RuntimeState::Stale {
                selected: selected.to_string(),
                host,
            },
            gpu,
        )
    } else if let Some(reason) = outdated_reason(sys, home, &gpu, &manifest) {
        info(
            RuntimeState::Outdated {
                glibc: host,
                reason,
            },
            gpu,
        )
    } else {
        info(RuntimeState::Ready { glibc: host }, gpu)
    }
}

/// Why the selected generation is behind the lock in effect, if it is.
fn outdated_reason(sys: &Sys, home: &Home, gpu: &str, manifest: &Value) -> Option<String> {
    // An explicit generation is the user's choice.
    if sys.env("AVX2_RUNTIME").is_some() {
        return None;
    }
    let missing = missing_roots(home, gpu);
    if !missing.is_empty() {
        return Some(format!(
            "This launcher's package list also contains {}.",
            missing.join(", ")
        ));
    }
    let recorded = manifest["lock_sha256"].as_str()?;
    let lock = load_lock(home, gpu).ok()?;
    (builder::lock_identity(&lock) != recorded)
        .then(|| "A newer package lock than the selected runtime's is available.".to_string())
}

fn lock_roots(lock: &Value) -> Vec<String> {
    lock["roots"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|root| root.as_str().map(str::to_string))
        .collect()
}

/// Roots of the built-in lock that the lock in effect lacks (an update by an older launcher wrote it).
pub fn missing_roots(home: &Home, gpu: &str) -> Vec<String> {
    let embedded = assets::lock(gpu).and_then(|data| serde_json::from_slice::<Value>(data).ok());
    let (Some(embedded), Ok(lock)) = (embedded, load_lock(home, gpu)) else {
        return Vec::new();
    };
    let present = lock_roots(&lock);
    lock_roots(&embedded)
        .into_iter()
        .filter(|root| !present.contains(root))
        .collect()
}

/// The lock for `gpu`: the one a previous update wrote, otherwise the one built into the binary.
pub fn load_lock(home: &Home, gpu: &str) -> Result<Value, String> {
    let path = home.lock_override(gpu);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => String::from_utf8(
            assets::lock(gpu)
                .ok_or_else(|| format!("No lock file for {gpu}"))?
                .to_vec(),
        )
        .map_err(|error| error.to_string())?,
    };
    serde_json::from_str(&text).map_err(|error| format!("Invalid lock for {gpu}: {error}"))
}

pub fn locked_glibc(lock: &Value) -> Option<&str> {
    lock["packages"]
        .as_array()?
        .iter()
        .find(|package| package["name"] == "glibc")
        .and_then(|package| package["version"].as_str())
}

/// Generates or upgrades the private runtime and can be stopped from another thread.
#[derive(Default)]
pub struct Provision {
    cancel: Cancel,
    tools: Tools,
    keyring: Option<PathBuf>,
}

impl Provision {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// With other helper programs, for tests.
    pub fn with_tools(tools: Tools, keyring: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            cancel: Cancel::default(),
            tools,
            keyring: Some(keyring),
        })
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn run(
        &self,
        home: &Home,
        gpu: &str,
        host_glibc: &str,
        log: &(dyn Fn(&str) + Sync),
    ) -> Result<(), String> {
        self.run_with(home, gpu, host_glibc, false, log)
    }

    /// Builds the selected runtime again, replacing the existing generation.
    pub fn regenerate(
        &self,
        home: &Home,
        gpu: &str,
        host_glibc: &str,
        log: &(dyn Fn(&str) + Sync),
    ) -> Result<(), String> {
        self.run_with(home, gpu, host_glibc, true, log)
    }

    fn run_with(
        &self,
        home: &Home,
        gpu: &str,
        host_glibc: &str,
        replace: bool,
        log: &(dyn Fn(&str) + Sync),
    ) -> Result<(), String> {
        let lock = load_lock(home, gpu)?;
        let locked =
            locked_glibc(&lock).ok_or_else(|| format!("The {gpu} lock does not list glibc"))?;
        let mut builder = Builder::new(home.builder_work(), home.generations(), &self.cancel, log);
        builder.tools = self.tools.clone();
        builder.replace = replace;
        if let Some(keyring) = &self.keyring {
            builder.keyring = keyring.clone();
        }

        let missing = missing_roots(home, gpu);
        let generation = if locked == host_glibc && missing.is_empty() {
            builder
                .build_runtime(&lock, false)
                .map_err(|failure| failure.to_string())?
        } else {
            if locked != host_glibc {
                log(&format!(
                    "Locked glibc {locked} differs from the host's {host_glibc}; resolving current packages."
                ));
            } else {
                log(&format!(
                    "The package list gained {}; resolving current packages.",
                    missing.join(", ")
                ));
            }
            // Packages added with `update --add` stay in the new lock.
            let seeds = lock_roots(&lock);
            builder.update(
                gpu,
                builder::DEFAULT_MIRROR,
                &seeds,
                &home.lock_override(gpu),
            )?
        };
        match builder.select(&generation, host_glibc) {
            Ok(_) => Ok(()),
            Err(error) => {
                if self.cancel.is_cancelled() {
                    return Err(error);
                }
                Err(format!(
                    "{error}\nIf the mirror's glibc is newer than the host's, resolve against a matching snapshot with: pingu-launcher runtime update --gpu {gpu} --mirror https://archive.archlinux.org/repos/YYYY/MM/DD"
                ))
            }
        }
    }
}
