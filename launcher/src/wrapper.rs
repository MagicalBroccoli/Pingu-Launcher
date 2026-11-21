//! The policy wrapper: starts the command inside a companion Proton whose entry point arms
//! the XCR0 restriction, with the generated runtime overlaid on the host libraries.

use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::assets;
use crate::fsutil::{self, TempDir};
use crate::home::Home;
use crate::launch::is_lutris;
use crate::runtime::{self, RuntimeInfo, RuntimeState};
use crate::shlex;
use crate::sys::Sys;
use crate::vdf::{self, Value as Node};

const MANIFEST_SCHEMA: i64 = 2;
const GPUS: [&str; 3] = ["nvidia", "amd", "intel"];
const MODES: [&str; 4] = ["0", "1", "runtime-only", "xcr0-only"];
const REQUIRED_MOUNTS: [&str; 4] = [
    "usr/lib",
    "usr/lib32",
    "usr/share/vulkan",
    "usr/share/glvnd/egl_vendor.d",
];
const OVERLAYS: [&str; 6] = [
    "usr/lib",
    "usr/lib32",
    "usr/share/vulkan",
    "usr/share/glvnd/egl_vendor.d",
    "usr/share/drirc.d",
    "usr/share/libdrm",
];

/// Runs the original Proton so that its prefix files name the original directory.
const RUNNER: &str = "original-proton";
const RUNNER_SOURCE: &str = include_str!("original_proton.py");

pub type Environment = Vec<(String, String)>;

/// What to execute: the namespace wrapper around the command, and its environment.
#[derive(Debug)]
pub struct Prepared {
    pub program: String,
    pub args: Vec<String>,
    pub env: Environment,
    pub note: String,
}

fn at(path: &Path) -> impl Fn(io::Error) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

fn truthy(map: &vdf::Map, key: &str) -> bool {
    match map.get(key) {
        Some(Node::Text(text)) => !text.is_empty(),
        Some(Node::Map(_)) => true,
        None => false,
    }
}

struct Lock {
    _file: fs::File,
}

impl Lock {
    fn exclusive(path: &Path) -> Result<Self, String> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(at(path))?;
        // SAFETY: flock on a descriptor this struct owns; it is released when the file closes.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(at(path)(io::Error::last_os_error()));
        }
        Ok(Self { _file: file })
    }
}

/// Builds `<cache>/<Proton>-<key>`: a view of the original Proton whose entry point is `launcher`.
pub fn prepare_tool(original: &Path, launcher: &Path, cache: &Path) -> Result<PathBuf, String> {
    let original = fs::canonicalize(original).map_err(at(original))?;
    let launcher = fs::canonicalize(launcher).map_err(at(launcher))?;
    let manifest_path = original.join("toolmanifest.vdf");
    let text = fs::read_to_string(&manifest_path).map_err(at(&manifest_path))?;
    let mut document =
        vdf::parse(&text).map_err(|error| format!("{}: {error}", manifest_path.display()))?;
    let mut manifest = document
        .map("manifest")
        .cloned()
        .ok_or("toolmanifest.vdf has no manifest section")?;
    if manifest.text("compatmanager_layer_name") != Some("proton") {
        return Err("The selected tool is not a Proton compatibility layer".into());
    }
    if !truthy(&manifest, "require_tool_appid") {
        return Err("The selected Proton does not require an isolated runtime".into());
    }
    if truthy(&manifest, "avx2_policy_companion") {
        return Err("Select the original Proton, not an AVX2 companion tool".into());
    }
    let commandline = manifest
        .text("commandline")
        .ok_or("toolmanifest.vdf has no commandline")?
        .to_string();
    if !commandline.starts_with('/') {
        return Err("Proton's manifest command must be relative to its tool directory".into());
    }
    let original_text = original.to_string_lossy().into_owned();
    let mut command = shlex::split(&(shlex::quote(&original_text) + &commandline))?;
    let entry = command
        .first()
        .ok_or("Proton's manifest command is empty")?;
    if fs::canonicalize(entry).map_err(at(Path::new(entry)))? != original.join("proton") {
        return Err("Only the selected Proton's own proton entry point is supported".into());
    }
    if original_text.contains(':') || cache.to_string_lossy().contains(':') {
        return Err("Runtime mount paths cannot contain ':'".into());
    }

    let digest = Sha256::digest(original.as_os_str().as_bytes());
    let key: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    fs::create_dir_all(cache).map_err(at(cache))?;
    let name = original
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let companion = cache.join(format!("{name}-{key}"));
    command[0] = companion
        .join("original")
        .join("proton")
        .to_string_lossy()
        .into_owned();
    command.insert(0, companion.join(RUNNER).to_string_lossy().into_owned());
    manifest.set_text("commandline", format!("/proton {}", shlex::join(&command)));
    manifest.set_text("avx2_policy_companion", "1");
    document.insert("manifest", Node::Map(manifest));

    let _lock = Lock::exclusive(&cache.join(format!("{key}.lock")))?;
    if fsutil::is_symlink(&companion) {
        return Err("Refusing a symlink at the companion directory".into());
    }
    match fs::DirBuilder::new().mode(0o700).create(&companion) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(at(&companion)(error)),
    }
    let mount = companion.join("original");
    if original.join("original").exists() || fsutil::is_symlink(&mount) {
        return Err("The companion's original mount point is reserved".into());
    }
    match fs::create_dir(&mount) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(at(&mount)(error)),
    }
    for entry in fs::read_dir(&original).map_err(at(&original))? {
        let entry = entry.map_err(at(&original))?;
        let name = entry.file_name();
        let source = original.join(&name);

        let view = mount.join(&name);
        if fsutil::is_symlink(&view) {
            if fs::read_link(&view).map_err(at(&view))? != source {
                fs::remove_file(&view).map_err(at(&view))?;
                symlink(&source, &view).map_err(at(&view))?;
            }
        } else if view.exists() {
            return Err(format!(
                "Unexpected non-symlink in original view: {}",
                view.display()
            ));
        } else {
            symlink(&source, &view).map_err(at(&view))?;
        }
        if name == "proton" || name == "toolmanifest.vdf" || name == RUNNER {
            continue;
        }

        let destination = companion.join(&name);
        let target = Path::new("original").join(&name);
        if fsutil::is_symlink(&destination) {
            if fs::read_link(&destination).map_err(at(&destination))? == target {
                continue;
            }
            fs::remove_file(&destination).map_err(at(&destination))?;
        } else if destination.exists() {
            return Err(format!(
                "Unexpected non-symlink in companion: {}",
                destination.display()
            ));
        }
        symlink(&target, &destination).map_err(at(&destination))?;
    }

    let staging = TempDir::new_in(cache, "prepare-").map_err(at(cache))?;
    let proton = staging.path().join("proton");
    fs::copy(&launcher, &proton).map_err(at(&proton))?;
    fs::set_permissions(&proton, fs::Permissions::from_mode(0o755)).map_err(at(&proton))?;
    let staged_manifest = staging.path().join("toolmanifest.vdf");
    fs::write(&staged_manifest, vdf::dump(&document)).map_err(at(&staged_manifest))?;
    let runner = staging.path().join(RUNNER);
    let shown = serde_json::to_string(&original_text).map_err(|error| error.to_string())?;
    fs::write(&runner, RUNNER_SOURCE.replace("\"__ORIGINAL__\"", &shown)).map_err(at(&runner))?;
    fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).map_err(at(&runner))?;
    for file in ["proton", "toolmanifest.vdf", RUNNER] {
        fs::rename(staging.path().join(file), companion.join(file))
            .map_err(at(&companion.join(file)))?;
    }
    Ok(companion)
}

/// The generation's manifest; `None` when the directory is not a generated runtime.
pub fn runtime_manifest(libraries: &Path) -> Result<Option<Value>, String> {
    let path = libraries.join("runtime.json");
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(at(&path))?;
    let manifest: Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let known_gpu = manifest["gpu"]
        .as_str()
        .is_some_and(|gpu| GPUS.contains(&gpu));
    if manifest["schema"].as_i64() != Some(MANIFEST_SCHEMA) || !known_gpu {
        return Err("Unsupported generated runtime manifest".into());
    }
    Ok(Some(manifest))
}

fn vendor_environment(
    sys: &Sys,
    env: &mut Environment,
    libraries: Option<&Path>,
) -> Result<(), String> {
    let manifest = match libraries {
        Some(libraries) => runtime_manifest(libraries)?,
        None => None,
    };
    let gpu = manifest
        .as_ref()
        .and_then(|manifest| manifest["gpu"].as_str())
        .unwrap_or("nvidia")
        .to_string();
    let (icds, egl) = if gpu == "nvidia" {
        let icd = "/usr/share/vulkan/icd.d/nvidia_icd.json";
        let egl = "/usr/share/glvnd/egl_vendor.d/10_nvidia.json";
        if !sys.path(icd).is_file() || !sys.path(egl).is_file() {
            return Err("The NVIDIA Vulkan/EGL driver manifests are not installed".into());
        }
        (vec![icd.to_string()], egl.to_string())
    } else {
        let libraries = libraries.ok_or("A generated runtime is required for this GPU")?;
        let prefix = if gpu == "amd" {
            "radeon_icd"
        } else {
            "intel_icd"
        };
        let directory = libraries.join("usr/share/vulkan/icd.d");
        let mut names: Vec<String> = fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(prefix) && name.ends_with(".json"))
            .collect();
        names.sort();
        let egl = libraries.join("usr/share/glvnd/egl_vendor.d/50_mesa.json");
        if names.is_empty() || !egl.is_file() {
            return Err(format!(
                "The generated runtime lacks {gpu} Vulkan/EGL manifests"
            ));
        }
        (
            names
                .into_iter()
                .map(|name| format!("/usr/share/vulkan/icd.d/{name}"))
                .collect(),
            "/usr/share/glvnd/egl_vendor.d/50_mesa.json".to_string(),
        )
    };
    let files = icds.join(":");
    env.push(("VK_DRIVER_FILES".into(), files.clone()));
    env.push(("VK_ICD_FILENAMES".into(), files));
    env.push((
        "__GLX_VENDOR_LIBRARY_NAME".into(),
        if gpu == "nvidia" { "nvidia" } else { "mesa" }.into(),
    ));
    env.push(("__EGL_VENDOR_LIBRARY_FILENAMES".into(), egl));
    env.push(("AVX2_GPU".into(), gpu));
    env.push(("NODEVICE_SELECT".into(), "1".into()));
    Ok(())
}

/// The variables the wrapper sets on top of the inherited environment.
pub fn launch_environment(
    sys: &Sys,
    home: &Home,
    companion: &Path,
    libraries: Option<&Path>,
) -> Result<Environment, String> {
    let mut env: Environment = vec![(
        "PROTONPATH".into(),
        companion.to_string_lossy().into_owned(),
    )];
    if libraries.is_none() {
        env.push((
            "AVX2_GPU".into(),
            sys.env("AVX2_GPU").unwrap_or("nvidia").to_string(),
        ));
    } else {
        vendor_environment(sys, &mut env, libraries)?;
    }
    let mut mounts: Vec<String> = sys
        .env("PRESSURE_VESSEL_FILESYSTEMS_RO")
        .unwrap_or("")
        .split(':')
        .map(str::to_string)
        .collect();
    let extra = std::iter::once(home.root.to_string_lossy().into_owned())
        .chain(libraries.map(|path| path.to_string_lossy().into_owned()));
    for path in extra {
        if path.contains(':') {
            return Err("Runtime mount paths cannot contain ':'".into());
        }
        if !mounts.contains(&path) {
            mounts.push(path);
        }
    }
    mounts.retain(|mount| !mount.is_empty());
    env.push(("PRESSURE_VESSEL_FILESYSTEMS_RO".into(), mounts.join(":")));
    Ok(env)
}

/// The selected generation, checked against the host glibc; `None` when the runtime is disabled.
pub fn private_libraries(sys: &Sys, home: &Home, gpu: &str) -> Result<Option<PathBuf>, String> {
    if sys.env("AVX2_RUNTIME") == Some("none") {
        return Ok(None);
    }
    let (installed, _) =
        runtime::installed_glibc(sys).ok_or("Cannot determine the installed glibc version")?;
    let requested = runtime::selected_runtime(sys, home, gpu);
    if !requested.exists() {
        return Err("No selected runtime; generate one with the launcher window or `pingu-launcher runtime provision`".into());
    }
    let libraries = fs::canonicalize(&requested).map_err(at(&requested))?;
    let version = libraries.join("VERSION");
    if !version.is_file() {
        return Err("Matching private glibc is missing; regenerate the selected runtime".into());
    }
    let recorded = fs::read_to_string(&version).map_err(at(&version))?;
    if recorded.trim() != installed {
        return Err("Private glibc version differs from the host; regenerate the runtime".into());
    }
    match runtime_manifest(&libraries)? {
        Some(manifest) if manifest["glibc"].as_str() == Some(installed.as_str()) => {
            Ok(Some(libraries))
        }
        _ => {
            Err("AVX2_RUNTIME must select an audited runtime generation matching host glibc".into())
        }
    }
}

/// The bubblewrap command line that binds the original Proton and overlays the runtime.
/// The bind stays writable because Proton locks and fixes up its own directory (dist.lock).
pub fn namespace_command(
    sys: &Sys,
    original: &Path,
    companion: &Path,
    libraries: Option<&Path>,
    command: &[String],
) -> Result<Vec<String>, String> {
    let bubblewrap = sys
        .which("bwrap")
        .ok_or("bubblewrap is required for the companion tool mount")?;
    let mut result: Vec<String> = [
        bubblewrap.to_string_lossy().as_ref(),
        "--die-with-parent",
        "--bind",
        "/",
        "/",
        "--dev-bind",
        "/dev",
        "/dev",
        "--bind",
        &original.to_string_lossy(),
        &companion.join("original").to_string_lossy(),
    ]
    .iter()
    .map(|word| word.to_string())
    .collect();
    if let Some(libraries) = libraries {
        if runtime_manifest(libraries)?.is_none() {
            return Err("An audited runtime generation is required".into());
        }
        for relative in OVERLAYS {
            let source = libraries.join(relative);
            let destination = format!("/{relative}");
            if !source.is_dir() {
                continue;
            }
            if !sys.path(&destination).is_dir() {
                if REQUIRED_MOUNTS.contains(&relative) {
                    return Err(format!(
                        "Required host runtime mount directory is missing: {destination}"
                    ));
                }
                continue;
            }
            result.extend([
                "--overlay-src".into(),
                destination.clone(),
                "--overlay-src".into(),
                source.to_string_lossy().into_owned(),
                "--ro-overlay".into(),
                destination,
            ]);
        }
    }
    result.push("--".into());
    result.extend_from_slice(command);
    Ok(result)
}

/// Finds the original Proton in Steam's expanded launch command and where it sits.
pub fn steam_proton(command: &[String]) -> Result<(PathBuf, usize), String> {
    let mut runtimes = Vec::new();
    let mut protons = Vec::new();
    for (index, argument) in command.iter().enumerate() {
        let path = Path::new(argument);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !["_v2-entry-point", "run", "umu", "proton"].contains(&name) || !path.is_file() {
            continue;
        }
        let Some(directory) = path.parent() else {
            continue;
        };
        let manifest_path = directory.join("toolmanifest.vdf");
        if !manifest_path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&manifest_path).map_err(at(&manifest_path))?;
        let document =
            vdf::parse(&text).map_err(|error| format!("{}: {error}", manifest_path.display()))?;
        let manifest = document
            .map("manifest")
            .ok_or_else(|| format!("{} has no manifest section", manifest_path.display()))?;
        let role = manifest.text("compatmanager_layer_name");
        if name == "proton" && role == Some("proton") {
            if truthy(manifest, "avx2_policy_companion") {
                return Err("Select the original Proton in Steam, not a companion".into());
            }
            protons.push((fs::canonicalize(directory).map_err(at(directory))?, index));
        } else if role == Some("container-runtime") {
            runtimes.push(index);
        }
    }
    if protons.len() != 1 || runtimes.len() != 1 {
        return Err("Steam command must contain one Steam Linux Runtime entry and one original Proton; native Steam with container-enabled Proton is required".into());
    }
    let (original, index) = protons.remove(0);
    if runtimes[0] >= index
        || !command[runtimes[0] + 1..index]
            .iter()
            .any(|word| word == "--")
    {
        return Err("Proton must execute inside Steam Linux Runtime".into());
    }
    let verb = command.get(index + 1).map(String::as_str);
    if !matches!(verb, Some("run" | "waitforexitandrun" | "runinprefix")) {
        return Err("Unsupported Steam Proton launch verb".into());
    }
    Ok((original, index))
}

/// Replaces Proton in Steam's command with the companion, keeping everything around it.
pub fn steam_command(command: &[String], companion: &Path, index: usize) -> Vec<String> {
    let mut result = command[..index].to_vec();
    result.push(companion.join("proton").to_string_lossy().into_owned());
    result.push(companion.join(RUNNER).to_string_lossy().into_owned());
    result.push(
        companion
            .join("original/proton")
            .to_string_lossy()
            .into_owned(),
    );
    result.extend_from_slice(&command[index + 1..]);
    result
}

fn describe(policy: &str) -> &'static str {
    match policy {
        "runtime-only" => "keeping the private runtime WITHOUT CPU masking",
        "xcr0-only" => "restricting XCR0 while leaving CPUID to Wine and pingu-hook",
        _ => "activating CPU policy inside the runtime",
    }
}

/// Plans the whole policy launch of `command` (Lutris's `umu-run` or Steam's expanded command).
pub fn plan(
    sys: &Sys,
    home: &Home,
    runtime: Option<&RuntimeInfo>,
    command: &[String],
) -> Result<Prepared, String> {
    let policy = sys.env("AVX2_POLICY").unwrap_or("xcr0-only");
    if !MODES.contains(&policy) {
        return Err("AVX2_POLICY must be 0, 1, runtime-only, or xcr0-only".into());
    }
    let mut env = Environment::new();
    if sys.env("AVX2_POLICY").is_none() {
        env.push(("AVX2_POLICY".into(), policy.into()));
    }
    if policy == "0" {
        return Ok(Prepared {
            program: command[0].clone(),
            args: command[1..].to_vec(),
            env,
            note: String::new(),
        });
    }
    if sys.env("UMU_NO_RUNTIME").is_some_and(|value| value != "0")
        || sys.env("UMU_NO_PROTON") == Some("1")
    {
        return Err("The Proton container runtime must remain enabled".into());
    }

    let steam = !is_lutris(command);
    let (selected, steam_index) = if steam {
        let (original, index) = steam_proton(command)?;
        (original, Some(index))
    } else {
        let path = sys
            .env_path("AVX2_PROTON_PATH")
            .or_else(|| sys.env_path("PROTONPATH"))
            .ok_or("Set AVX2_PROTON_PATH to the original Proton directory")?;
        (path, None)
    };
    let original = fs::canonicalize(&selected).map_err(at(&selected))?;

    let helper = home.bin().join("avx2-run");
    assets::install(&helper, assets::AVX2_RUN, 0o755).map_err(at(&helper))?;
    if policy != "runtime-only" {
        (sys.arm_check)(&helper, policy)
            .map_err(|detail| format!("The kernel refused to arm the restriction: {detail}"))?;
    }
    let companion = prepare_tool(&original, &helper, &home.companions())?;

    let gpu = sys
        .env("AVX2_GPU")
        .or(runtime.map(|runtime| runtime.gpu.as_str()))
        .unwrap_or("nvidia");
    let disabled = matches!(
        runtime.map(|runtime| &runtime.state),
        Some(RuntimeState::NotRequired(_))
    );
    let libraries = if disabled {
        None
    } else {
        private_libraries(sys, home, gpu)?
    };
    let command = match steam_index {
        Some(index) => steam_command(command, &companion, index),
        None => command.to_vec(),
    };
    let wrapped = namespace_command(sys, &original, &companion, libraries.as_deref(), &command)?;
    env.extend(launch_environment(
        sys,
        home,
        &companion,
        libraries.as_deref(),
    )?);
    let name = original
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Prepared {
        program: wrapped[0].clone(),
        args: wrapped[1..].to_vec(),
        env,
        note: format!("{} for {name}", describe(policy)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fixture {
        root: PathBuf,
        sys: Sys,
        home: Home,
        original: PathBuf,
    }

    fn manifest(extra: &str) -> String {
        format!(
            "\"manifest\"\n{{\n\t\"version\" \"2\"\n\t\"commandline\" \"/proton %verb%\"\n\t\"require_tool_appid\" \"4183110\"\n\t\"compatmanager_layer_name\" \"proton\"\n{extra}}}\n"
        )
    }

    fn arm_ok(_: &Path, _: &str) -> Result<(), String> {
        Ok(())
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = crate::scratch(name);
            let original = root.join("Proton with spaces");
            fs::create_dir_all(original.join("files")).unwrap();
            fs::write(original.join("proton"), "original proton\n").unwrap();
            fs::write(original.join("toolmanifest.vdf"), manifest("")).unwrap();
            let bin = root.join("bin");
            fs::create_dir_all(&bin).unwrap();
            fs::write(bin.join("bwrap"), "#!/bin/sh\n").unwrap();
            fs::set_permissions(bin.join("bwrap"), fs::Permissions::from_mode(0o755)).unwrap();
            let mut sys = Sys::real();
            sys.root = root.clone();
            sys.env = HashMap::from([
                ("HOME".to_string(), "/home/user".to_string()),
                ("PATH".to_string(), bin.to_string_lossy().into_owned()),
            ]);
            sys.arm_check = arm_ok;
            let home = Home {
                root: root.join("data"),
            };
            Self {
                root,
                sys,
                home,
                original,
            }
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }

        fn launcher(&self) -> PathBuf {
            self.write("launcher", "launcher bytes");
            self.root.join("launcher")
        }

        fn prepare(&self) -> PathBuf {
            prepare_tool(&self.original, &self.launcher(), &self.root.join("cache")).unwrap()
        }

        fn runtime(&self, gpu: &str) -> PathBuf {
            let libraries = self.root.join("managed");
            for directory in [
                "usr/lib",
                "usr/lib32",
                "usr/share/vulkan/icd.d",
                "usr/share/glvnd/egl_vendor.d",
            ] {
                fs::create_dir_all(libraries.join(directory)).unwrap();
                // The host has the same directories to overlay.
                fs::create_dir_all(self.root.join(directory)).unwrap();
            }
            fs::write(
                libraries.join("runtime.json"),
                format!("{{\"schema\": 2, \"gpu\": \"{gpu}\", \"glibc\": \"2.44-1\"}}"),
            )
            .unwrap();
            fs::write(libraries.join("VERSION"), "2.44-1\n").unwrap();
            libraries
        }
    }

    fn value<'a>(env: &'a Environment, key: &str) -> Option<&'a str> {
        env.iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn the_companion_views_the_original_and_swaps_the_entry_point() {
        let fixture = Fixture::new("wrapper-prepare");
        let before = fs::read(fixture.original.join("toolmanifest.vdf")).unwrap();
        let companion = fixture.prepare();

        assert_eq!(
            fs::read(fixture.original.join("toolmanifest.vdf")).unwrap(),
            before
        );
        assert_eq!(
            fs::read_to_string(fixture.original.join("proton")).unwrap(),
            "original proton\n"
        );
        assert_eq!(
            fs::read_link(companion.join("files")).unwrap(),
            PathBuf::from("original/files")
        );
        assert_eq!(
            fs::read_to_string(companion.join("original/proton")).unwrap(),
            "original proton\n"
        );
        assert_eq!(
            fs::read(companion.join("proton")).unwrap(),
            b"launcher bytes"
        );
        assert_eq!(
            fs::metadata(companion.join("proton"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(fixture.prepare(), companion);

        let document =
            vdf::parse(&fs::read_to_string(companion.join("toolmanifest.vdf")).unwrap()).unwrap();
        let manifest = document.map("manifest").unwrap();
        assert_eq!(manifest.text("avx2_policy_companion"), Some("1"));
        let command = shlex::split(
            manifest
                .text("commandline")
                .unwrap()
                .strip_prefix("/proton ")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            command,
            [
                companion.join(RUNNER).to_string_lossy(),
                companion.join("original/proton").to_string_lossy(),
                "%verb%".into()
            ]
        );
    }

    #[test]
    fn the_runner_names_the_original_directory() {
        let fixture = Fixture::new("wrapper-runner");
        let companion = fixture.prepare();
        let runner = fs::read_to_string(companion.join(RUNNER)).unwrap();
        let original = fs::canonicalize(&fixture.original).unwrap();
        assert!(runner.starts_with("#!/usr/bin/env python3\n"));
        assert!(runner.contains(&format!("ORIGINAL = {:?}\n", original.to_str().unwrap())));
        assert!(!runner.contains("__ORIGINAL__"));
        assert_eq!(
            fs::metadata(companion.join(RUNNER)).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn prefix_links_into_the_companion_survive_a_second_prepare() {
        let fixture = Fixture::new("wrapper-links");
        let builtins = fixture.original.join("files/lib/wine/x86_64-windows");
        fs::create_dir_all(&builtins).unwrap();
        fs::write(builtins.join("kernel32.dll"), "builtin").unwrap();
        let companion = fixture.prepare();
        let system32 = fixture.root.join("prefix/system32");
        fs::create_dir_all(&system32).unwrap();
        let link = system32.join("kernel32.dll");
        symlink(
            companion.join("original/files/lib/wine/x86_64-windows/kernel32.dll"),
            &link,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&link).unwrap(), "builtin");
        fixture.prepare();
        assert_eq!(fs::read_to_string(&link).unwrap(), "builtin");
    }

    #[test]
    fn unsuitable_tools_are_rejected() {
        let fixture = Fixture::new("wrapper-reject");
        let cache = fixture.root.join("cache");
        let launcher = fixture.launcher();

        fixture.write(
            "Proton with spaces/toolmanifest.vdf",
            "\"manifest\" { \"commandline\" \"/proton %verb%\" \"compatmanager_layer_name\" \"proton\" }",
        );
        let error = prepare_tool(&fixture.original, &launcher, &cache).unwrap_err();
        assert!(error.contains("isolated runtime"), "{error}");

        fixture.write("Proton with spaces/toolmanifest.vdf", &manifest(""));
        let companion = prepare_tool(&fixture.original, &launcher, &cache).unwrap();
        let error = prepare_tool(&companion, &launcher, &cache).unwrap_err();
        assert!(error.contains("original Proton"), "{error}");

        fixture.write(
            "Proton with spaces/toolmanifest.vdf",
            &manifest("").replace("/proton %verb%", "proton"),
        );
        let error = prepare_tool(&fixture.original, &launcher, &cache).unwrap_err();
        assert!(error.contains("relative to its tool directory"), "{error}");
    }

    #[test]
    fn namespace_keeps_devices_and_argument_boundaries() {
        let fixture = Fixture::new("wrapper-namespace");
        let companion = fixture.prepare();
        let arguments = [
            "umu-run".to_string(),
            "/game with spaces/game.exe".into(),
            "argument with spaces".into(),
        ];
        let command = namespace_command(
            &fixture.sys,
            &fixture.original,
            &companion,
            None,
            &arguments,
        )
        .unwrap();
        assert!(command[0].ends_with("bin/bwrap"));
        let device = command
            .iter()
            .position(|word| word == "--dev-bind")
            .unwrap();
        assert_eq!(command[device..device + 3], ["--dev-bind", "/dev", "/dev"]);
        let bind = command
            .iter()
            .position(|word| *word == fixture.original.to_string_lossy())
            .unwrap()
            - 1;
        assert_eq!(command[bind], "--bind");
        assert_eq!(command[bind + 1], fixture.original.to_string_lossy());
        assert_eq!(
            command[bind + 2],
            companion.join("original").to_string_lossy()
        );
        assert!(!command.iter().any(|word| word == "--overlay-src"));
        assert_eq!(
            command[command.len() - 4..],
            [
                "--",
                "umu-run",
                "/game with spaces/game.exe",
                "argument with spaces"
            ]
        );
    }

    #[test]
    fn the_runtime_overlays_the_host_libraries() {
        let fixture = Fixture::new("wrapper-overlay");
        let companion = fixture.prepare();
        let libraries = fixture.runtime("nvidia");
        let command = namespace_command(
            &fixture.sys,
            &fixture.original,
            &companion,
            Some(&libraries),
            &["fixture".to_string()],
        )
        .unwrap();
        let first = command
            .iter()
            .position(|word| word == "--overlay-src")
            .unwrap();
        assert_eq!(
            command[first..first + 6],
            [
                "--overlay-src".to_string(),
                "/usr/lib".into(),
                "--overlay-src".into(),
                libraries.join("usr/lib").to_string_lossy().into_owned(),
                "--ro-overlay".into(),
                "/usr/lib".into(),
            ]
        );
        assert!(!command.iter().any(|word| word == "--overlay"));
        assert_eq!(command[command.len() - 2..], ["--", "fixture"]);

        fs::remove_dir_all(fixture.root.join("usr/lib32")).unwrap();
        let error = namespace_command(
            &fixture.sys,
            &fixture.original,
            &companion,
            Some(&libraries),
            &[],
        )
        .unwrap_err();
        assert!(error.contains("/usr/lib32"), "{error}");
    }

    #[test]
    fn missing_bubblewrap_is_reported() {
        let mut fixture = Fixture::new("wrapper-no-bwrap");
        fixture.sys.env.insert(
            "PATH".into(),
            fixture.root.join("empty").to_string_lossy().into_owned(),
        );
        let error = namespace_command(&fixture.sys, &fixture.original, &fixture.root, None, &[])
            .unwrap_err();
        assert!(error.contains("bubblewrap"), "{error}");
    }

    #[test]
    fn disabled_runtime_keeps_the_policy_but_skips_overlay_and_vendor_files() {
        let mut fixture = Fixture::new("wrapper-none");
        fixture.sys.env.insert("AVX2_GPU".into(), "amd".into());
        let companion = fixture.prepare();
        let env = launch_environment(&fixture.sys, &fixture.home, &companion, None).unwrap();
        assert_eq!(value(&env, "AVX2_GPU"), Some("amd"));
        for name in [
            "VK_DRIVER_FILES",
            "VK_ICD_FILENAMES",
            "__EGL_VENDOR_LIBRARY_FILENAMES",
            "NODEVICE_SELECT",
        ] {
            assert_eq!(value(&env, name), None, "{name}");
        }
        assert_eq!(value(&env, "PROTONPATH"), Some(companion.to_str().unwrap()));
        let mounts = value(&env, "PRESSURE_VESSEL_FILESYSTEMS_RO").unwrap();
        assert!(
            mounts
                .split(':')
                .any(|mount| mount == fixture.home.root.to_str().unwrap())
        );
    }

    #[test]
    fn nvidia_uses_the_host_driver_manifests() {
        let mut fixture = Fixture::new("wrapper-nvidia");
        fixture
            .sys
            .env
            .insert("PRESSURE_VESSEL_FILESYSTEMS_RO".into(), "/existing".into());
        let companion = fixture.prepare();
        let libraries = fixture.runtime("nvidia");

        let error = launch_environment(&fixture.sys, &fixture.home, &companion, Some(&libraries))
            .unwrap_err();
        assert!(error.contains("NVIDIA"), "{error}");

        fixture.write("usr/share/vulkan/icd.d/nvidia_icd.json", "{}");
        fixture.write("usr/share/glvnd/egl_vendor.d/10_nvidia.json", "{}");
        let env =
            launch_environment(&fixture.sys, &fixture.home, &companion, Some(&libraries)).unwrap();
        assert_eq!(
            value(&env, "VK_DRIVER_FILES"),
            Some("/usr/share/vulkan/icd.d/nvidia_icd.json")
        );
        assert_eq!(
            value(&env, "VK_ICD_FILENAMES"),
            value(&env, "VK_DRIVER_FILES")
        );
        assert_eq!(
            value(&env, "__EGL_VENDOR_LIBRARY_FILENAMES"),
            Some("/usr/share/glvnd/egl_vendor.d/10_nvidia.json")
        );
        assert_eq!(value(&env, "__GLX_VENDOR_LIBRARY_NAME"), Some("nvidia"));
        let mounts: Vec<_> = value(&env, "PRESSURE_VESSEL_FILESYSTEMS_RO")
            .unwrap()
            .split(':')
            .collect();
        assert!(mounts.contains(&"/existing"));
        assert!(mounts.contains(&libraries.to_str().unwrap()));
        assert!(!mounts.contains(&fixture.original.to_str().unwrap()));
    }

    #[test]
    fn mesa_profiles_select_only_their_own_gpu() {
        let fixture = Fixture::new("wrapper-mesa");
        let companion = fixture.prepare();
        for (gpu, file) in [
            ("amd", "radeon_icd.x86_64.json"),
            ("intel", "intel_icd.x86_64.json"),
        ] {
            let libraries = fixture.runtime(gpu);
            fs::write(libraries.join("usr/share/vulkan/icd.d").join(file), "{}").unwrap();
            fs::write(
                libraries.join("usr/share/vulkan/icd.d/other_icd.json"),
                "{}",
            )
            .unwrap();
            fs::write(
                libraries.join("usr/share/glvnd/egl_vendor.d/50_mesa.json"),
                "{}",
            )
            .unwrap();
            let env = launch_environment(&fixture.sys, &fixture.home, &companion, Some(&libraries))
                .unwrap();
            assert_eq!(
                value(&env, "VK_DRIVER_FILES"),
                Some(format!("/usr/share/vulkan/icd.d/{file}").as_str())
            );
            assert_eq!(
                value(&env, "__EGL_VENDOR_LIBRARY_FILENAMES"),
                Some("/usr/share/glvnd/egl_vendor.d/50_mesa.json")
            );
            assert_eq!(value(&env, "__GLX_VENDOR_LIBRARY_NAME"), Some("mesa"));
            assert_eq!(value(&env, "AVX2_GPU"), Some(gpu));
        }
    }

    fn glibc(fixture: &Fixture, version: &str) {
        fixture.write(
            "var/lib/pacman/local/glibc-x/desc",
            &format!("%NAME%\nglibc\n\n%VERSION%\n{version}\n\n%ARCH%\nx86_64_v4\n"),
        );
    }

    #[test]
    fn a_selected_generation_must_match_the_host_glibc() {
        let mut fixture = Fixture::new("wrapper-glibc");
        let libraries = fixture.runtime("nvidia");
        fixture.sys.env.insert(
            "AVX2_RUNTIME".into(),
            libraries.to_string_lossy().into_owned(),
        );

        let error = private_libraries(&fixture.sys, &fixture.home, "nvidia").unwrap_err();
        assert!(error.contains("installed glibc"), "{error}");

        glibc(&fixture, "9.9-1");
        let error = private_libraries(&fixture.sys, &fixture.home, "nvidia").unwrap_err();
        assert!(error.contains("differs from the host"), "{error}");

        glibc(&fixture, "2.44-1");
        assert_eq!(
            private_libraries(&fixture.sys, &fixture.home, "nvidia").unwrap(),
            Some(fs::canonicalize(&libraries).unwrap())
        );

        fs::write(
            libraries.join("runtime.json"),
            "{\"schema\": 2, \"gpu\": \"nvidia\", \"glibc\": \"other\"}",
        )
        .unwrap();
        let error = private_libraries(&fixture.sys, &fixture.home, "nvidia").unwrap_err();
        assert!(error.contains("audited runtime generation"), "{error}");

        fixture.sys.env.insert("AVX2_RUNTIME".into(), "none".into());
        assert_eq!(
            private_libraries(&fixture.sys, &fixture.home, "nvidia").unwrap(),
            None
        );
    }

    #[test]
    fn the_default_generation_is_the_per_gpu_link() {
        let fixture = Fixture::new("wrapper-current");
        glibc(&fixture, "2.44-1");
        let libraries = fixture.runtime("amd");
        fs::create_dir_all(fixture.home.generations()).unwrap();
        symlink(&libraries, fixture.home.generations().join("amd-current")).unwrap();
        assert_eq!(
            private_libraries(&fixture.sys, &fixture.home, "amd").unwrap(),
            Some(fs::canonicalize(&libraries).unwrap())
        );
        let error = private_libraries(&fixture.sys, &fixture.home, "intel").unwrap_err();
        assert!(error.contains("No selected runtime"), "{error}");
    }

    fn steam_fixture(fixture: &Fixture) -> Vec<String> {
        let runtime = fixture.root.join("Steam Runtime with spaces");
        fs::create_dir_all(&runtime).unwrap();
        fs::write(runtime.join("_v2-entry-point"), "x").unwrap();
        fs::write(
            runtime.join("toolmanifest.vdf"),
            "\"manifest\" { \"compatmanager_layer_name\" \"container-runtime\" }",
        )
        .unwrap();
        [
            "reaper".to_string(),
            "SteamLaunch".into(),
            "AppId=123".into(),
            "--".into(),
            runtime
                .join("_v2-entry-point")
                .to_string_lossy()
                .into_owned(),
            "--verb=waitforexitandrun".into(),
            "--".into(),
            fixture
                .original
                .join("proton")
                .to_string_lossy()
                .into_owned(),
            "waitforexitandrun".into(),
            "game with spaces.exe".into(),
            "argument with spaces".into(),
        ]
        .to_vec()
    }

    #[test]
    fn steam_commands_keep_their_outer_arguments_and_runtime() {
        let fixture = Fixture::new("wrapper-steam");
        let command = steam_fixture(&fixture);
        let (original, index) = steam_proton(&command).unwrap();
        assert_eq!(original, fs::canonicalize(&fixture.original).unwrap());
        assert_eq!(index, 7);
        let companion = fixture.prepare();
        let rewritten = steam_command(&command, &companion, index);
        assert_eq!(rewritten[..index], command[..index]);
        assert_eq!(rewritten[index], companion.join("proton").to_string_lossy());
        assert_eq!(rewritten[index + 1], companion.join(RUNNER).to_string_lossy());
        assert_eq!(
            rewritten[index + 2],
            companion.join("original/proton").to_string_lossy()
        );
        assert_eq!(rewritten[index + 3..], command[index + 1..]);
    }

    #[test]
    fn steam_commands_without_the_container_are_rejected() {
        let fixture = Fixture::new("wrapper-steam-reject");
        let proton = fixture
            .original
            .join("proton")
            .to_string_lossy()
            .into_owned();
        let error = steam_proton(&[proton.clone(), "run".into(), "game.exe".into()]).unwrap_err();
        assert!(error.contains("Steam Linux Runtime"), "{error}");
        assert!(steam_proton(&["/usr/bin/true".into()]).is_err());

        let mut command = steam_fixture(&fixture);
        command[8] = "unknown-verb".into();
        let error = steam_proton(&command).unwrap_err();
        assert!(error.contains("verb"), "{error}");

        let mut command = steam_fixture(&fixture);
        command.remove(6);
        let error = steam_proton(&command).unwrap_err();
        assert!(error.contains("inside Steam Linux Runtime"), "{error}");
    }

    #[test]
    fn a_lutris_launch_is_planned_end_to_end() {
        let mut fixture = Fixture::new("wrapper-plan");
        fixture.sys.env.insert(
            "AVX2_PROTON_PATH".into(),
            fixture.original.to_string_lossy().into_owned(),
        );
        let command = ["umu-run".to_string(), "game.exe".into()];
        let runtime = RuntimeInfo {
            state: RuntimeState::NotRequired("test".into()),
            gpu: "nvidia".into(),
            host_glibc: None,
            home: fixture.home.root.clone(),
            exe: "pingu-launcher".into(),
        };
        let prepared = plan(&fixture.sys, &fixture.home, Some(&runtime), &command).unwrap();
        assert!(prepared.program.ends_with("bin/bwrap"));
        assert_eq!(
            prepared.args[prepared.args.len() - 3..],
            ["--", "umu-run", "game.exe"]
        );
        assert_eq!(value(&prepared.env, "AVX2_POLICY"), Some("xcr0-only"));
        assert!(prepared.note.contains("restricting XCR0"));
        let helper = fixture.home.bin().join("avx2-run");
        assert_eq!(fs::read(&helper).unwrap(), assets::AVX2_RUN);
        let companion = PathBuf::from(value(&prepared.env, "PROTONPATH").unwrap());
        assert_eq!(
            fs::read(companion.join("proton")).unwrap(),
            assets::AVX2_RUN
        );
    }

    #[test]
    fn a_kernel_without_the_policy_stops_the_launch() {
        let mut fixture = Fixture::new("wrapper-arm");
        fixture.sys.arm_check = |_, _| Err("Operation not supported".into());
        fixture.sys.env.insert(
            "AVX2_PROTON_PATH".into(),
            fixture.original.to_string_lossy().into_owned(),
        );
        let error = plan(&fixture.sys, &fixture.home, None, &["umu-run".to_string()]).unwrap_err();
        assert!(error.contains("Operation not supported"), "{error}");

        // Runtime-only mode never arms the restriction.
        fixture
            .sys
            .env
            .insert("AVX2_POLICY".into(), "runtime-only".into());
        fixture.sys.env.insert("AVX2_RUNTIME".into(), "none".into());
        let runtime = RuntimeInfo {
            state: RuntimeState::NotRequired("test".into()),
            gpu: "nvidia".into(),
            host_glibc: None,
            home: fixture.home.root.clone(),
            exe: "pingu-launcher".into(),
        };
        assert!(
            plan(
                &fixture.sys,
                &fixture.home,
                Some(&runtime),
                &["umu-run".to_string()]
            )
            .is_ok()
        );
    }

    #[test]
    fn invalid_policy_settings_are_rejected() {
        let mut fixture = Fixture::new("wrapper-settings");
        fixture
            .sys
            .env
            .insert("AVX2_POLICY".into(), "sometimes".into());
        assert!(
            plan(&fixture.sys, &fixture.home, None, &["umu-run".to_string()])
                .unwrap_err()
                .contains("AVX2_POLICY")
        );

        fixture.sys.env.insert("AVX2_POLICY".into(), "1".into());
        fixture.sys.env.insert("UMU_NO_RUNTIME".into(), "1".into());
        assert!(
            plan(&fixture.sys, &fixture.home, None, &["umu-run".to_string()])
                .unwrap_err()
                .contains("container runtime")
        );

        fixture.sys.env.remove("UMU_NO_RUNTIME");
        let error = plan(&fixture.sys, &fixture.home, None, &["umu-run".to_string()]).unwrap_err();
        assert!(error.contains("AVX2_PROTON_PATH"), "{error}");
    }
}
