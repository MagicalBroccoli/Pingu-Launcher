//! The runtime builder: resolves, downloads, verifies and audits the generic Arch runtime that
//! replaces AVX-512 host libraries. It drives the Arch tools (pacman, curl, gpgv, bsdtar).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::cmd::{self, Cancel};
use crate::elf;
use crate::fsutil::{self, TempDir, normpath, relpath};

pub const GENERATION_SCHEMA: i64 = 2;
pub const DEFAULT_MIRROR: &str = "https://geo.mirror.pkgbuild.com";
pub const GPUS: [&str; 3] = ["nvidia", "amd", "intel"];
const ARCHIVE: &str = "https://archive.archlinux.org";
const KEYRING: &str = "/usr/share/pacman/keyrings/archlinux.gpg";
const REPOSITORIES: [&str; 3] = ["core", "extra", "multilib"];
const COMMON_PACKAGES: [&str; 19] = [
    "glibc",
    "lib32-glibc",
    "vulkan-icd-loader",
    "lib32-vulkan-icd-loader",
    "libglvnd",
    "lib32-libglvnd",
    "wayland",
    "lib32-wayland",
    "libx11",
    "lib32-libx11",
    "libxcb",
    "lib32-libxcb",
    // Pressure-vessel imports the host copy (a dependency of libva-x11), which Valve's winex11 calls.
    "libxfixes",
    "lib32-libxfixes",
    "libxkbcommon",
    "libxkbcommon-x11",
    "libdrm",
    "lib32-libdrm",
    "mangohud",
];
const ROUNDS: usize = 5;

fn gpu_packages(gpu: &str) -> Option<&'static [&'static str]> {
    match gpu {
        "nvidia" => Some(&["egl-wayland2", "egl-wayland", "egl-gbm", "egl-x11"]),
        "amd" => Some(&["mesa", "lib32-mesa", "vulkan-radeon", "lib32-vulkan-radeon"]),
        "intel" => Some(&["mesa", "lib32-mesa", "vulkan-intel", "lib32-vulkan-intel"]),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingLib {
    pub path: String,
    pub bits: u32,
    pub name: String,
}

/// Why a build or audit stopped. Missing libraries are recoverable by adding their packages.
#[derive(Debug)]
pub enum Failure {
    Missing(Vec<MissingLib>),
    Message(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
            Self::Missing(missing) => {
                formatter.write_str("Unresolved runtime ELF dependencies:")?;
                for item in missing {
                    write!(
                        formatter,
                        "\n{}: {} ({}-bit)",
                        item.path, item.name, item.bits
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self::Message(message.to_string())
    }
}

/// The audited libraries of a generation, as recorded in its manifest.
#[derive(Debug)]
pub struct Audit {
    pub elf_libraries: Vec<Value>,
    pub library_paths: Vec<String>,
}

/// Names of the helper programs; tests substitute stand-ins.
#[derive(Clone, Debug)]
pub struct Tools {
    pub curl: String,
    pub pacman: String,
    pub gpg: String,
    pub gpgv: String,
    pub bsdtar: String,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            curl: "curl".into(),
            pacman: "pacman".into(),
            gpg: "gpg".into(),
            gpgv: "gpgv".into(),
            bsdtar: "bsdtar".into(),
        }
    }
}

// --- JSON in the exact form Python's json module writes it ---------------------------------

fn escape_json(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if !(' '..='~').contains(&c) => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_json(value: &Value, indent: Option<usize>, level: usize, out: &mut String) {
    let newline = |out: &mut String, level: usize| {
        if let Some(width) = indent {
            out.push('\n');
            out.push_str(&" ".repeat(width * level));
        }
    };
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => escape_json(text, out),
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, level + 1);
                write_json(item, indent, level + 1, out);
            }
            newline(out, level);
            out.push(']');
        }
        Value::Object(map) if map.is_empty() => out.push_str("{}"),
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, level + 1);
                escape_json(key, out);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                write_json(item, indent, level + 1, out);
            }
            newline(out, level);
            out.push('}');
        }
    }
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, None, 0, &mut out);
    out
}

/// `json.dumps(value, sort_keys=True, indent=2)`.
pub fn pretty_json(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, Some(2), 0, &mut out);
    out
}

fn write_json_file(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    let result = fs::write(&temporary, pretty_json(value) + "\n")
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| format!("{}: {error}", path.display()))
}

/// The directory name component of a generation: the lock plus the builder schema, hashed.
pub fn lock_identity(lock: &Value) -> String {
    let document = json!({ "builder": GENERATION_SCHEMA, "lock": lock });
    hex(&Sha256::digest(canonical_json(&document).as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Standard base64 with padding; anything outside the alphabet is an error.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("Incorrect base64 padding".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let padding = chunk.iter().rev().take_while(|&&byte| byte == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return Err("Incorrect base64 padding".into());
        }
        let mut accumulator = 0u32;
        for &byte in &chunk[..4 - padding] {
            accumulator = accumulator << 6 | value(byte).ok_or("Non-base64 character")?;
        }
        accumulator <<= 6 * padding as u32;
        let produced = 3 - padding;
        out.extend_from_slice(&accumulator.to_be_bytes()[1..1 + produced]);
    }
    Ok(out)
}

/// `urllib.parse.quote(text, safe="")`.
pub fn url_quote(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

// --- pacman databases -----------------------------------------------------------------------

pub type Fields = HashMap<String, Vec<String>>;

/// Parses a pacman `desc` or `files` entry into its `%FIELD%` sections.
pub fn parse_fields(text: &str) -> Fields {
    let mut fields = Fields::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.len() >= 2 && line.starts_with('%') && line.ends_with('%') {
            let key = line[1..line.len() - 1].to_string();
            fields.insert(key.clone(), Vec::new());
            current = Some(key);
        } else if !line.is_empty()
            && let Some(key) = &current
        {
            fields
                .entry(key.clone())
                .or_default()
                .push(line.to_string());
        }
    }
    fields
}

/// Calls `visit(entry name, content)` for every regular file of a (gzip) tar archive.
fn each_archive_file(
    path: &Path,
    mut visit: impl FnMut(&str, String) -> Result<(), String>,
) -> Result<(), String> {
    let mut file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut magic = [0u8; 2];
    let known = file.read(&mut magic).map_err(|error| error.to_string())? == 2;
    let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let reader: Box<dyn Read> = if known && magic == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .into_owned();
        let mut content = String::new();
        entry
            .read_to_string(&mut content)
            .map_err(|error| format!("Unreadable repository entry {name}: {error}"))?;
        visit(&name, content)?;
    }
    Ok(())
}

/// The packages of a sync database by name.
pub fn read_database(path: &Path) -> Result<HashMap<String, Fields>, String> {
    let mut packages = HashMap::new();
    each_archive_file(path, |name, content| {
        if name.ends_with("/desc") {
            let fields = parse_fields(&content);
            let package = fields
                .get("NAME")
                .and_then(|names| names.first())
                .ok_or_else(|| format!("Repository entry {name} has no NAME"))?
                .clone();
            packages.insert(package, fields);
        }
        Ok(())
    })?;
    Ok(packages)
}

pub fn package_urls(package: &Value, mirror: &str) -> Vec<String> {
    let filename = url_quote(package["filename"].as_str().unwrap_or_default());
    let name = url_quote(package["name"].as_str().unwrap_or_default());
    let first = name.chars().next().unwrap_or('_');
    vec![
        format!(
            "{}/{}/os/x86_64/{filename}",
            mirror.trim_end_matches('/'),
            package["repository"].as_str().unwrap_or_default()
        ),
        format!("{ARCHIVE}/packages/{first}/{name}/{filename}"),
    ]
}

// --- the generation's file system ----------------------------------------------------------

fn library_files(root: &Path) -> Result<Vec<PathBuf>, Failure> {
    fn walk(directory: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let entries =
            fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if meta.is_dir() {
                walk(&path, out)?;
            } else if !fs::metadata(&path).is_ok_and(|target| target.is_dir()) {
                out.push(path);
            }
        }
        Ok(())
    }

    let resolved_root =
        fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let mut files = Vec::new();
    for relative in ["usr/lib", "usr/lib32"] {
        let directory = root.join(relative);
        if !directory.is_dir() {
            continue;
        }
        let mut candidates = Vec::new();
        walk(&directory, &mut candidates)?;
        for path in candidates {
            let inside = path.strip_prefix(root).unwrap_or(&path);
            let components: Vec<_> = inside
                .components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect();
            let name = components.last().map(String::as_str).unwrap_or("");
            if !name.contains(".so") && !components.iter().any(|part| part == "gconv") {
                continue;
            }
            if components.iter().any(|part| part == "glibc-hwcaps") {
                continue;
            }
            let resolved =
                fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            if !resolved.starts_with(&resolved_root) {
                return Err(
                    format!("Runtime library escapes generation: {}", path.display()).into(),
                );
            }
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Makes every symlink below `usr` relative and keeps library links inside the generation.
pub fn normalize_links(root: &Path) -> Result<(), String> {
    fn collect(directory: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let entries =
            fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if meta.file_type().is_symlink() {
                out.push(path);
            } else if meta.is_dir() {
                collect(&path, out)?;
            }
        }
        Ok(())
    }

    let usr = root.join("usr");
    if !usr.is_dir() {
        return Ok(());
    }
    let mut links = Vec::new();
    collect(&usr, &mut links)?;
    for path in links {
        let target =
            fs::read_link(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let target = target.to_string_lossy().into_owned();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        let destination = if target.starts_with('/') {
            normpath(&target).trim_start_matches('/').to_string()
        } else {
            let parent = relative.parent().unwrap_or(Path::new(""));
            normpath(&parent.join(&target).to_string_lossy())
        };
        if !destination.starts_with("usr/") {
            if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains(".so"))
            {
                return Err(format!(
                    "Library link escapes runtime: {} -> {target}",
                    relative.display()
                ));
            }
            continue;
        }
        fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let parent = path.parent().unwrap_or(root);
        symlink(relpath(&root.join(&destination), parent), &path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(())
}

/// Checks that every `DT_NEEDED` name of the generation's libraries has a provider of the same
/// word size and that none explicitly requires x86-64-v4.
pub fn inspect_libraries(root: &Path) -> Result<Audit, Failure> {
    let libraries = library_files(root)?;
    let mut available: [BTreeSet<String>; 2] = [BTreeSet::new(), BTreeSet::new()];
    let mut requirements: Vec<(String, u32, Vec<String>)> = Vec::new();
    let mut seen = BTreeSet::new();
    let relative = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    };
    let slot = |bits: u32| usize::from(bits == 64);
    for path in &libraries {
        let resolved =
            fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))?;
        if !seen.insert(resolved.clone()) {
            continue;
        }
        let Some(info) = elf::inspect(&resolved)? else {
            continue;
        };
        if let Some(name) = resolved.file_name() {
            available[slot(info.bits)].insert(name.to_string_lossy().into_owned());
        }
        if info.needs_x86_64_v4 {
            return Err(
                format!("Library explicitly requires x86-64-v4: {}", relative(path)).into(),
            );
        }
        if let Some(soname) = info.soname {
            available[slot(info.bits)].insert(soname);
        }
        requirements.push((relative(path), info.bits, info.needed));
    }
    let mut missing = Vec::new();
    for (path, bits, needed) in &requirements {
        for dependency in needed {
            if !available[slot(*bits)].contains(dependency) {
                missing.push(MissingLib {
                    path: path.clone(),
                    bits: *bits,
                    name: dependency.clone(),
                });
            }
        }
    }
    if !missing.is_empty() {
        return Err(Failure::Missing(missing));
    }
    Ok(Audit {
        elf_libraries: requirements
            .into_iter()
            .map(|(path, bits, needed)| json!({ "path": path, "bits": bits, "needed": needed }))
            .collect(),
        library_paths: libraries.iter().map(|path| relative(path)).collect(),
    })
}

// --- the builder ----------------------------------------------------------------------------

pub struct Builder<'a> {
    /// Package downloads and scratch space.
    pub work: PathBuf,
    /// Where generations are created and selected.
    pub output: PathBuf,
    pub tools: Tools,
    pub keyring: PathBuf,
    /// Rebuilds a generation that already exists instead of reusing it.
    pub replace: bool,
    pub cancel: &'a Cancel,
    pub log: &'a (dyn Fn(&str) + Sync),
}

impl<'a> Builder<'a> {
    pub fn new(
        work: PathBuf,
        output: PathBuf,
        cancel: &'a Cancel,
        log: &'a (dyn Fn(&str) + Sync),
    ) -> Self {
        Self {
            work,
            output,
            tools: Tools::default(),
            keyring: PathBuf::from(KEYRING),
            replace: false,
            cancel,
            log,
        }
    }

    fn run(&self, command: &mut Command, seconds: u64) -> Result<cmd::Output, String> {
        cmd::run_checked(command, Duration::from_secs(seconds), Some(self.cancel))
    }

    /// Fetches the first location that works into `destination`, verifying `checksum`.
    pub fn download(
        &self,
        urls: &[String],
        destination: &Path,
        checksum: Option<&str>,
        offline: bool,
    ) -> Result<(), String> {
        if let Some(checksum) = checksum
            && destination.is_file()
            && sha256_file(destination)? == checksum
        {
            return Ok(());
        }
        let name = destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if offline {
            return Err(format!(
                "Offline cache entry missing or corrupt: {}",
                destination.display()
            ));
        }
        let parent = destination.parent().unwrap_or(Path::new("."));
        let scratch = TempDir::new_in(parent, "download-").map_err(|error| error.to_string())?;
        let candidate = scratch.path().join("payload");
        (self.log)(&format!("Downloading {name}"));
        for url in urls {
            if !url.starts_with("https://") {
                return Err(format!("Only HTTPS downloads are allowed: {url}"));
            }
            let output = cmd::run(
                Command::new(&self.tools.curl)
                    .args([
                        "--fail",
                        "--location",
                        "--silent",
                        "--show-error",
                        "--max-time",
                        "180",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--output",
                    ])
                    .arg(&candidate)
                    .arg(url),
                Duration::from_secs(190),
                Some(self.cancel),
            )?;
            if !output.success() {
                continue;
            }
            if let Some(checksum) = checksum
                && sha256_file(&candidate)? != checksum
            {
                return Err(format!("SHA-256 mismatch: {url}"));
            }
            fs::rename(&candidate, destination)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            return Ok(());
        }
        Err(format!(
            "Download unavailable from all recorded locations: {name}"
        ))
    }

    fn resolve_packages(
        &self,
        config: &Path,
        database: &Path,
        seeds: &[String],
        records: &HashMap<&str, HashMap<String, Fields>>,
    ) -> Result<Vec<Value>, String> {
        let output = self.run(
            Command::new(&self.tools.pacman)
                .arg("--config")
                .arg(config)
                .arg("--dbpath")
                .arg(database)
                .args([
                    "--sync",
                    "--print",
                    "--print-format",
                    "%r/%n",
                    "--noconfirm",
                    "--",
                ])
                .args(seeds),
            120,
        )?;
        let mut selected = Vec::new();
        for line in output.stdout.lines() {
            let (repository, name) = line
                .split_once('/')
                .ok_or_else(|| format!("Unexpected pacman output: {line}"))?;
            let record = records
                .get(repository)
                .and_then(|packages| packages.get(name))
                .ok_or_else(|| format!("{line} is not in the downloaded databases"))?;
            let first = |key: &str| -> Result<String, String> {
                record
                    .get(key)
                    .and_then(|values| values.first())
                    .cloned()
                    .ok_or_else(|| format!("{name} has no {key}"))
            };
            selected.push(json!({
                "name": name,
                "repository": repository,
                "version": first("VERSION")?,
                "filename": first("FILENAME")?,
                "sha256": first("SHA256SUM")?,
                "signature": record.get("PGPSIG").and_then(|values| values.first()),
                "dependencies": record.get("DEPENDS").cloned().unwrap_or_default(),
            }));
        }
        selected.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        Ok(selected)
    }

    /// Resolves the package set for `gpu` (plus `seeds`) into a lock.
    pub fn create_lock(&self, gpu: &str, mirror: &str, seeds: &[String]) -> Result<Value, String> {
        if !mirror.starts_with("https://") || mirror.contains(['\r', '\n']) {
            return Err("An HTTPS Arch mirror is required".into());
        }
        let gpu_roots = gpu_packages(gpu).ok_or_else(|| format!("Unknown GPU {gpu}"))?;
        let mirror = mirror.trim_end_matches('/');
        let scratch = TempDir::new_in(&self.work, "resolve-").map_err(|error| error.to_string())?;
        let database = scratch.path().join("db");
        let root = scratch.path().join("root");
        for directory in [database.join("sync"), database.join("local"), root.clone()] {
            fs::create_dir_all(&directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
        }
        let config = scratch.path().join("pacman.conf");
        let mut text = format!(
            "[options]\nArchitecture = x86_64\nRootDir = {}\nDBPath = {}\nLogFile = {}\nSigLevel = Never\n",
            root.display(),
            database.display(),
            scratch.path().join("pacman.log").display()
        );
        for repository in REPOSITORIES {
            text.push_str(&format!(
                "[{repository}]\nServer = {mirror}/{repository}/os/x86_64\n"
            ));
        }
        fs::write(&config, text).map_err(|error| format!("{}: {error}", config.display()))?;

        let mut records = HashMap::new();
        for repository in REPOSITORIES {
            let path = database.join("sync").join(format!("{repository}.db"));
            self.download(
                &[format!("{mirror}/{repository}/os/x86_64/{repository}.db")],
                &path,
                None,
                false,
            )?;
            records.insert(repository, read_database(&path)?);
        }
        let roots: BTreeSet<String> = COMMON_PACKAGES
            .iter()
            .chain(gpu_roots)
            .map(|name| name.to_string())
            .chain(seeds.iter().cloned())
            .collect();
        let roots: Vec<String> = roots.into_iter().collect();
        let mut packages = self.resolve_packages(&config, &database, &roots, &records)?;
        for package in &mut packages {
            package["urls"] = json!(package_urls(package, mirror));
        }
        Ok(json!({
            "schema": 1,
            "gpu": gpu,
            "mirror": mirror,
            "roots": roots,
            "packages": packages,
        }))
    }

    /// Downloads and checks the signature of every package of `lock`.
    pub fn verified_packages(&self, lock: &Value, offline: bool) -> Result<Vec<PathBuf>, String> {
        let cache = self.work.join("downloads");
        fs::create_dir_all(&cache).map_err(|error| format!("{}: {error}", cache.display()))?;
        let home = TempDir::new_in(&self.work, "signature-").map_err(|error| error.to_string())?;
        let ring = home.path().join("archlinux.gpg");
        self.run(
            Command::new(&self.tools.gpg)
                .args(["--no-options", "--homedir"])
                .arg(home.path())
                .args(["--batch", "--yes", "--dearmor", "--output"])
                .arg(&ring)
                .arg(&self.keyring),
            30,
        )?;
        let mut archives = Vec::new();
        let packages = lock["packages"]
            .as_array()
            .ok_or("The lock lists no packages")?;
        for package in packages {
            let text = |key: &str| package[key].as_str().unwrap_or_default();
            let filename = text("filename");
            let checksum = text("sha256");
            let plain = Path::new(filename)
                .file_name()
                .is_some_and(|name| name == filename);
            let valid = checksum.len() == 64
                && checksum
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
            if !plain || !valid {
                return Err("Invalid package filename or checksum in lockfile".into());
            }
            let urls: Vec<String> = package["urls"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|url| url.as_str().map(str::to_string))
                .collect();
            let archive = cache.join(filename);
            self.download(&urls, &archive, Some(checksum), offline)?;

            let signature = home.path().join("package.sig");
            let cached = cache.join(format!("{filename}.sig"));
            match package["signature"]
                .as_str()
                .filter(|text| !text.is_empty())
            {
                Some(encoded) => {
                    fs::write(&signature, base64_decode(encoded)?)
                        .map_err(|error| format!("{}: {error}", signature.display()))?;
                }
                None if offline => {
                    fs::copy(&cached, &signature)
                        .map_err(|error| format!("{}: {error}", cached.display()))?;
                }
                None => {
                    let urls: Vec<String> = urls.iter().map(|url| format!("{url}.sig")).collect();
                    self.download(&urls, &signature, None, false)?;
                }
            }
            let output = cmd::run(
                Command::new(&self.tools.gpgv)
                    .arg("--homedir")
                    .arg(home.path())
                    .arg("--keyring")
                    .arg(&ring)
                    .arg(&signature)
                    .arg(&archive),
                Duration::from_secs(30),
                Some(self.cancel),
            )?;
            if !output.success() {
                return Err(format!(
                    "Signature verification failed for {filename}: {}",
                    output.stderr.trim()
                ));
            }
            fs::copy(&signature, &cached)
                .map_err(|error| format!("{}: {error}", cached.display()))?;
            archives.push(archive);
            (self.log)(&format!("Verified {} {}", text("name"), text("version")));
        }
        Ok(archives)
    }

    /// Creates the generation for `lock` (or finds it again) and returns its directory.
    pub fn build_runtime(&self, lock: &Value, offline: bool) -> Result<PathBuf, Failure> {
        let gpu = lock["gpu"].as_str().unwrap_or_default();
        if lock["schema"].as_i64() != Some(1) || gpu_packages(gpu).is_none() {
            return Err("Unsupported runtime lockfile".into());
        }
        let identity = lock_identity(lock);
        let destination = self.output.join(format!("{gpu}-{}", &identity[..20]));
        if destination.exists() && !self.replace {
            let text = fs::read_to_string(destination.join("runtime.json"))
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            let manifest: Value = serde_json::from_str(&text)
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            if manifest["lock_sha256"].as_str() != Some(identity.as_str()) {
                return Err("Existing runtime generation does not match lockfile".into());
            }
            inspect_libraries(&destination)?;
            return Ok(destination);
        }
        fs::create_dir_all(&self.work)
            .map_err(|error| format!("{}: {error}", self.work.display()))?;
        let packages = self.verified_packages(lock, offline)?;
        fs::create_dir_all(&self.output)
            .map_err(|error| format!("{}: {error}", self.output.display()))?;
        let build = TempDir::new_in(&self.output, ".build-").map_err(|error| error.to_string())?;
        let root = build.path().to_path_buf();
        for package in &packages {
            let listing = self.run(Command::new(&self.tools.bsdtar).arg("-tf").arg(package), 60)?;
            let mut has_usr = false;
            for name in listing.stdout.lines() {
                let parts: Vec<&str> = name
                    .split('/')
                    .filter(|part| !part.is_empty() && *part != ".")
                    .collect();
                if name.starts_with('/') || parts.contains(&"..") {
                    return Err(format!(
                        "Unsafe path in package: {}",
                        package.file_name().unwrap_or_default().to_string_lossy()
                    )
                    .into());
                }
                has_usr |= parts.first() == Some(&"usr");
            }
            if !has_usr {
                continue;
            }
            (self.log)(&format!(
                "Extracting {}",
                package.file_name().unwrap_or_default().to_string_lossy()
            ));
            self.run(
                Command::new(&self.tools.bsdtar)
                    .args(["--no-same-owner", "--unlink-first", "-xf"])
                    .arg(package)
                    .arg("-C")
                    .arg(&root)
                    .arg("usr"),
                120,
            )?;
        }
        let glibc = lock["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|package| package["name"] == "glibc")
            .and_then(|package| package["version"].as_str())
            .ok_or("The lock does not list glibc")?
            .to_string();
        normalize_links(&root)?;
        (self.log)("Auditing the libraries");
        let audit = inspect_libraries(&root)?;
        let mut manifest = Map::new();
        manifest.insert("schema".into(), json!(GENERATION_SCHEMA));
        manifest.insert("gpu".into(), json!(gpu));
        manifest.insert("glibc".into(), json!(glibc));
        manifest.insert("lock_sha256".into(), json!(identity));
        manifest.insert("elf_libraries".into(), Value::Array(audit.elf_libraries));
        manifest.insert("library_paths".into(), json!(audit.library_paths));
        write_json_file(&root.join("runtime.json"), &Value::Object(manifest))?;
        write_json_file(&root.join("runtime.lock.json"), lock)?;
        fs::write(root.join("VERSION"), format!("{glibc}\n"))
            .map_err(|error| format!("{}: {error}", root.join("VERSION").display()))?;
        let root = build.into_path();
        // The old generation moves aside first so the selected link never dangles for long.
        let old = if destination.exists() {
            let old = TempDir::new_in(&self.output, ".old-").map_err(|error| error.to_string())?;
            fs::rename(&destination, old.path().join("generation"))
                .map_err(|error| format!("{}: {error}", destination.display()))?;
            Some(old)
        } else {
            None
        };
        if let Err(error) = fs::rename(&root, &destination) {
            if let Some(old) = &old {
                let _ = fs::rename(old.path().join("generation"), &destination);
            }
            let _ = fs::remove_dir_all(&root);
            return Err(format!("{}: {error}", destination.display()).into());
        }
        Ok(destination)
    }

    /// Looks up which packages provide the missing libraries.
    pub fn find_library_providers(
        &self,
        missing: &[MissingLib],
        mirror: &str,
        scratch: &Path,
    ) -> Result<Vec<String>, String> {
        let wanted: BTreeSet<(u32, String)> = missing
            .iter()
            .map(|item| (item.bits, item.name.clone()))
            .collect();
        let mut matches: BTreeMap<(u32, String), BTreeSet<String>> = wanted
            .iter()
            .map(|key| (key.clone(), BTreeSet::new()))
            .collect();
        for repository in REPOSITORIES {
            let database = scratch.join(format!("{repository}.files"));
            if !database.exists() {
                self.download(
                    &[format!(
                        "{}/{repository}/os/x86_64/{repository}.files",
                        mirror.trim_end_matches('/')
                    )],
                    &database,
                    None,
                    false,
                )?;
            }
            let mut names: HashMap<String, String> = HashMap::new();
            let mut listings: HashMap<String, BTreeSet<(u32, String)>> = HashMap::new();
            each_archive_file(&database, |entry, content| {
                let Some((owner, file)) = entry.rsplit_once('/') else {
                    return Ok(());
                };
                match file {
                    "desc" => {
                        if let Some(name) = parse_fields(&content)
                            .get("NAME")
                            .and_then(|names| names.first())
                        {
                            names.insert(owner.to_string(), name.clone());
                        }
                    }
                    "files" => {
                        let mut selected = BTreeSet::new();
                        for filename in parse_fields(&content).get("FILES").into_iter().flatten() {
                            let bits = if filename.starts_with("usr/lib32/") {
                                32
                            } else if filename.starts_with("usr/lib/") {
                                64
                            } else {
                                0
                            };
                            let base = filename.rsplit('/').next().unwrap_or(filename);
                            let key = (bits, base.to_string());
                            if wanted.contains(&key) {
                                selected.insert(key);
                            }
                        }
                        if !selected.is_empty() {
                            listings.insert(owner.to_string(), selected);
                        }
                    }
                    _ => {}
                }
                Ok(())
            })?;
            for (owner, keys) in listings {
                let Some(name) = names.get(&owner) else {
                    continue;
                };
                for key in keys {
                    if let Some(found) = matches.get_mut(&key) {
                        found.insert(name.clone());
                    }
                }
            }
        }
        let mut providers = BTreeSet::new();
        for (key, candidates) in matches {
            if candidates.len() != 1 {
                return Err(format!(
                    "Cannot choose a unique package for {} ({}-bit): {:?}; specify an extra package",
                    key.1, key.0, candidates
                ));
            }
            providers.extend(candidates);
        }
        Ok(providers.into_iter().collect())
    }

    /// Resolves current packages for `gpu`, adding providers of missing libraries, builds the
    /// generation and records the lock in `lock_path` on success.
    pub fn update(
        &self,
        gpu: &str,
        mirror: &str,
        extras: &[String],
        lock_path: &Path,
    ) -> Result<PathBuf, String> {
        fs::create_dir_all(&self.work)
            .map_err(|error| format!("{}: {error}", self.work.display()))?;
        let providers =
            TempDir::new_in(&self.work, "providers-").map_err(|error| error.to_string())?;
        let mut extras: BTreeSet<String> = extras.iter().cloned().collect();
        for _ in 0..ROUNDS {
            let seeds: Vec<String> = extras.iter().cloned().collect();
            let lock = self.create_lock(gpu, mirror, &seeds)?;
            match self.build_runtime(&lock, false) {
                Ok(destination) => {
                    write_json_file(lock_path, &lock)?;
                    return Ok(destination);
                }
                Err(Failure::Message(message)) => return Err(message),
                Err(Failure::Missing(missing)) => {
                    let found: BTreeSet<String> = self
                        .find_library_providers(&missing, mirror, providers.path())?
                        .into_iter()
                        .collect();
                    if found.is_subset(&extras) {
                        return Err(Failure::Missing(missing).to_string());
                    }
                    (self.log)(&format!(
                        "Adding ELF dependency providers: {}",
                        found.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                    extras.extend(found);
                }
            }
        }
        Err("ELF dependency completion exceeded five rounds; previous lockfile unchanged".into())
    }

    /// Selects `runtime` through the stable per-GPU `<gpu>-current` link.
    pub fn select(&self, runtime: &Path, host_glibc: &str) -> Result<PathBuf, String> {
        let runtime =
            fs::canonicalize(runtime).map_err(|error| format!("{}: {error}", runtime.display()))?;
        let text = fs::read_to_string(runtime.join("runtime.json"))
            .map_err(|error| format!("{}: {error}", runtime.display()))?;
        let manifest: Value = serde_json::from_str(&text)
            .map_err(|error| format!("{}: {error}", runtime.display()))?;
        let gpu = manifest["gpu"].as_str().unwrap_or_default();
        if manifest["schema"].as_i64() != Some(GENERATION_SCHEMA) || gpu_packages(gpu).is_none() {
            return Err("Unsupported runtime generation".into());
        }
        if manifest["glibc"].as_str() != Some(host_glibc) {
            return Err(
                "Generation glibc does not match the host; previous selection unchanged".into(),
            );
        }
        inspect_libraries(&runtime).map_err(|failure| failure.to_string())?;
        let parent = runtime
            .parent()
            .ok_or("The generation has no parent directory")?;
        let destination = parent.join(format!("{gpu}-current"));
        if destination.exists() && !fsutil::is_symlink(&destination) {
            return Err(format!(
                "Refusing to overwrite a non-symlink: {}",
                destination.display()
            ));
        }
        let scratch = TempDir::new_in(parent, ".select-").map_err(|error| error.to_string())?;
        let link = scratch.path().join("link");
        symlink(&runtime, &link).map_err(|error| format!("{}: {error}", link.display()))?;
        fs::rename(&link, &destination)
            .map_err(|error| format!("{}: {error}", destination.display()))?;
        Ok(destination)
    }
}
