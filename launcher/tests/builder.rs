//! The runtime builder against stand-ins for curl, pacman, gpg and gpgv and real bsdtar.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use pingu_launcher::builder::{
    self, Builder, Failure, Tools, base64_decode, canonical_json, inspect_libraries, lock_identity,
    normalize_links, package_urls, parse_fields, pretty_json, url_quote,
};
use pingu_launcher::cmd::Cancel;
use pingu_launcher::home::Home;
use pingu_launcher::runtime::Provision;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{name}-{}", COUNTER.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    directory
}

fn bsdtar_available() -> bool {
    Command::new("bsdtar").arg("--version").output().is_ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

// --- fixtures ---------------------------------------------------------------------------------

/// An ELF64 file with a dynamic section naming `needed`, an optional soname and an ISA note.
fn elf64(needed: &[&str], soname: Option<&str>, isa_needed: Option<u32>) -> Vec<u8> {
    let push16 = |out: &mut Vec<u8>, value: u16| out.extend_from_slice(&value.to_le_bytes());
    let push32 = |out: &mut Vec<u8>, value: u32| out.extend_from_slice(&value.to_le_bytes());
    let push64 = |out: &mut Vec<u8>, value: u64| out.extend_from_slice(&value.to_le_bytes());

    let mut strings = vec![0u8];
    let mut offsets = Vec::new();
    for name in needed.iter().copied().chain(soname) {
        offsets.push(strings.len() as u64);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    let mut note = Vec::new();
    if let Some(flags) = isa_needed {
        push32(&mut note, 4);
        push32(&mut note, 16);
        push32(&mut note, 5);
        note.extend_from_slice(b"GNU\0");
        push32(&mut note, 0xc000_8002);
        push32(&mut note, 4);
        push32(&mut note, flags);
        push32(&mut note, 0);
    }
    let strtab = 64 + 3 * 56;
    let note_at = strtab + strings.len() as u64;
    let dynamic = note_at + note.len() as u64;
    let mut entries = Vec::new();
    for offset in offsets.iter().take(needed.len()) {
        push64(&mut entries, 1);
        push64(&mut entries, *offset);
    }
    if soname.is_some() {
        push64(&mut entries, 14);
        push64(&mut entries, *offsets.last().unwrap());
    }
    for (tag, value) in [(5, strtab), (10, strings.len() as u64), (0, 0)] {
        push64(&mut entries, tag);
        push64(&mut entries, value);
    }
    let total = dynamic + entries.len() as u64;

    let mut out = b"\x7fELF\x02\x01\x01".to_vec();
    out.resize(16, 0);
    push16(&mut out, 3);
    push16(&mut out, 62);
    push32(&mut out, 1);
    push64(&mut out, 0);
    push64(&mut out, 64);
    push64(&mut out, 0);
    push32(&mut out, 0);
    for value in [64, 56, 3, 64, 0, 0] {
        push16(&mut out, value);
    }
    for (kind, offset, size) in [
        (1u32, 0u64, total),
        (4, note_at, note.len() as u64),
        (2, dynamic, entries.len() as u64),
    ] {
        push32(&mut out, kind);
        push32(&mut out, 4);
        for value in [offset, offset, offset, size, size, 8] {
            push64(&mut out, value);
        }
    }
    out.extend_from_slice(&strings);
    out.extend_from_slice(&note);
    out.extend_from_slice(&entries);
    out
}

#[derive(Clone)]
enum Entry {
    File(Vec<u8>),
    Link(&'static str),
}

fn tar_bytes(entries: &[(&str, Entry)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, entry) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        match entry {
            Entry::File(data) => {
                header.set_size(data.len() as u64);
                builder.append_data(&mut header, path, &data[..]).unwrap();
            }
            Entry::Link(target) => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                builder.append_link(&mut header, path, target).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn desc(name: &str, version: &str, filename: &str, sha256: &str, signature: &str) -> String {
    format!(
        "%FILENAME%\n{filename}\n\n%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%SHA256SUM%\n{sha256}\n\n%PGPSIG%\n{signature}\n\n%DEPENDS%\nfilesystem\n"
    )
}

const CURL: &str = r#"#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift 2;;
    --max-time|--proto|--proto-redir) shift 2;;
    --*) shift;;
    *) url="$1"; shift;;
  esac
done
base="${url##*/}"
echo "$url" >> "$LOG"
[ -f "$REPO/$base" ] || exit 22
cp "$REPO/$base" "$out"
"#;

/// One distribution state: the packages the "mirror" serves and the stand-in tools.
struct Scenario {
    root: PathBuf,
    repo: PathBuf,
    tools: Tools,
    keyring: PathBuf,
    glibc: String,
}

impl Scenario {
    fn new(name: &str, glibc: &str) -> Self {
        let root = scratch(name);
        let repo = root.join("repo");
        let bin = root.join("fakebin");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let log = root.join("curl.log");
        let curl = format!(
            "#!/bin/sh\nREPO='{}'\nLOG='{}'\n{}",
            repo.display(),
            log.display(),
            CURL.trim_start_matches("#!/bin/sh\n")
        );
        executable(&bin.join("curl"), &curl);
        executable(
            &bin.join("pacman"),
            &format!(
                "#!/bin/sh\ncase \"$*\" in\n  *extralib*) cat '{0}/pacman-extra.out';;\n  *) cat '{0}/pacman.out';;\nesac\n",
                root.display()
            ),
        );
        executable(
            &bin.join("gpg"),
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --output ] && echo ring > \"$2\"; shift; done\n",
        );
        executable(
            &bin.join("gpgv"),
            &format!(
                "#!/bin/sh\n[ -f '{}/gpgv.fail' ] && {{ echo 'BAD signature' >&2; exit 2; }}\nexit 0\n",
                root.display()
            ),
        );
        let keyring = root.join("keyring.gpg");
        fs::write(&keyring, "keyring").unwrap();
        let tools = Tools {
            curl: bin.join("curl").to_string_lossy().into_owned(),
            pacman: bin.join("pacman").to_string_lossy().into_owned(),
            gpg: bin.join("gpg").to_string_lossy().into_owned(),
            gpgv: bin.join("gpgv").to_string_lossy().into_owned(),
            bsdtar: "bsdtar".into(),
        };
        let scenario = Self {
            root,
            repo,
            tools,
            keyring,
            glibc: glibc.to_string(),
        };
        scenario.serve_glibc();
        scenario
    }

    fn glibc_libraries(&self) -> Vec<(&'static str, Entry)> {
        vec![
            (
                "usr/lib/libc.so.6",
                Entry::File(elf64(&[], Some("libc.so.6"), None)),
            ),
            (
                "usr/lib/ld-linux-x86-64.so.2",
                Entry::File(elf64(&[], Some("ld-linux-x86-64.so.2"), Some(1))),
            ),
            (
                "usr/lib/libm.so.6",
                Entry::File(elf64(&["libc.so.6"], Some("libm.so.6"), None)),
            ),
            ("usr/lib/libc-alias.so.6", Entry::Link("/usr/lib/libc.so.6")),
            ("usr/share/doc/readme", Entry::File(b"ignored".to_vec())),
        ]
    }

    /// Serves a package and returns its lock entry.
    fn serve_package(
        &self,
        name: &str,
        repository: &str,
        version: &str,
        files: &[(&'static str, Entry)],
    ) -> Value {
        let filename = format!("{name}-{version}-x86_64.pkg.tar.zst");
        let bytes = tar_bytes(files);
        fs::write(self.repo.join(&filename), &bytes).unwrap();
        fs::write(self.repo.join(format!("{filename}.sig")), "signature").unwrap();
        json!({
            "name": name,
            "repository": repository,
            "version": version,
            "filename": filename,
            "sha256": hex(&Sha256::digest(&bytes)),
            "signature": null,
            "dependencies": ["filesystem"],
            "urls": [
                format!("https://mirror.test/{repository}/os/x86_64/{filename}"),
                format!("https://archive.archlinux.org/packages/{}/{name}/{filename}", &name[..1]),
            ],
        })
    }

    fn serve_glibc(&self) -> Value {
        self.serve_package(
            "glibc",
            "core",
            &self.glibc.clone(),
            &self.glibc_libraries(),
        )
    }

    fn lock(&self, packages: Vec<Value>) -> Value {
        // Current roots, so that a lock like this does not count as one of an older launcher.
        let embedded: Value =
            serde_json::from_slice(pingu_launcher::assets::lock("nvidia").unwrap()).unwrap();
        json!({
            "schema": 1,
            "gpu": "nvidia",
            "mirror": "https://mirror.test",
            "roots": embedded["roots"],
            "packages": packages,
        })
    }

    fn glibc_lock(&self) -> Value {
        self.lock(vec![self.serve_glibc()])
    }

    /// The repository databases and what pacman resolves, for `update`.
    fn serve_databases(&self, glibc: &Value, with_extralib: bool) {
        let mut core = vec![(
            format!("glibc-{}/desc", self.glibc),
            desc(
                "glibc",
                &self.glibc,
                glibc["filename"].as_str().unwrap(),
                glibc["sha256"].as_str().unwrap(),
                "c2ln",
            ),
        )];
        core.push((
            format!("glibc-{}/files", self.glibc),
            "%FILES%\nusr/lib/libc.so.6\n".into(),
        ));
        let mut extra = Vec::new();
        let resolved = "core/glibc\n".to_string();
        let mut resolved_extra = resolved.clone();
        if with_extralib {
            let package = self.serve_package(
                "extralib",
                "extra",
                "1-1",
                &[(
                    "usr/lib/libextra.so.1",
                    Entry::File(elf64(&[], Some("libextra.so.1"), None)),
                )],
            );
            extra.push((
                "extralib-1-1/desc".to_string(),
                desc(
                    "extralib",
                    "1-1",
                    package["filename"].as_str().unwrap(),
                    package["sha256"].as_str().unwrap(),
                    "c2ln",
                ),
            ));
            resolved_extra.push_str("extra/extralib\n");
            // The files database lets the builder find the provider of the missing library.
            for repository in ["core", "extra", "multilib"] {
                let mut files: Vec<(String, String)> = Vec::new();
                if repository == "core" {
                    files.push((format!("glibc-{}/desc", self.glibc), core[0].1.clone()));
                    files.push((
                        format!("glibc-{}/files", self.glibc),
                        "%FILES%\nusr/lib/libc.so.6\n".into(),
                    ));
                }
                if repository == "extra" {
                    files.push(("extralib-1-1/desc".into(), extra[0].1.clone()));
                    files.push((
                        "extralib-1-1/files".into(),
                        "%FILES%\nusr/lib/libextra.so.1\nusr/share/x\n".into(),
                    ));
                }
                self.serve_database(&format!("{repository}.files"), &files);
            }
        }
        self.serve_database("core.db", &core);
        self.serve_database("extra.db", &extra);
        self.serve_database("multilib.db", &[]);
        fs::write(self.root.join("pacman.out"), resolved).unwrap();
        fs::write(self.root.join("pacman-extra.out"), resolved_extra).unwrap();
    }

    fn serve_database(&self, name: &str, entries: &[(String, String)]) {
        let entries: Vec<(&str, Entry)> = entries
            .iter()
            .map(|(path, text)| (path.as_str(), Entry::File(text.clone().into_bytes())))
            .collect();
        fs::write(self.repo.join(name), gzip(&tar_bytes(&entries))).unwrap();
    }

    fn builder<'a>(&self, cancel: &'a Cancel, log: &'a (dyn Fn(&str) + Sync)) -> Builder<'a> {
        let mut builder = Builder::new(self.root.join("work"), self.root.join("out"), cancel, log);
        builder.tools = self.tools.clone();
        builder.keyring = self.keyring.clone();
        builder
    }

    fn requests(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("curl.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

// --- the JSON and text formats the lock identity depends on -----------------------------------

fn parity_lock() -> Value {
    json!({
        "gpu": "nvidia", "n": [1, 2], "s": "é\"\\\n\u{2603}\u{1F600}/\u{7f}\u{1}",
        "x": null, "t": true, "e": {}, "l": [], "nested": {"b": [{"z": 1, "a": 2}], "a": "v"}
    })
}

#[test]
fn json_and_identity_match_python() {
    let document = json!({ "builder": 2, "lock": parity_lock() });
    let canonical = canonical_json(&document);
    assert_eq!(
        canonical,
        "{\"builder\":2,\"lock\":{\"e\":{},\"gpu\":\"nvidia\",\"l\":[],\"n\":[1,2],\"nested\":{\"a\":\"v\",\"b\":[{\"a\":2,\"z\":1}]},\"s\":\"\\u00e9\\\"\\\\\\n\\u2603\\ud83d\\ude00/\\u007f\\u0001\",\"t\":true,\"x\":null}}"
    );
    assert_eq!(
        hex(&Sha256::digest(canonical.as_bytes())),
        "8f996bab5bac72c05f2c6a2a539189aec8375ca82ca774de1086643bdabcfe7a"
    );
    assert_eq!(
        lock_identity(&parity_lock()),
        "8f996bab5bac72c05f2c6a2a539189aec8375ca82ca774de1086643bdabcfe7a"
    );
    assert_eq!(
        pretty_json(&parity_lock()),
        "{\n  \"e\": {},\n  \"gpu\": \"nvidia\",\n  \"l\": [],\n  \"n\": [\n    1,\n    2\n  ],\n  \"nested\": {\n    \"a\": \"v\",\n    \"b\": [\n      {\n        \"a\": 2,\n        \"z\": 1\n      }\n    ]\n  },\n  \"s\": \"\\u00e9\\\"\\\\\\n\\u2603\\ud83d\\ude00/\\u007f\\u0001\",\n  \"t\": true,\n  \"x\": null\n}"
    );
}

#[test]
fn text_helpers_match_their_python_counterparts() {
    assert_eq!(base64_decode("c2ln").unwrap(), b"sig");
    assert_eq!(base64_decode("c2lnbg==").unwrap(), b"sign");
    assert_eq!(base64_decode("c2lnbmE=").unwrap(), b"signa");
    assert_eq!(base64_decode("").unwrap(), b"");
    for bad in ["c2l", "c2ln\n", "c2=n", "====", "c2lnbg=a"] {
        assert!(base64_decode(bad).is_err(), "{bad}");
    }
    assert_eq!(
        url_quote("lib32-glibc-2.44+r5-1-x86_64.pkg.tar.zst"),
        "lib32-glibc-2.44%2Br5-1-x86_64.pkg.tar.zst"
    );
    assert_eq!(url_quote("a/b c~"), "a%2Fb%20c~");

    let fields = parse_fields("%NAME%\nglibc\n\n%DEPENDS%\na\nb>=1\n\n%EMPTY%\n");
    assert_eq!(fields["NAME"], ["glibc"]);
    assert_eq!(fields["DEPENDS"], ["a", "b>=1"]);
    assert!(fields["EMPTY"].is_empty());

    let package = json!({"name": "lib32-glibc", "repository": "multilib", "filename": "lib32-glibc-2.44+r5-1-x86_64.pkg.tar.zst"});
    assert_eq!(
        package_urls(&package, "https://m.test/"),
        [
            "https://m.test/multilib/os/x86_64/lib32-glibc-2.44%2Br5-1-x86_64.pkg.tar.zst",
            "https://archive.archlinux.org/packages/l/lib32-glibc/lib32-glibc-2.44%2Br5-1-x86_64.pkg.tar.zst",
        ]
    );
}

// --- the generation's files -------------------------------------------------------------------

fn write_library(root: &Path, relative: &str, data: Vec<u8>) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

#[test]
fn links_become_relative_and_stay_inside() {
    let root = scratch("links");
    write_library(
        &root,
        "usr/lib/libc.so.6",
        elf64(&[], Some("libc.so.6"), None),
    );
    let link =
        |name: &str, target: &str| std::os::unix::fs::symlink(target, root.join(name)).unwrap();
    link("usr/lib/libalias.so.6", "/usr/lib/libc.so.6");
    link("usr/lib/libsibling.so.6", "libc.so.6");
    fs::create_dir_all(root.join("usr/lib64")).unwrap();
    link("usr/lib64/libc.so.6", "../lib/libc.so.6");
    link("usr/lib/ld.conf", "/etc/ld.so.conf");
    normalize_links(&root).unwrap();
    assert_eq!(
        fs::read_link(root.join("usr/lib/libalias.so.6")).unwrap(),
        Path::new("libc.so.6")
    );
    assert_eq!(
        fs::read_link(root.join("usr/lib/libsibling.so.6")).unwrap(),
        Path::new("libc.so.6")
    );
    assert_eq!(
        fs::read_link(root.join("usr/lib64/libc.so.6")).unwrap(),
        Path::new("../lib/libc.so.6")
    );
    // Links to places outside are left alone unless they look like libraries.
    assert_eq!(
        fs::read_link(root.join("usr/lib/ld.conf")).unwrap(),
        Path::new("/etc/ld.so.conf")
    );

    link("usr/lib/libescape.so.1", "/etc/libescape.so.1");
    let error = normalize_links(&root).unwrap_err();
    assert!(error.contains("Library link escapes runtime"), "{error}");
}

#[test]
fn the_audit_matches_needed_names_by_word_size_and_rejects_v4() {
    let root = scratch("audit");
    write_library(
        &root,
        "usr/lib/libc.so.6",
        elf64(&[], Some("libc.so.6"), None),
    );
    write_library(
        &root,
        "usr/lib/libm.so.6",
        elf64(&["libc.so.6"], Some("libm.so.6"), None),
    );
    write_library(
        &root,
        "usr/lib/glibc-hwcaps/x86-64-v4/libm.so.6",
        elf64(&["libnothing.so"], None, None),
    );
    write_library(
        &root,
        "usr/lib/libscript.so",
        b"GROUP ( libc.so.6 )".to_vec(),
    );
    write_library(
        &root,
        "usr/lib/gconv/UTF.so",
        elf64(&["libc.so.6"], None, None),
    );
    write_library(&root, "usr/lib/plain.txt", b"not a library".to_vec());
    std::os::unix::fs::symlink("libc.so.6", root.join("usr/lib/libalias.so.6")).unwrap();
    let audit = inspect_libraries(&root).unwrap();
    let paths: Vec<_> = audit.library_paths.iter().map(String::as_str).collect();
    assert_eq!(
        paths,
        [
            "usr/lib/gconv/UTF.so",
            "usr/lib/libalias.so.6",
            "usr/lib/libc.so.6",
            "usr/lib/libm.so.6",
            "usr/lib/libscript.so",
        ]
    );
    // The alias resolves to a file that is already audited.
    assert_eq!(audit.elf_libraries.len(), 3);

    write_library(
        &root,
        "usr/lib/libbroken.so.1",
        elf64(&["libgone.so.1"], None, None),
    );
    match inspect_libraries(&root) {
        Err(Failure::Missing(missing)) => {
            assert_eq!(missing.len(), 1);
            assert_eq!(missing[0].name, "libgone.so.1");
            assert_eq!(missing[0].bits, 64);
            assert_eq!(missing[0].path, "usr/lib/libbroken.so.1");
        }
        other => panic!("{other:?}"),
    }
    fs::remove_file(root.join("usr/lib/libbroken.so.1")).unwrap();

    write_library(
        &root,
        "usr/lib/libv4.so.1",
        elf64(&[], Some("libv4.so.1"), Some(8)),
    );
    let error = inspect_libraries(&root).unwrap_err().to_string();
    assert!(error.contains("x86-64-v4: usr/lib/libv4.so.1"), "{error}");
}

#[test]
fn a_broken_library_link_is_an_error() {
    let root = scratch("broken-link");
    fs::create_dir_all(root.join("usr/lib")).unwrap();
    std::os::unix::fs::symlink("missing.so.1", root.join("usr/lib/libgone.so.1")).unwrap();
    assert!(inspect_libraries(&root).is_err());
}

// --- building ---------------------------------------------------------------------------------

#[test]
fn a_generation_is_built_verified_and_audited() {
    if !bsdtar_available() {
        eprintln!("skipped: bsdtar is not installed");
        return;
    }
    let scenario = Scenario::new("build", "2.44-1");
    let lock = scenario.glibc_lock();
    let cancel = Cancel::default();
    let lines = Mutex::new(Vec::new());
    let log = |line: &str| lines.lock().unwrap().push(line.to_string());
    let builder = scenario.builder(&cancel, &log);

    let generation = builder.build_runtime(&lock, false).unwrap();
    let identity = lock_identity(&lock);
    assert_eq!(
        generation,
        scenario
            .root
            .join("out")
            .join(format!("nvidia-{}", &identity[..20]))
    );

    let manifest: Value =
        serde_json::from_slice(&fs::read(generation.join("runtime.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema"], 2);
    assert_eq!(manifest["gpu"], "nvidia");
    assert_eq!(manifest["glibc"], "2.44-1");
    assert_eq!(manifest["lock_sha256"], identity);
    assert_eq!(manifest["elf_libraries"].as_array().unwrap().len(), 3);
    assert_eq!(
        fs::read_to_string(generation.join("VERSION")).unwrap(),
        "2.44-1\n"
    );
    let recorded: Value =
        serde_json::from_slice(&fs::read(generation.join("runtime.lock.json")).unwrap()).unwrap();
    assert_eq!(recorded, lock);
    assert_eq!(
        fs::read_link(generation.join("usr/lib/libc-alias.so.6")).unwrap(),
        Path::new("libc.so.6")
    );
    assert!(generation.join("usr/share/doc/readme").is_file());
    // Nothing is left behind next to the generation.
    let leftovers: Vec<_> = fs::read_dir(scenario.root.join("out"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    // The cache keeps the archive and its signature for offline rebuilds.
    let cache = scenario.root.join("work/downloads");
    assert!(cache.join("glibc-2.44-1-x86_64.pkg.tar.zst").is_file());
    assert!(cache.join("glibc-2.44-1-x86_64.pkg.tar.zst.sig").is_file());
    let lines = lines.lock().unwrap().clone();
    assert!(
        lines.iter().any(|line| line == "Verified glibc 2.44-1"),
        "{lines:?}"
    );

    // A second build finds the same generation without downloading again.
    let requests = scenario.requests().len();
    assert_eq!(builder.build_runtime(&lock, false).unwrap(), generation);
    assert_eq!(scenario.requests().len(), requests);

    fs::write(
        generation.join("runtime.json"),
        "{\"lock_sha256\": \"other\"}",
    )
    .unwrap();
    let error = builder.build_runtime(&lock, false).unwrap_err().to_string();
    assert!(error.contains("does not match lockfile"), "{error}");
}

#[test]
fn replacing_rebuilds_an_existing_generation() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("replace", "2.44-1");
    let lock = scenario.glibc_lock();
    let cancel = Cancel::default();
    let log = |_: &str| {};
    let mut builder = scenario.builder(&cancel, &log);

    let generation = builder.build_runtime(&lock, false).unwrap();
    fs::write(generation.join("stale"), "").unwrap();

    builder.replace = true;
    assert_eq!(builder.build_runtime(&lock, false).unwrap(), generation);
    assert!(!generation.join("stale").exists());
    assert!(generation.join("runtime.json").is_file());
    let leftovers = fs::read_dir(scenario.root.join("out")).unwrap().count();
    assert_eq!(leftovers, 1);
}

#[test]
fn a_bad_signature_or_checksum_stops_the_build() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("bad-signature", "2.44-1");
    let lock = scenario.glibc_lock();
    let cancel = Cancel::default();
    let builder = scenario.builder(&cancel, &|_| {});

    fs::write(scenario.root.join("gpgv.fail"), "").unwrap();
    let error = builder.build_runtime(&lock, false).unwrap_err().to_string();
    assert!(
        error.contains("Signature verification failed for glibc-2.44-1"),
        "{error}"
    );
    assert!(error.contains("BAD signature"), "{error}");
    assert!(
        !scenario
            .root
            .join("out")
            .read_dir()
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
    );
    fs::remove_file(scenario.root.join("gpgv.fail")).unwrap();

    let mut wrong = lock.clone();
    wrong["packages"][0]["sha256"] = json!("0".repeat(64));
    let scenario = Scenario::new("bad-checksum", "2.44-1");
    let builder = scenario.builder(&cancel, &|_| {});
    let error = builder
        .build_runtime(&wrong, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("SHA-256 mismatch"), "{error}");

    let mut invalid = lock.clone();
    invalid["packages"][0]["filename"] = json!("../glibc.pkg.tar.zst");
    let error = builder
        .build_runtime(&invalid, false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("Invalid package filename"), "{error}");
}

#[test]
fn offline_builds_use_only_the_verified_cache() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("offline", "2.44-1");
    let lock = scenario.glibc_lock();
    let cancel = Cancel::default();
    let builder = scenario.builder(&cancel, &|_| {});

    let error = builder.build_runtime(&lock, true).unwrap_err().to_string();
    assert!(error.contains("Offline cache entry missing"), "{error}");

    let generation = builder.build_runtime(&lock, false).unwrap();
    fs::remove_dir_all(&generation).unwrap();
    // The mirror is gone; the cache is enough.
    fs::remove_dir_all(&scenario.repo).unwrap();
    fs::create_dir_all(&scenario.repo).unwrap();
    let before = scenario.requests().len();
    assert_eq!(builder.build_runtime(&lock, true).unwrap(), generation);
    assert_eq!(scenario.requests().len(), before);
}

#[test]
fn missing_libraries_leave_no_generation_and_are_reported_for_completion() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("missing", "2.44-1");
    let mut package = scenario.serve_package(
        "needy",
        "extra",
        "1-1",
        &[(
            "usr/lib/libneedy.so.1",
            Entry::File(elf64(&["libextra.so.1"], Some("libneedy.so.1"), None)),
        )],
    );
    package["signature"] = json!("c2ln");
    let lock = scenario.lock(vec![scenario.serve_glibc(), package]);
    let cancel = Cancel::default();
    let builder = scenario.builder(&cancel, &|_| {});
    match builder.build_runtime(&lock, false) {
        Err(Failure::Missing(missing)) => assert_eq!(missing[0].name, "libextra.so.1"),
        other => panic!("{other:?}"),
    }
    let out = scenario.root.join("out");
    assert_eq!(fs::read_dir(out).unwrap().count(), 0);
}

#[test]
fn selecting_checks_glibc_and_replaces_only_symlinks() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("select", "2.44-1");
    let lock = scenario.glibc_lock();
    let cancel = Cancel::default();
    let builder = scenario.builder(&cancel, &|_| {});
    let generation = builder.build_runtime(&lock, false).unwrap();

    let error = builder.select(&generation, "2.99-1").unwrap_err();
    assert!(error.contains("does not match the host"), "{error}");
    assert!(!scenario.root.join("out/nvidia-current").exists());

    let link = builder.select(&generation, "2.44-1").unwrap();
    assert_eq!(link, scenario.root.join("out/nvidia-current"));
    assert_eq!(
        fs::read_link(&link).unwrap(),
        fs::canonicalize(&generation).unwrap()
    );
    // Selecting again replaces the link in place.
    builder.select(&generation, "2.44-1").unwrap();

    fs::remove_file(&link).unwrap();
    fs::create_dir(&link).unwrap();
    let error = builder.select(&generation, "2.44-1").unwrap_err();
    assert!(error.contains("non-symlink"), "{error}");
}

// --- provisioning through the window's entry point --------------------------------------------

fn home_with_lock(scenario: &Scenario, lock: &Value) -> Home {
    let home = Home {
        root: scenario.root.join("data"),
    };
    fs::create_dir_all(home.file("locks")).unwrap();
    fs::write(
        home.lock_override("nvidia"),
        serde_json::to_vec(lock).unwrap(),
    )
    .unwrap();
    home
}

fn provision(scenario: &Scenario) -> std::sync::Arc<Provision> {
    Provision::with_tools(scenario.tools.clone(), scenario.keyring.clone())
}

#[test]
fn a_matching_lock_is_rebuilt_exactly_then_selected() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("provision-build", "2.44-1");
    let lock = scenario.glibc_lock();
    let home = home_with_lock(&scenario, &lock);
    let lines = Mutex::new(Vec::new());
    provision(&scenario)
        .run(&home, "nvidia", "2.44-1", &|line| {
            lines.lock().unwrap().push(line.to_string())
        })
        .unwrap();
    let link = home.generations().join("nvidia-current");
    assert!(
        fs::read_link(&link)
            .unwrap()
            .ends_with(format!("nvidia-{}", &lock_identity(&lock)[..20]))
    );
    assert!(
        lines
            .lock()
            .unwrap()
            .iter()
            .any(|line| line == "Verified glibc 2.44-1")
    );
    // The lock the user holds is untouched by an exact rebuild.
    let kept: Value =
        serde_json::from_slice(&fs::read(home.lock_override("nvidia")).unwrap()).unwrap();
    assert_eq!(kept, lock);
}

#[test]
fn a_stale_lock_resolves_current_packages_and_records_the_new_lock() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("provision-update", "2.45-1");
    let glibc = scenario.serve_glibc();
    scenario.serve_databases(&glibc, false);
    let old = Scenario::new("provision-update-old", "2.44-1").glibc_lock();
    let home = home_with_lock(&scenario, &old);
    let lines = Mutex::new(Vec::new());
    provision(&scenario)
        .run(&home, "nvidia", "2.45-1", &|line| {
            lines.lock().unwrap().push(line.to_string())
        })
        .unwrap();
    let lines = lines.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("differs from the host's 2.45-1")),
        "{lines:?}"
    );

    let recorded: Value =
        serde_json::from_slice(&fs::read(home.lock_override("nvidia")).unwrap()).unwrap();
    assert_eq!(recorded["mirror"], builder::DEFAULT_MIRROR);
    assert_eq!(recorded["packages"][0]["version"], "2.45-1");
    assert_eq!(
        recorded["packages"][0]["urls"][0],
        format!(
            "{}/core/os/x86_64/glibc-2.45-1-x86_64.pkg.tar.zst",
            builder::DEFAULT_MIRROR
        )
    );
    assert!(home.generations().join("nvidia-current").exists());
}

#[test]
fn a_lock_missing_built_in_roots_is_resolved_again_keeping_its_extras() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("provision-roots", "2.44-1");
    let glibc = scenario.serve_glibc();
    scenario.serve_databases(&glibc, false);
    let mut old = scenario.glibc_lock();
    old["roots"] = json!(["glibc", "libpulse"]);
    let home = home_with_lock(&scenario, &old);
    let lines = Mutex::new(Vec::new());
    provision(&scenario)
        .run(&home, "nvidia", "2.44-1", &|line| {
            lines.lock().unwrap().push(line.to_string())
        })
        .unwrap();
    let lines = lines.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("The package list gained")),
        "{lines:?}"
    );
    let recorded: Value =
        serde_json::from_slice(&fs::read(home.lock_override("nvidia")).unwrap()).unwrap();
    let roots = recorded["roots"].as_array().unwrap();
    assert!(roots.contains(&json!("libpulse")));
    assert!(roots.contains(&json!("libxfixes")));
}

#[test]
fn updating_adds_the_providers_of_missing_libraries() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("update-providers", "2.44-1");
    // glibc itself needs a library that only extralib ships.
    let needy = vec![(
        "usr/lib/libc.so.6",
        Entry::File(elf64(&["libextra.so.1"], Some("libc.so.6"), None)),
    )];
    let glibc = scenario.serve_package("glibc", "core", "2.44-1", &needy);
    scenario.serve_databases(&glibc, true);
    let cancel = Cancel::default();
    let lines = Mutex::new(Vec::new());
    let log = |line: &str| lines.lock().unwrap().push(line.to_string());
    let builder = scenario.builder(&cancel, &log);
    let lock_path = scenario.root.join("recorded.lock.json");
    let generation = builder
        .update("nvidia", "https://mirror.test", &[], &lock_path)
        .unwrap();
    assert!(generation.join("usr/lib/libextra.so.1").is_file());
    let recorded: Value = serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    let names: Vec<_> = recorded["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| package["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["extralib", "glibc"]);
    assert!(
        recorded["roots"]
            .as_array()
            .unwrap()
            .contains(&json!("extralib"))
    );
    let lines = lines.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|line| line == "Adding ELF dependency providers: extralib"),
        "{lines:?}"
    );
}

#[test]
fn cancelling_stops_the_download() {
    let scenario = Scenario::new("provision-cancel", "2.44-1");
    let lock = scenario.glibc_lock();
    let home = home_with_lock(&scenario, &lock);
    executable(Path::new(&scenario.tools.curl), "#!/bin/sh\nsleep 60\n");
    let provision = provision(&scenario);
    let started = Instant::now();
    let worker = {
        let provision = provision.clone();
        std::thread::spawn(move || provision.run(&home, "nvidia", "2.44-1", &|_| {}))
    };
    std::thread::sleep(Duration::from_millis(700));
    provision.cancel();
    assert_eq!(worker.join().unwrap(), Err("Cancelled".to_string()));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_host_that_cannot_be_matched_points_at_a_snapshot() {
    if !bsdtar_available() {
        return;
    }
    let scenario = Scenario::new("provision-select-fails", "2.44-1");
    let lock = scenario.glibc_lock();
    let home = home_with_lock(&scenario, &lock);
    let provision = provision(&scenario);
    provision.run(&home, "nvidia", "2.44-1", &|_| {}).unwrap();

    // The generation on disk now claims another glibc than the host's.
    let manifest_path = fs::read_dir(home.generations())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join("runtime.json").is_file())
        .unwrap()
        .join("runtime.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["glibc"] = json!("9.9-1");
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let error = provision
        .run(&home, "nvidia", "2.44-1", &|_| {})
        .unwrap_err();
    assert!(error.contains("does not match the host"), "{error}");
    assert!(error.contains("archive.archlinux.org"), "{error}");
}

#[test]
fn the_lock_must_list_glibc() {
    let scenario = Scenario::new("provision-no-glibc", "2.44-1");
    let home = home_with_lock(&scenario, &scenario.lock(vec![]));
    let error = provision(&scenario)
        .run(&home, "nvidia", "2.44-1", &|_| {})
        .unwrap_err();
    assert!(error.contains("does not list glibc"), "{error}");

    // Without an update the embedded lock of the GPU is used.
    let fresh = Home {
        root: scenario.root.join("fresh"),
    };
    let error = provision(&scenario)
        .run(&fresh, "amd", "0.0-0", &|_| {})
        .unwrap_err();
    assert!(!error.contains("No lock file"), "{error}");
}
