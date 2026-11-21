//! The mandatory offline VM gate: boots the target kernel with the built module in QEMU/KVM
//! and runs the guest regression suite while injecting NMIs over QMP.
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::image::Res;
use crate::profile::digest;

pub const FIXTURES: [&str; 4] = [
    "policy-test-static",
    "xstate-probe-static",
    "avx2-run-static",
    "xstate-compat32",
];
/// When a stuck guest is asked to quit, and when its whole process group is killed.
#[derive(Clone, Copy)]
struct Deadlines {
    soft: Duration,
    hard: Duration,
}

const DEADLINES: Deadlines = Deadlines {
    soft: Duration::from_secs(120),
    hard: Duration::from_secs(125),
};
const INSTALL_NMIS: u32 = 512;
const EXECUTION_NMIS: u32 = 20;
const EXPECTED_EXECUTION_NMIS: u32 = 40;

fn io_error(path: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

/// Python's `json.dumps(sort_keys=True)` layout, which the build log has always used.
fn compact(value: &Value) -> String {
    match value {
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, item)| format!("{}: {}", Value::String(key.clone()), compact(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(compact).collect::<Vec<_>>().join(", ")
        ),
        other => other.to_string(),
    }
}

fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    text
}

/// Copies the VM fixtures into `<package>/validation` and records their checksums.
pub fn prepare(package: &Path, fixtures: &Path) -> Res<()> {
    let destination = package.join("validation");
    fs::create_dir_all(&destination).map_err(io_error(&destination))?;
    let mut manifest = BTreeMap::new();
    for name in FIXTURES {
        let target = destination.join(name);
        fs::copy(fixtures.join(name), &target).map_err(io_error(&target))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .map_err(io_error(&target))?;
        manifest.insert(name.to_string(), digest(&target)?);
    }
    let path = destination.join("manifest.json");
    fs::write(&path, pretty(&serde_json::to_value(&manifest).unwrap())).map_err(io_error(&path))
}

struct Entry {
    name: String,
    mode: u32,
    data: Vec<u8>,
}

/// A newc cpio archive, as the kernel's initramfs unpacker reads it.
fn newc(entries: &[Entry]) -> Vec<u8> {
    let mut archive = Vec::new();
    let pad = |archive: &mut Vec<u8>| {
        while !archive.len().is_multiple_of(4) {
            archive.push(0);
        }
    };
    let trailer = Entry {
        name: "TRAILER!!!".into(),
        mode: 0,
        data: Vec::new(),
    };
    for (index, entry) in entries.iter().chain([&trailer]).enumerate() {
        let directory = entry.mode & 0o170000 == 0o040000;
        let fields = [
            index as u32 + 1,
            entry.mode,
            0,
            0,
            if directory { 2 } else { 1 },
            0,
            entry.data.len() as u32,
            0,
            0,
            0,
            0,
            entry.name.len() as u32 + 1,
            0,
        ];
        archive.extend(b"070701");
        for field in fields {
            archive.extend(format!("{field:08X}").bytes());
        }
        archive.extend(entry.name.bytes());
        archive.push(0);
        pad(&mut archive);
        archive.extend(&entry.data);
        pad(&mut archive);
    }
    archive
}

fn initramfs(assets: &Path, module: &Path) -> Res<Vec<u8>> {
    let read = |path: &Path| fs::read(path).map_err(io_error(path));
    let mut entries: Vec<Entry> = ["dev", "proc", "sys"]
        .into_iter()
        .map(|name| Entry {
            name: name.into(),
            mode: 0o040755,
            data: Vec::new(),
        })
        .collect();
    let file = |name: &str, mode: u32, data: Vec<u8>| Entry {
        name: name.into(),
        mode: 0o100000 | mode,
        data,
    };
    entries.push(file(
        "init",
        0o755,
        read(&assets.join("policy-test-static"))?,
    ));
    entries.push(file(
        "policy-test",
        0o755,
        read(&assets.join("policy-test-static"))?,
    ));
    entries.push(file(
        "xstate-probe",
        0o755,
        read(&assets.join("xstate-probe-static"))?,
    ));
    entries.push(file(
        "avx2-run",
        0o755,
        read(&assets.join("avx2-run-static"))?,
    ));
    entries.push(file(
        "xstate-compat32",
        0o755,
        read(&assets.join("xstate-compat32"))?,
    ));
    entries.push(file("pingu_policy.ko", 0o600, read(module)?));
    let mut compressed = Vec::new();
    {
        let mut encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(&mut compressed, flate2::Compression::best());
        encoder
            .write_all(&newc(&entries))
            .map_err(|e| e.to_string())?;
        encoder.finish().map_err(|e| e.to_string())?;
    }
    Ok(compressed)
}

enum Message {
    Line(String),
    Closed,
}

struct Qemu {
    child: Child,
    stdin: ChildStdin,
    messages: Receiver<Message>,
    errors: Arc<Mutex<String>>,
    next_id: u64,
    started: Instant,
    deadlines: Deadlines,
}

impl Qemu {
    fn start(
        program: &Path,
        kernel: &Path,
        initrd: &Path,
        log: &Path,
        root: &Path,
        deadlines: Deadlines,
    ) -> Res<Self> {
        let append = "console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200 loglevel=5 nopvspin \
                      rdinit=/init panic=-1 AVX2_MODULE_PROBE=1 \
                      AVX2_MODULE_INSTALL_STRESS=1";
        let mut command = Command::new(program);
        command
            .args(["-enable-kvm", "-cpu", "host,vendor=GenuineIntel,pmu=off"])
            .args(["-smp", "2", "-m", "512"])
            .args(["-nodefaults", "-no-reboot", "-display", "none"])
            .arg("-serial")
            .arg(format!("file:{}", log.display()))
            .args(["-qmp", "stdio", "-nic", "none"])
            .arg("-kernel")
            .arg(kernel)
            .arg("-initrd")
            .arg(initrd)
            .args(["-append", append])
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group, so a timeout can take everything down at once.
            .process_group(0);
        let mut child = command
            .spawn()
            .map_err(|error| format!("{}: {error}", program.display()))?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, messages) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(Message::Line(line)).is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = sender.send(Message::Closed);
        });
        let errors = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&errors);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut text = collected.lock().unwrap();
                text.push_str(&line);
                text.push('\n');
                if text.len() > 16384 {
                    let cut = text.len() - 16384;
                    let boundary = (cut..text.len())
                        .find(|i| text.is_char_boundary(*i))
                        .unwrap_or(cut);
                    text.drain(..boundary);
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            messages,
            errors,
            next_id: 0,
            started: Instant::now(),
            deadlines,
        })
    }

    fn kill_group(&self) {
        // SAFETY: signalling the process group that this tool created.
        unsafe {
            libc::killpg(self.child.id() as i32, libc::SIGKILL);
        }
    }

    /// Sends one QMP command and waits for its answer.
    fn execute(&mut self, command: &str, arguments: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({ "execute": command, "arguments": arguments, "id": id });
        writeln!(self.stdin, "{request}").map_err(|error| error.to_string())?;
        loop {
            if self.started.elapsed() > self.deadlines.hard {
                return Err("QMP command timed out".into());
            }
            match self.messages.recv_timeout(Duration::from_millis(100)) {
                Ok(Message::Line(line)) => {
                    let Ok(message) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if message.get("id").and_then(Value::as_u64) == Some(id) {
                        if let Some(error) = message.get("error") {
                            return Err(error.to_string());
                        }
                        return Ok(message.get("return").cloned().unwrap_or(Value::Null));
                    }
                }
                Ok(Message::Closed) | Err(RecvTimeoutError::Disconnected) => {
                    return Err("QEMU closed the QMP channel".into());
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

struct Outcome {
    passed: bool,
    summary: String,
}

fn run_vm(
    program: &Path,
    kernel: &Path,
    initrd: &Path,
    log: &Path,
    root: &Path,
    deadlines: Deadlines,
) -> Res<Outcome> {
    fs::write(log, "").map_err(io_error(log))?;
    let mut vm = Qemu::start(program, kernel, initrd, log, root, deadlines)?;
    let mut ready = false;
    let mut timed_out = false;
    let mut closed = false;
    let mut install_started = false;
    let mut install_pending = 0;
    let mut execution_pending = 0;
    let mut requested = 0usize;
    let (mut injected, mut install_injected) = (0u32, 0u32);
    let mut failed = false;
    let mut errors = String::new();

    while !closed {
        if !ready {
            match vm.messages.recv_timeout(Duration::from_millis(50)) {
                Ok(Message::Line(line)) => {
                    if serde_json::from_str::<Value>(&line).is_ok_and(|v| v.get("QMP").is_some()) {
                        match vm.execute("qmp_capabilities", json!({})) {
                            Ok(_) => ready = true,
                            Err(error) => {
                                errors.push_str(&format!("{error}\n"));
                                vm.kill_group();
                            }
                        }
                    }
                }
                Ok(Message::Closed) | Err(RecvTimeoutError::Disconnected) => closed = true,
                Err(RecvTimeoutError::Timeout) => {}
            }
        } else {
            std::thread::sleep(Duration::from_millis(50));
            let log_text = String::from_utf8_lossy(&fs::read(log).unwrap_or_default()).into_owned();
            if !install_started && log_text.contains("MODULE_INSTALL_NMI_READY") {
                install_started = true;
                install_pending = INSTALL_NMIS;
            }
            let markers = log_text.matches("AVX512_POLICY_NMI_READY").count();
            while markers > requested {
                requested += 1;
                execution_pending += EXECUTION_NMIS;
            }
            // Both batches take turns, as concurrent injections would.
            while (install_pending > 0 || execution_pending > 0) && !failed {
                for (pending, counter) in [
                    (&mut install_pending, &mut install_injected),
                    (&mut execution_pending, &mut injected),
                ] {
                    if *pending == 0 {
                        continue;
                    }
                    *pending -= 1;
                    match vm.execute("inject-nmi", json!({})) {
                        Ok(_) => *counter += 1,
                        Err(error) => {
                            failed = true;
                            errors.push_str(&format!("{error}\n"));
                            break;
                        }
                    }
                }
            }
            // A closed channel ends the loop; pending QMP messages are only events.
            while let Ok(message) = vm.messages.try_recv() {
                if matches!(message, Message::Closed) {
                    closed = true;
                }
            }
        }
        let elapsed = vm.started.elapsed();
        if elapsed > deadlines.soft && !timed_out {
            timed_out = true;
            if !ready || vm.execute("quit", json!({})).is_err() {
                vm.kill_group();
            }
        }
        if elapsed > deadlines.hard {
            vm.kill_group();
        }
        if !closed && matches!(vm.child.try_wait(), Ok(Some(_))) {
            closed = true;
        }
        if closed {
            break;
        }
    }
    let status = vm.child.wait().map_err(|error| error.to_string())?;
    vm.kill_group();
    errors.push_str(&vm.errors.lock().unwrap());
    let log_text = String::from_utf8_lossy(&fs::read(log).unwrap_or_default()).into_owned();
    let marker = log_text
        .lines()
        .any(|line| line.trim_end_matches('\r') == "MODULE_PROBE_TEST_PASS failures=0");
    let bad = ["BUG:", "WARNING:", "Oops:", "Kernel panic"]
        .iter()
        .any(|pattern| log_text.contains(pattern));
    let passed = !timed_out
        && status.code() == Some(0)
        && marker
        && !bad
        && injected == EXPECTED_EXECUTION_NMIS
        && !failed
        && install_injected == INSTALL_NMIS;
    // A failing run needs the whole guest log; the first failed check is usually not in the tail.
    let lines: Vec<&str> = log_text.lines().collect();
    let shown = if passed && lines.len() > 100 {
        &lines[lines.len() - 100..]
    } else {
        &lines[..]
    };
    println!("{}", shown.join("\n"));
    if !errors.is_empty() {
        eprintln!("{errors}");
    }
    println!("QMP NMI injections: {injected}");
    println!("Installation NMI injections: {install_injected}");
    let signal = status
        .signal()
        .map_or("null".to_string(), |signal| signal.to_string());
    let code = status
        .code()
        .map_or("null".to_string(), |code| code.to_string());
    Ok(Outcome {
        passed,
        summary: format!(
            "VM validation: {} (exit={code}, signal={signal}, timeout={timed_out})",
            if passed { "PASS" } else { "FAIL" }
        ),
    })
}

/// What is missing for the VM test, if anything. Root can open /dev/kvm whenever it exists.
fn missing_vm_support(path: Option<&std::ffi::OsStr>, kvm: &Path) -> Option<&'static str> {
    let qemu = path.is_some_and(|path| {
        std::env::split_paths(path).any(|dir| dir.join("qemu-system-x86_64").is_file())
    });
    if !qemu {
        return Some("qemu-system-x86_64 is not installed");
    }
    let usable = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(kvm)
        .is_ok();
    if !usable {
        return Some("/dev/kvm is not readable and writable (KVM is missing or not allowed)");
    }
    None
}

/// The launcher looks for this phrase in DKMS's build log; keep both in step.
pub const UNVALIDATED_MARKER: &str = "built WITHOUT its VM test";

fn unvalidated_warning(problem: &str) -> String {
    format!(
        "\n*** WARNING: pingu-policy is {UNVALIDATED_MARKER} ***\n\
         {problem}, so the module could not be tested in a virtual machine.\n\
         That test boots this kernel with the module in a throwaway VM, where a faulty kernel \
         patch crashes the VM instead of this computer. Without it only the static checks ran, \
         and loading the module can crash the system if the kernel is not compatible.\n\
         Install QEMU and make sure KVM is available, then build the module again.\n"
    )
}

fn identities(paths: &[PathBuf]) -> Res<BTreeMap<String, String>> {
    paths
        .iter()
        .map(|path| Ok((path.to_string_lossy().into_owned(), digest(path)?)))
        .collect()
}

/// Boots the module in the target kernel and writes `validation.result.json` on success.
/// With `optional`, a machine without QEMU or KVM only gets a warning and no receipt.
pub fn validate(package: &Path, headers: &Path, release: &str, optional: bool) -> Res<()> {
    let result_path = package.join("validation.result.json");
    let _ = fs::remove_file(&result_path);
    let metadata = package.join("profile.generated.json");
    let profile: Value =
        serde_json::from_str(&fs::read_to_string(&metadata).map_err(io_error(&metadata))?)
            .map_err(|error| format!("{}: {error}", metadata.display()))?;
    let release_file = headers.join("include/config/kernel.release");
    let header_release = fs::read_to_string(&release_file).map_err(io_error(&release_file))?;
    if profile["release"].as_str() != Some(release) || header_release.trim() != release {
        return Err("DKMS kernel release does not match generated profile and headers".into());
    }
    let inputs = profile["inputs"]
        .as_object()
        .ok_or("The generated profile has no input list")?;
    for (path, checksum) in inputs {
        if Some(digest(Path::new(path))?.as_str()) != checksum.as_str() {
            return Err("Kernel inputs changed after static validation".into());
        }
    }
    let Some(image) = profile["boot_image"].as_str().map(PathBuf::from) else {
        return Err("No boot image for this kernel was found; pass XCR0_IMAGE".into());
    };
    let module = package.join("pingu_policy.ko");
    let assets = package.join("validation");
    let manifest_path = assets.join("manifest.json");
    let manifest: BTreeMap<String, String> = serde_json::from_str(
        &fs::read_to_string(&manifest_path).map_err(io_error(&manifest_path))?,
    )
    .map_err(|_| "Invalid VM fixture manifest".to_string())?;
    if manifest.keys().map(String::as_str).collect::<Vec<_>>() != {
        let mut expected = FIXTURES.to_vec();
        expected.sort();
        expected
    } {
        return Err("Invalid VM fixture manifest".into());
    }
    for (name, checksum) in &manifest {
        if digest(&assets.join(name))? != *checksum {
            return Err(format!("VM fixture checksum mismatch: {name}"));
        }
    }
    let path = std::env::var_os("PATH");
    if let Some(problem) = missing_vm_support(path.as_deref(), Path::new("/dev/kvm")) {
        if optional {
            // The build log is where DKMS keeps this output, and the launcher reads it from there.
            eprintln!("{}", unvalidated_warning(problem));
            return Ok(());
        }
        return Err(format!(
            "The VM validation is mandatory here, but {problem}"
        ));
    }
    let mut tracked: Vec<PathBuf> = vec![image.clone(), module.clone()];
    tracked.extend(inputs.keys().map(PathBuf::from));
    let before = identities(&tracked)?;

    let scratch = package.join(format!("vm-validation-{}", std::process::id()));
    fs::create_dir_all(&scratch).map_err(io_error(&scratch))?;
    let outcome = (|| {
        let initrd = scratch.join("initramfs.cpio.gz");
        fs::write(&initrd, initramfs(&assets, &module)?).map_err(io_error(&initrd))?;
        let serial = scratch.join("serial.log");
        println!(
            "DKMS VM validation: {release} ({})",
            profile["build_id"].as_str().unwrap_or("")
        );
        let outcome = run_vm(
            Path::new("qemu-system-x86_64"),
            &image,
            &initrd,
            &serial,
            package,
            DEADLINES,
        )?;
        println!("{}", outcome.summary);
        if !outcome.passed {
            return Err(format!("VM validation failed: {}", outcome.summary));
        }
        for (path, checksum) in identities(&tracked)? {
            if before.get(&path) != Some(&checksum) {
                return Err(format!(
                    "Validation input changed during the VM run: {path}"
                ));
            }
        }
        for (name, checksum) in &manifest {
            if digest(&assets.join(name))? != *checksum {
                return Err(format!("VM fixture changed during validation: {name}"));
            }
        }
        digest(&serial)
    })();
    let _ = fs::remove_dir_all(&scratch);
    let vm_log_sha256 = outcome?;
    let result = json!({
        "schema": 1,
        "release": release,
        "build_id": profile["build_id"],
        "profile_sha256": profile["profile_sha256"],
        "module_sha256": before[&module.to_string_lossy().into_owned()],
        "kernel_image_sha256": before[&image.to_string_lossy().into_owned()],
        "fixtures": manifest,
        "vm_log_sha256": vm_log_sha256,
        "install_stress": "PASS",
    });
    fs::write(&result_path, pretty(&result)).map_err(io_error(&result_path))?;
    println!("DKMS VM VALIDATION PASS {}", compact(&result));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-tmp")
            .join(name);
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn fake_qemu(directory: &Path, script: &str) -> PathBuf {
        let path = directory.join("qemu");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn run(directory: &Path, program: &Path, soft: u64, hard: u64) -> Outcome {
        run_vm(
            program,
            Path::new("kernel"),
            Path::new("initrd"),
            &directory.join("serial.log"),
            directory,
            Deadlines {
                soft: Duration::from_secs(soft),
                hard: Duration::from_secs(hard),
            },
        )
        .unwrap()
    }

    fn gone(pid: i32) -> bool {
        for _ in 0..50 {
            let state = fs::read_to_string(format!("/proc/{pid}/stat")).ok();
            if state.is_none_or(|text| {
                text.rsplit(") ")
                    .next()
                    .is_some_and(|rest| rest.starts_with('Z'))
            }) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn leftover_pid(directory: &Path) -> i32 {
        for _ in 0..50 {
            if let Ok(text) = fs::read_to_string(directory.join("pid"))
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the fake guest never started its helper");
    }

    #[test]
    fn vm_failure_fails_the_run_and_cleans_the_process_group() {
        let directory = scratch("vm-failure");
        let program = fake_qemu(&directory, "sleep 30 &\necho $! > pid\nexit 1");
        let outcome = run(&directory, &program, 20, 25);
        assert!(!outcome.passed);
        assert!(outcome.summary.contains("FAIL"), "{}", outcome.summary);
        assert!(gone(leftover_pid(&directory)));
    }

    #[test]
    fn vm_timeout_cleans_the_process_group() {
        let directory = scratch("vm-timeout");
        let program = fake_qemu(&directory, "sleep 30 &\necho $! > pid\nwait");
        let outcome = run(&directory, &program, 1, 2);
        assert!(!outcome.passed);
        assert!(
            outcome.summary.contains("timeout=true"),
            "{}",
            outcome.summary
        );
        assert!(gone(leftover_pid(&directory)));
    }

    const FAKE_GUEST: &str = r#"
for a in "$@"; do case "$a" in file:*) LOG=${a#file:};; esac; done
echo '{"QMP": {"version": {}}}'
count=0
reply() { id=${line#*\"id\":}; echo "{\"return\": {}, \"id\": ${id%\}}}"; }
while IFS= read -r line; do
  case "$line" in
    *qmp_capabilities*)
      reply
      echo MODULE_INSTALL_NMI_READY >> "$LOG"
      (sleep 0.2; echo AVX512_POLICY_NMI_READY >> "$LOG"; sleep 0.2; echo AVX512_POLICY_NMI_READY >> "$LOG") &
      ;;
    *inject-nmi*)
      reply
      count=$((count + 1))
      if [ "$count" -eq EXPECTED ]; then echo "MODULE_PROBE_TEST_PASS failures=0" >> "$LOG"; exit 0; fi
      ;;
  esac
done
"#;

    #[test]
    fn guest_that_gets_every_nmi_and_passes_makes_the_run_pass() {
        let directory = scratch("vm-pass");
        let program = fake_qemu(&directory, &FAKE_GUEST.replace("EXPECTED", "552"));
        let outcome = run(&directory, &program, 30, 35);
        assert!(outcome.passed, "{}", outcome.summary);
        assert!(
            outcome
                .summary
                .contains("PASS (exit=0, signal=null, timeout=false)")
        );
    }

    #[test]
    fn a_pass_marker_without_the_full_set_of_nmis_is_a_failure() {
        let directory = scratch("vm-few-nmis");
        let program = fake_qemu(&directory, &FAKE_GUEST.replace("EXPECTED", "540"));
        let outcome = run(&directory, &program, 30, 35);
        assert!(!outcome.passed, "{}", outcome.summary);
    }

    #[test]
    fn the_vm_test_needs_qemu_on_the_path_and_a_usable_kvm_device() {
        let directory = scratch("vm-support");
        let path = std::env::join_paths([&directory]).unwrap();
        let kvm = directory.join("kvm");
        assert!(
            missing_vm_support(Some(&path), &kvm)
                .unwrap()
                .contains("qemu-system-x86_64")
        );
        assert!(missing_vm_support(None, &kvm).is_some());

        fs::write(directory.join("qemu-system-x86_64"), "").unwrap();
        assert!(
            missing_vm_support(Some(&path), &kvm)
                .unwrap()
                .contains("/dev/kvm")
        );

        fs::write(&kvm, "").unwrap();
        assert_eq!(missing_vm_support(Some(&path), &kvm), None);
    }

    #[test]
    fn the_warning_names_the_problem_and_carries_the_marker() {
        let text = unvalidated_warning("qemu-system-x86_64 is not installed");
        assert!(text.contains(UNVALIDATED_MARKER), "{text}");
        assert!(
            text.contains("qemu-system-x86_64 is not installed"),
            "{text}"
        );
        assert!(text.contains("make sure KVM is available"), "{text}");
    }

    #[test]
    fn missing_qemu_is_reported() {
        let directory = scratch("vm-missing");
        let error = run_vm(
            &directory.join("no-such-qemu"),
            Path::new("k"),
            Path::new("i"),
            &directory.join("serial.log"),
            &directory,
            DEADLINES,
        )
        .err()
        .unwrap();
        assert!(error.contains("no-such-qemu"), "{error}");
    }

    #[test]
    fn initramfs_is_a_valid_newc_archive() {
        let entries = [
            Entry {
                name: "dev".into(),
                mode: 0o040755,
                data: Vec::new(),
            },
            Entry {
                name: "init".into(),
                mode: 0o100755,
                data: b"abcde".to_vec(),
            },
        ];
        let archive = newc(&entries);
        assert_eq!(archive.len() % 4, 0);
        let mut position = 0;
        let mut names = Vec::new();
        loop {
            assert_eq!(&archive[position..position + 6], b"070701");
            let field = |index: usize| {
                let start = position + 6 + index * 8;
                u32::from_str_radix(std::str::from_utf8(&archive[start..start + 8]).unwrap(), 16)
                    .unwrap()
            };
            let (size, name_size) = (field(6) as usize, field(11) as usize);
            let name_start = position + 110;
            names.push(
                String::from_utf8(archive[name_start..name_start + name_size - 1].to_vec())
                    .unwrap(),
            );
            let data_start = (name_start + name_size).next_multiple_of(4);
            position = (data_start + size).next_multiple_of(4);
            if names.last().unwrap() == "TRAILER!!!" {
                break;
            }
        }
        assert_eq!(names, ["dev", "init", "TRAILER!!!"]);
        assert_eq!(position, archive.len());
    }

    #[test]
    fn prepare_records_the_fixture_checksums() {
        let fixtures = scratch("prepare-fixtures");
        for name in FIXTURES {
            fs::write(fixtures.join(name), name).unwrap();
        }
        let package = scratch("prepare-package");
        prepare(&package, &fixtures).unwrap();
        let manifest: BTreeMap<String, String> = serde_json::from_str(
            &fs::read_to_string(package.join("validation/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.len(), FIXTURES.len());
        assert_eq!(
            manifest["xstate-compat32"],
            digest(&package.join("validation/xstate-compat32")).unwrap()
        );
    }
}
