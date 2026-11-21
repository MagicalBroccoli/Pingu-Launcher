//! Installing the kernel modules: through DKMS, from the prebuilt SteamOS set, or built on the device on ostree images. The steps need root; the window runs them through pkexec.

use std::fs;
use std::io::Write;
use std::process::Command;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::assets;
use crate::cmd;
use crate::home::Home;
use crate::sys::{CpuInfo, Sys};
use crate::tools;

const OPTIONS_FILE: &str = "/etc/modprobe.d/pingu-policy.conf";
const POLICY_AUTOLOAD: &str = "/etc/modules-load.d/pingu-policy.conf";
/// pkexec's exit codes for a dismissed prompt and for a refusal.
const PKEXEC_DISMISSED: i32 = 126;
const PKEXEC_REFUSED: i32 = 127;
/// SteamOS and ostree images keep the modules and their loader below /var, which updates leave alone.
const STEAMOS_BASE: &str = "/var/lib/pingu-runtime";
const STEAMOS_UNIT: &str = "pingu-modules.service";
/// The loader script, and the copy of this launcher that rebuilds the module on ostree images.
const LOADER_SCRIPT: &str = "pingu-modules-load";
const LAUNCHER_COPY: &str = "pingu-launcher";
/// The transient unit that rebuilds the module in the background after a kernel update.
pub const REBUILD_UNIT: &str = "pingu-modules-rebuild";
/// The key pair that signs the module where the kernel only loads signed ones.
pub const SIGNING_KEY: &str = "/var/lib/pingu-runtime/mok/MOK.priv";
pub const SIGNING_CERT: &str = "/var/lib/pingu-runtime/mok/MOK.der";
/// The module that pingu_policy replaced: its DKMS package, boot loading and SteamOS opt-in file.
const LEGACY_CPUID_PACKAGE: &str = "cpuid_fault_emulation";
const LEGACY_CPUID_AUTOLOAD: &str = "/etc/modules-load.d/cpuid_fault_emulation.conf";
const LEGACY_CPUID_MARKER: &str = "/var/lib/pingu-runtime/enable-cpuid-fault";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Module {
    Policy,
}

impl Module {
    pub fn name(self) -> &'static str {
        match self {
            Self::Policy => "pingu_policy",
        }
    }

    pub fn package(self) -> &'static str {
        match self {
            Self::Policy => "pingu-policy",
        }
    }

    pub fn version(self) -> String {
        match self {
            Self::Policy => assets::module_version(),
        }
    }

    /// The `module` subcommand that installs it.
    pub fn subcommand(self) -> &'static str {
        match self {
            Self::Policy => "install",
        }
    }

    fn dkms_tree(self, version: &str) -> String {
        format!("/var/lib/dkms/{}/{version}", self.package())
    }
}

/// What is left of the deprecated cpuid_fault_emulation module on this machine.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LegacyCpuid {
    pub loaded: bool,
    /// DKMS versions of the package.
    pub dkms: Vec<String>,
    /// Directories below /usr/src.
    pub sources: Vec<String>,
    pub autoload: bool,
    /// The SteamOS file that enabled it at boot.
    pub marker: bool,
}

impl LegacyCpuid {
    pub fn found(&self) -> bool {
        self.loaded
            || !self.dkms.is_empty()
            || !self.sources.is_empty()
            || self.autoload
            || self.marker
    }
}

pub fn legacy_cpuid(sys: &Sys) -> LegacyCpuid {
    LegacyCpuid {
        loaded: sys.module_loaded(LEGACY_CPUID_PACKAGE),
        dkms: subdirectories(sys, &format!("/var/lib/dkms/{LEGACY_CPUID_PACKAGE}")),
        sources: subdirectories(sys, "/usr/src")
            .into_iter()
            .filter(|name| name.starts_with(&format!("{LEGACY_CPUID_PACKAGE}-")))
            .collect(),
        autoload: sys.exists(LEGACY_CPUID_AUTOLOAD),
        marker: sys.exists(LEGACY_CPUID_MARKER),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    RemoveFile(&'static str),
    DkmsRemove {
        package: &'static str,
        version: String,
    },
    RemoveTree(String),
    Export,
    DkmsAdd,
    DkmsInstall,
    Modprobe,
    Selftest,
    Autoload,
    SteamosFiles,
    /// Builds, tests and stores the module for the running kernel (ostree).
    LocalBuild,
    /// The boot loader service and a copy of this launcher that rebuilds after kernel updates (ostree).
    LoaderFiles,
    /// Lets kvm claim SVM only while a virtual machine runs, so the CPUID faulting emulation can use it in between.
    KvmLazy,
    Systemd(&'static [&'static str]),
}

impl Step {
    fn describe(&self, module: Module) -> String {
        let package = module.package();
        let version = module.version();
        match self {
            Self::RemoveFile(path) => format!("Removing {path}"),
            Self::DkmsRemove { package, version } => {
                format!("Removing {package} {version} from DKMS")
            }
            Self::RemoveTree(path) => format!("Removing {path}"),
            Self::Export => format!("Writing the {package} {version} sources to /usr/src"),
            Self::DkmsAdd => format!("Adding {package} {version} to DKMS"),
            Self::DkmsInstall => format!(
                "Building and testing {package} {version} (the VM test takes a minute or two)"
            ),
            Self::Modprobe => format!("Loading {}", module.name()),
            Self::Selftest => "Running the native self test".to_string(),
            Self::Autoload => format!("Loading {} on every boot", module.name()),
            Self::SteamosFiles => "Installing the prebuilt modules and their loader".to_string(),
            Self::LocalBuild => format!(
                "Building and testing {package} {version} for this kernel (the VM test takes a minute or two)"
            ),
            Self::LoaderFiles => {
                "Installing the boot loader, which rebuilds the module after kernel updates"
                    .to_string()
            }
            Self::KvmLazy => {
                format!("Letting kvm claim SVM only while a virtual machine runs ({KVM_LAZY_FILE})")
            }
            Self::Systemd(arguments) => format!("systemctl {}", arguments.join(" ")),
        }
    }
}

fn has_tool(sys: &Sys, name: &str) -> bool {
    sys.which(name).is_some()
        || sys.exists(&format!("/usr/sbin/{name}"))
        || sys.exists(&format!("/usr/bin/{name}"))
}

/// Whether a boot service loads the module, instead of DKMS and modules-load.d: SteamOS and ostree images have a read-only /usr.
pub fn uses_loader(sys: &Sys) -> bool {
    sys.is_steamos() || sys.is_ostree()
}

/// What the on-device build needs and the machine lacks, as Fedora package names.
pub fn local_missing(sys: &Sys) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !sys.exists(&format!(
        "/lib/modules/{}/build/Makefile",
        sys.kernel_release()
    )) {
        missing.push("kernel-devel");
    }
    if !has_tool(sys, "make") {
        missing.push("make");
    }
    if !has_tool(sys, "gcc") {
        missing.push("gcc");
    }
    if !sys.exists("/usr/include/libelf.h") {
        missing.push("elfutils-libelf-devel");
    }
    missing
}

/// The command that layers `missing`; the kernel headers must be those of the running kernel.
pub fn layer_command(missing: &[&str]) -> String {
    let packages: Vec<String> = missing
        .iter()
        .map(|name| match *name {
            "kernel-devel" => "kernel-devel-$(uname -r)".to_string(),
            other => other.to_string(),
        })
        .collect();
    format!("sudo rpm-ostree install {}", packages.join(" "))
}

/// The module is not signed yet and the kernel would refuse it.
pub fn signing_key_missing(sys: &Sys) -> bool {
    sys.module_signature_required() && !(sys.exists(SIGNING_KEY) && sys.exists(SIGNING_CERT))
}

/// The steps that make a key the kernel trusts; enrolling it needs a reboot and a password prompt of the firmware.
pub fn signing_steps() -> String {
    format!(
        "sudo install -d -m 700 /var/lib/pingu-runtime/mok\nsudo openssl req -new -x509 -newkey rsa:2048 -nodes -days 36500 -outform DER -subj \"/CN=pingu-policy module signing/\" -keyout {SIGNING_KEY} -out {SIGNING_CERT}\nsudo mokutil --import {SIGNING_CERT}\nReboot, enroll the key in the blue MOK manager screen, then press Check again."
    )
}

/// The tools the installation needs are there; without them nothing can be installed.
pub fn available(sys: &Sys) -> bool {
    if sys.is_steamos() {
        return has_tool(sys, "pkexec");
    }
    if sys.is_ostree() {
        return has_tool(sys, "pkexec")
            && local_missing(sys).is_empty()
            && !signing_key_missing(sys);
    }
    has_tool(sys, "dkms") && has_tool(sys, "pkexec")
}

pub fn dkms_available(sys: &Sys) -> bool {
    has_tool(sys, "dkms")
}

/// What keeps DKMS from testing the module in a VM, if anything. DKMS runs as root, which can
/// open /dev/kvm whenever the device exists.
pub fn vm_test_problem(sys: &Sys) -> Option<&'static str> {
    if !has_tool(sys, "qemu-system-x86_64") {
        return Some("QEMU (qemu-system-x86_64) is not installed");
    }
    if !sys.exists("/dev/kvm") {
        return Some("KVM is not available (there is no /dev/kvm)");
    }
    None
}

/// Why a module built without the VM test is a risk, for the window and the install log.
pub fn vm_warning(sys: &Sys, problem: &str) -> String {
    let remedy = if sys.is_ostree() {
        "Layer QEMU (sudo rpm-ostree install qemu-system-x86-core) and reboot to get the test."
    } else {
        "Install QEMU to get the test."
    };
    format!(
        "{problem}, so the module is built without its VM test. That test boots the new kernel \
         with the module in a throwaway virtual machine, where a faulty kernel patch only \
         crashes the VM. Without it only the static checks run, and loading the module can \
         crash this computer if the kernel is not compatible. {remedy}"
    )
}

/// The phrase the module tool prints into DKMS's build log when it had to skip the VM test.
const UNVALIDATED_MARKER: &str = "built WITHOUT its VM test";

/// Whether this version was built for the running kernel without the VM test.
pub fn built_without_vm_test(sys: &Sys, version: &str) -> bool {
    let log = if sys.is_ostree() {
        local_log(sys)
    } else {
        format!(
            "{}/{}/x86_64/log/make.log",
            Module::Policy.dkms_tree(version),
            sys.kernel_release()
        )
    };
    sys.read(&log)
        .is_some_and(|text| text.contains(UNVALIDATED_MARKER))
}

/// Whether this launcher carries the prebuilt module for the running SteamOS kernel build.
pub fn prebuilt_available(sys: &Sys, module: Module) -> bool {
    sys.steamos_module(&format!("{}.ko", module.name()))
        .is_some()
}

/// Where the prebuilt module of the running kernel build is installed.
pub fn steamos_installed_path(sys: &Sys, module: Module) -> Option<String> {
    Some(format!(
        "{STEAMOS_BASE}/modules/{}/{}.ko",
        sys.kernel_build_id()?,
        module.name()
    ))
}

/// The build log of the module of the running kernel on an ostree image.
fn local_log(sys: &Sys) -> String {
    format!(
        "{STEAMOS_BASE}/logs/{}.log",
        sys.kernel_build_id().unwrap_or_default()
    )
}

/// Where the module built on this machine for the running kernel build is stored.
pub fn local_module_dir(sys: &Sys) -> Option<String> {
    Some(format!("{STEAMOS_BASE}/modules/{}", sys.kernel_build_id()?))
}

/// Whether the module of this launcher was built on this machine for the running kernel build.
fn local_installed(sys: &Sys, module: Module) -> bool {
    let Some(directory) = local_module_dir(sys) else {
        return false;
    };
    sys.exists(&format!("{directory}/{}.ko", module.name()))
        && sys
            .read(&format!("{directory}/VERSION"))
            .is_some_and(|text| text.trim() == module.version())
}

/// Whether the module of this launcher is installed for the running kernel, which a reboot then loads.
pub fn installed_for_running_kernel(sys: &Sys, module: Module) -> bool {
    if sys.is_ostree() {
        return local_installed(sys, module);
    }
    if !sys.is_steamos() {
        return built_for_running_kernel(sys, module);
    }
    let file = format!("{}.ko", module.name());
    let (Some(asset), Some(path)) = (
        sys.steamos_module(&file),
        steamos_installed_path(sys, module),
    ) else {
        return false;
    };
    sys.read_bytes(&path)
        .is_some_and(|bytes| bytes == asset.data)
}

/// The one line per file in a build's `SHA256SUMS`, checked against what is embedded.
fn verify_embedded_build(sys: &Sys, build: &str) -> Result<(), String> {
    let sums = sys
        .steamos_modules
        .iter()
        .find(|asset| asset.path == format!("{build}/SHA256SUMS"))
        .ok_or_else(|| format!("build {build} has no SHA256SUMS"))?;
    for line in String::from_utf8_lossy(sums.data).lines() {
        let Some((hash, name)) = line.split_once("  ") else {
            continue;
        };
        let asset = sys
            .steamos_modules
            .iter()
            .find(|asset| asset.path == format!("{build}/{name}"))
            .ok_or_else(|| format!("build {build} lacks {name}"))?;
        let actual: String = Sha256::digest(asset.data)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if actual != hash {
            return Err(format!("{build}/{name} does not match its checksum"));
        }
    }
    Ok(())
}

/// Whether DKMS has built `module` of this version for the running kernel.
pub fn built_for_running_kernel(sys: &Sys, module: Module) -> bool {
    sys.exists(&format!(
        "{}/{}/x86_64/module",
        module.dkms_tree(&module.version()),
        sys.kernel_release()
    ))
}

fn sources_match(sys: &Sys, module: Module, source: &str) -> bool {
    let directory = sys.path(source);
    match module {
        Module::Policy => assets::module_sources_match(&directory),
    }
}

fn loaded_version(sys: &Sys, module: Module) -> Option<String> {
    sys.read(&format!("/sys/module/{}/version", module.name()))
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// What has to happen to get `module` installed and loaded on this machine.
pub fn plan(sys: &Sys, module: Module) -> Vec<Step> {
    if sys.is_steamos() {
        return steamos_plan(sys, module);
    }
    if sys.is_ostree() {
        return local_plan(sys, module);
    }
    let version = module.version();
    let mut steps = Vec::new();
    // Versions before 0.4.0 needed options that the module no longer accepts.
    if sys.exists(OPTIONS_FILE) {
        steps.push(Step::RemoveFile(OPTIONS_FILE));
    }
    if let Some(loaded) = loaded_version(sys, module)
        && loaded != version
        && sys.exists(&module.dkms_tree(&loaded))
    {
        steps.push(Step::DkmsRemove {
            package: module.package(),
            version: loaded,
        });
    }
    // pingu_policy took over the deprecated module's work; what is loaded keeps running until reboot.
    let legacy = legacy_cpuid(sys);
    for version in legacy.dkms {
        steps.push(Step::DkmsRemove {
            package: LEGACY_CPUID_PACKAGE,
            version,
        });
    }
    for name in legacy.sources {
        steps.push(Step::RemoveTree(format!("/usr/src/{name}")));
    }
    if legacy.autoload {
        steps.push(Step::RemoveFile(LEGACY_CPUID_AUTOLOAD));
    }
    // Sources of the same version that differ (a build from before a fix) are replaced, with
    // DKMS's copy of that version, so the module is built from what this launcher carries.
    let source = format!("/usr/src/{}-{version}", module.package());
    let replaced = sys.exists(&source) && !sources_match(sys, module, &source);
    let tree = module.dkms_tree(&version);
    if replaced {
        if sys.exists(&tree) {
            steps.push(Step::DkmsRemove {
                package: module.package(),
                version: version.clone(),
            });
        }
        steps.push(Step::RemoveTree(source));
    }
    steps.push(Step::Export);
    if replaced || !sys.exists(&tree) {
        steps.push(Step::DkmsAdd);
    }
    if replaced || !built_for_running_kernel(sys, module) {
        steps.push(Step::DkmsInstall);
    }
    if kvm_lazy_missing(sys) {
        steps.push(Step::KvmLazy);
    }
    if !sys.module_loaded(module.name()) {
        steps.push(Step::Modprobe);
        steps.push(Step::Selftest);
    }
    if !sys.exists(POLICY_AUTOLOAD) {
        steps.push(Step::Autoload);
    }
    steps
}

/// SteamOS has no DKMS: the prebuilt modules and the loader are written and the service started.
fn steamos_plan(sys: &Sys, module: Module) -> Vec<Step> {
    let mut steps = Vec::new();
    if legacy_cpuid(sys).marker {
        steps.push(Step::RemoveFile(LEGACY_CPUID_MARKER));
    }
    steps.push(Step::SteamosFiles);
    steps.push(Step::Systemd(&["daemon-reload"]));
    steps.push(Step::Systemd(&["enable", STEAMOS_UNIT]));
    steps.push(Step::Systemd(&["restart", STEAMOS_UNIT]));
    if !sys.module_loaded(module.name()) {
        steps.push(Step::Selftest);
    }
    steps
}

/// An ostree image has no DKMS install: the module is built here, kept below /var and loaded by the service.
fn local_plan(sys: &Sys, module: Module) -> Vec<Step> {
    let mut steps = Vec::new();
    if legacy_cpuid(sys).marker {
        steps.push(Step::RemoveFile(LEGACY_CPUID_MARKER));
    }
    if !local_installed(sys, module) {
        steps.push(Step::LocalBuild);
    }
    if kvm_lazy_missing(sys) {
        steps.push(Step::KvmLazy);
    }
    steps.push(Step::LoaderFiles);
    steps.push(Step::Systemd(&["daemon-reload"]));
    steps.push(Step::Systemd(&["enable", STEAMOS_UNIT]));
    steps.push(Step::Systemd(&["restart", STEAMOS_UNIT]));
    if !sys.module_loaded(module.name()) {
        steps.push(Step::Selftest);
    }
    steps
}

/// The kvm option that leaves SVM free until a virtual machine exists; kernels before 6.16 always behave so.
pub const KVM_LAZY_FILE: &str = "/etc/modprobe.d/pingu-kvm-lazy.conf";
const KVM_LAZY_TEXT: &str = "# Written by pingu-launcher. kvm claims SVM only while a virtual machine exists, so the CPUID faulting\n# emulation of pingu_policy can use SVM in between. A virtual machine cannot start while a game runs.\noptions kvm enable_virt_at_load=0\n";

/// Whether the CPUID faulting emulation of pingu_policy will run here: an AMD CPU with SVM that cannot fault CPUID itself.
pub fn needs_kvm_lazy(sys: &Sys) -> bool {
    let cpu = CpuInfo::read(sys);
    if cpu.vendor != "AuthenticAMD" || !cpu.has("svm") {
        return false;
    }
    match sys.read("/sys/module/pingu_policy/parameters/cpuid_fault") {
        Some(state) => matches!(state.trim(), "emulated" | "on_demand" | "busy"),
        None => !(sys.cpuid_faulting)(),
    }
}

fn kvm_lazy_missing(sys: &Sys) -> bool {
    needs_kvm_lazy(sys) && sys.read(KVM_LAZY_FILE).as_deref() != Some(KVM_LAZY_TEXT)
}

/// Writes the kvm option and, when no virtual machine runs, reloads kvm so that it applies now.
fn write_kvm_lazy(sys: &Sys) -> Result<(), String> {
    let path = sys.path(KVM_LAZY_FILE);
    assets::install(&path, KVM_LAZY_TEXT.as_bytes(), 0o644)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let eager = |sys: &Sys| {
        sys.read("/sys/module/kvm/parameters/enable_virt_at_load")
            .is_some_and(|text| text.trim() == "Y")
    };
    if !eager(sys) || !sys.module_loaded("kvm_amd") {
        return Ok(());
    }
    let users = sys
        .read("/sys/module/kvm_amd/refcnt")
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(1);
    if users != 0 {
        println!(
            "kvm_amd is in use by a virtual machine. The setting applies after it stops and kvm_amd is reloaded, or after a reboot."
        );
        return Ok(());
    }
    let reloaded = external(
        Command::new("modprobe").args(["-r", "kvm_amd", "kvm"]),
        "modprobe -r",
    )
    .and_then(|()| external(Command::new("modprobe").arg("kvm_amd"), "modprobe kvm_amd"));
    if reloaded.is_err() || eager(sys) {
        println!(
            "WARNING: kvm could not be reloaded. The setting applies after a reboot; until then a game cannot use CPUID faulting while kvm_amd holds SVM."
        );
    }
    Ok(())
}

/// Writes the loader script and its unit; `with_launcher` also keeps a copy of this launcher that the script runs to rebuild the module after a kernel update.
fn write_loader(sys: &Sys, with_launcher: bool) -> Result<(), String> {
    for asset in assets::STEAMOS_LOADER {
        let destination = if asset.path == STEAMOS_UNIT {
            sys.path(&format!("/etc/systemd/system/{STEAMOS_UNIT}"))
        } else {
            sys.path(STEAMOS_BASE).join(asset.path)
        };
        assets::install(&destination, asset.data, asset.mode)
            .map_err(|error| format!("{}: {error}", destination.display()))?;
    }
    if with_launcher {
        let data = fs::read(&sys.exe).map_err(|error| format!("{}: {error}", sys.exe.display()))?;
        let destination = sys.path(STEAMOS_BASE).join(LAUNCHER_COPY);
        assets::install(&destination, &data, 0o755)
            .map_err(|error| format!("{}: {error}", destination.display()))?;
    }
    relabel(sys);
    Ok(())
}

/// Best effort: with SELinux enforcing, the loader service and kmod only use files that carry the types of system files.
fn relabel(sys: &Sys) {
    if !sys.exists("/sys/fs/selinux/enforce") {
        return;
    }
    let Some(chcon) = sys.which("chcon") else {
        return;
    };
    let base = sys.path(STEAMOS_BASE);
    let mut attempts = vec![vec![
        "-R".to_string(),
        "-t".into(),
        "modules_object_t".into(),
        base.join("modules").to_string_lossy().into_owned(),
    ]];
    let programs: Vec<String> = [LOADER_SCRIPT, LAUNCHER_COPY]
        .iter()
        .map(|name| base.join(name))
        .filter(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    if !programs.is_empty() {
        attempts.push(
            ["-t".to_string(), "bin_t".into()]
                .into_iter()
                .chain(programs)
                .collect(),
        );
    }
    for arguments in attempts {
        if let Err(error) = external(Command::new(&chcon).args(&arguments), "chcon") {
            println!("WARNING: {error}. SELinux may keep the service from using the files.");
        }
    }
}

/// Builds the module against the headers of the running kernel, tests it in the VM, signs it if the kernel demands it and stores it where the loader looks.
fn local_build(sys: &Sys, module: Module) -> Result<(), String> {
    let release = sys.kernel_release();
    let build_id = sys
        .kernel_build_id()
        .ok_or("Cannot read the kernel build ID from /sys/kernel/notes.")?;
    let headers = sys.path(&format!("/lib/modules/{release}/build"));
    let scratch = format!("{STEAMOS_BASE}/build/{build_id}");
    let work = sys.path(&scratch);
    remove_path(sys, &scratch, true)?;
    assets::export_module(&work)?;
    let make = sys.which("make").unwrap_or_else(|| "make".into());
    let log = Mutex::new(String::new());
    let status = cmd::stream(
        Command::new(make)
            .arg("-C")
            .arg(&work)
            .arg(format!("XCR0_HEADERS={}", headers.display()))
            .arg(format!("XCR0_RELEASE={release}"))
            .arg("dkms-validated-build"),
        &|line| {
            println!("{line}");
            if let Ok(mut text) = log.lock() {
                text.push_str(line);
                text.push('\n');
            }
        },
    )?;
    let text = log.into_inner().unwrap_or_default();
    // A log that cannot be written only costs the warning about a skipped VM test.
    let _ = assets::install(&sys.path(&local_log(sys)), text.as_bytes(), 0o644);
    if !status.success() {
        return Err(format!("Building {} failed ({status}).", module.name()));
    }
    let built = work.join(format!("{}.ko", module.name()));
    if !built.exists() {
        return Err(format!("The build left no {}.", built.display()));
    }
    if sys.module_signature_required() {
        let (key, cert) = (sys.path(SIGNING_KEY), sys.path(SIGNING_CERT));
        if !key.exists() || !cert.exists() {
            return Err(format!(
                "This kernel only loads signed modules and there is no signing key.\n{}",
                signing_steps()
            ));
        }
        external(
            Command::new(headers.join("scripts/sign-file"))
                .arg("sha256")
                .arg(&key)
                .arg(&cert)
                .arg(&built),
            "sign-file",
        )?;
    }
    let data = fs::read(&built).map_err(|error| format!("{}: {error}", built.display()))?;
    let directory = sys.path(&format!("{STEAMOS_BASE}/modules/{build_id}"));
    let destination = directory.join(format!("{}.ko", module.name()));
    assets::install(&destination, &data, 0o644)
        .map_err(|error| format!("{}: {error}", destination.display()))?;
    // Written last, so a half installed build never counts as installed.
    let version = directory.join("VERSION");
    assets::install(
        &version,
        format!("{}\n", module.version()).as_bytes(),
        0o644,
    )
    .map_err(|error| format!("{}: {error}", version.display()))?;
    remove_path(sys, &scratch, true)?;
    relabel(sys);
    Ok(())
}

/// The prerequisites of the on-device build as an error text, or None when they are met.
fn local_prerequisites(sys: &Sys) -> Option<String> {
    let missing = local_missing(sys);
    if !missing.is_empty() {
        return Some(format!(
            "The module is built on this machine and needs {}. Layer them, reboot, and run this again:\n{}",
            missing.join(", "),
            layer_command(&missing)
        ));
    }
    if signing_key_missing(sys) {
        return Some(format!(
            "This kernel only loads signed modules. Make and enroll a signing key first:\n{}",
            signing_steps()
        ));
    }
    None
}

/// Builds the module for the running kernel without touching the service; the loader runs this after a kernel update. Must run as root.
pub fn rebuild(sys: &Sys, module: Module) -> Result<(), String> {
    // SAFETY: geteuid has no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err("Rebuilding a module needs root.".into());
    }
    if !sys.is_ostree() {
        return Err(
            "module rebuild is for ostree images; other systems rebuild through DKMS.".into(),
        );
    }
    if let Some(problem) = local_prerequisites(sys) {
        return Err(problem);
    }
    println!("==> {}", Step::LocalBuild.describe(module));
    local_build(sys, module)
}

fn write_steamos_files(sys: &Sys) -> Result<(), String> {
    let mut builds: Vec<&str> = sys
        .steamos_modules
        .iter()
        .filter_map(|asset| asset.path.split_once('/').map(|(build, _)| build))
        .collect();
    builds.dedup();
    for build in &builds {
        verify_embedded_build(sys, build)?;
    }
    // Only the builds of this launcher stay, like the bundle installer did.
    let modules = sys.path(&format!("{STEAMOS_BASE}/modules"));
    match fs::remove_dir_all(&modules) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", modules.display())),
    }
    for asset in sys.steamos_modules {
        let destination = modules.join(asset.path);
        assets::install(&destination, asset.data, 0o644)
            .map_err(|error| format!("{}: {error}", destination.display()))?;
    }
    write_loader(sys, false)
}

fn external(command: &mut Command, what: &str) -> Result<(), String> {
    let status = cmd::stream(command, &|line| println!("{line}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed ({status})"))
    }
}

fn execute(sys: &Sys, home: &Home, module: Module, step: &Step) -> Result<(), String> {
    let package = module.package();
    let version = module.version();
    match step {
        Step::RemoveFile(path) => match fs::remove_file(sys.path(path)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("{path}: {error}")),
        },
        Step::DkmsRemove { package, version } => external(
            Command::new("dkms").args(["remove", &format!("{package}/{version}"), "--all"]),
            "dkms remove",
        ),
        Step::RemoveTree(path) => remove_path(sys, path, true),
        Step::Export => {
            let destination = sys.path(&format!("/usr/src/{package}-{version}"));
            assets::export_module(&destination).map(|_| ())
        }
        Step::DkmsAdd => external(
            Command::new("dkms").args(["add", "-m", package, "-v", &version]),
            "dkms add",
        ),
        Step::DkmsInstall => external(
            Command::new("dkms").args([
                "install",
                "-m",
                package,
                "-v",
                &version,
                "-k",
                &sys.kernel_release(),
            ]),
            "dkms install",
        ),
        Step::Modprobe => external(Command::new("modprobe").arg(module.name()), "modprobe")
            .map_err(|error| {
                format!(
                    "{error}. The reason is in the kernel log: dmesg | grep -i {}",
                    module.name()
                )
            }),
        Step::Selftest => tools::selftest(sys, home),
        Step::SteamosFiles => write_steamos_files(sys),
        Step::LocalBuild => local_build(sys, module),
        Step::LoaderFiles => write_loader(sys, true),
        Step::KvmLazy => write_kvm_lazy(sys),
        Step::Systemd(arguments) => external(
            Command::new("systemctl").args(*arguments),
            &format!("systemctl {}", arguments[0]),
        ),
        Step::Autoload => {
            let path = sys.path(POLICY_AUTOLOAD);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("{}: {error}", parent.display()))?;
            }
            let mut file =
                fs::File::create(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            writeln!(file, "{}", module.name())
                .map_err(|error| format!("{}: {error}", path.display()))
        }
    }
}

/// Installs `module`; must run as root. Progress goes to stdout.
pub fn run(sys: &Sys, home: &Home, module: Module) -> Result<(), String> {
    // SAFETY: geteuid has no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err(format!(
            "Installing a module needs root. Run `sudo {} module {}` or use the button in the window.",
            sys.exe.display(),
            module.subcommand()
        ));
    }
    if sys.is_steamos() && !prebuilt_available(sys, module) {
        return Err(format!(
            "This launcher has no prebuilt {} for SteamOS kernel {} (build ID {}).",
            module.name(),
            sys.kernel_release(),
            sys.kernel_build_id().unwrap_or_default()
        ));
    }
    if let Some(problem) = sys.is_ostree().then(|| local_prerequisites(sys)).flatten() {
        return Err(problem);
    }
    for step in plan(sys, module) {
        println!("==> {}", step.describe(module));
        if matches!(step, Step::DkmsInstall | Step::LocalBuild)
            && let Some(problem) = vm_test_problem(sys)
        {
            println!("WARNING: {}", vm_warning(sys, problem));
        }
        execute(sys, home, module, &step)?;
    }
    let loaded = loaded_version(sys, module);
    if loaded.is_some_and(|loaded| loaded != module.version()) {
        println!(
            "==> {} {} is installed. Reboot to load it instead of the version that is running.",
            module.package(),
            module.version()
        );
    } else {
        println!("==> Done.");
    }
    Ok(())
}

/// What the uninstallation removes, in order.
#[derive(Debug, PartialEq, Eq)]
pub enum Removal {
    File(String),
    Tree(String),
    Dkms {
        package: &'static str,
        version: String,
    },
    Systemd(&'static [&'static str]),
}

impl Removal {
    fn describe(&self) -> String {
        match self {
            Self::File(path) | Self::Tree(path) => format!("Removing {path}"),
            Self::Dkms { package, version } => format!("Removing {package} {version} from DKMS"),
            Self::Systemd(arguments) => format!("systemctl {}", arguments.join(" ")),
        }
    }
}

/// The real directories below `absolute`; DKMS also keeps `kernel-*` symlinks next to its versions.
fn subdirectories(sys: &Sys, absolute: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(sys.path(absolute))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Everything the installation put on the system; the user's data directory is not part of it.
pub fn uninstall_plan(sys: &Sys) -> Vec<Removal> {
    let mut steps = Vec::new();
    if uses_loader(sys) {
        let unit = format!("/etc/systemd/system/{STEAMOS_UNIT}");
        if sys.exists(&unit) {
            steps.push(Removal::Systemd(&["disable", "--now", STEAMOS_UNIT]));
            steps.push(Removal::File(unit));
            steps.push(Removal::Systemd(&["daemon-reload"]));
        }
        if sys.exists(STEAMOS_BASE) {
            steps.push(Removal::Tree(STEAMOS_BASE.to_string()));
        }
        if sys.exists(KVM_LAZY_FILE) {
            steps.push(Removal::File(KVM_LAZY_FILE.to_string()));
        }
        return steps;
    }
    for package in [Module::Policy.package(), LEGACY_CPUID_PACKAGE] {
        for version in subdirectories(sys, &format!("/var/lib/dkms/{package}")) {
            steps.push(Removal::Dkms { package, version });
        }
        for name in subdirectories(sys, "/usr/src") {
            if name.starts_with(&format!("{package}-")) {
                steps.push(Removal::Tree(format!("/usr/src/{name}")));
            }
        }
    }
    for file in [
        POLICY_AUTOLOAD,
        LEGACY_CPUID_AUTOLOAD,
        OPTIONS_FILE,
        KVM_LAZY_FILE,
    ] {
        if sys.exists(file) {
            steps.push(Removal::File(file.to_string()));
        }
    }
    steps
}

/// Whether there is anything to uninstall.
pub fn installed(sys: &Sys) -> bool {
    !uninstall_plan(sys).is_empty()
}

fn remove_path(sys: &Sys, path: &str, tree: bool) -> Result<(), String> {
    let target = sys.path(path);
    let result = if tree {
        fs::remove_dir_all(&target)
    } else {
        fs::remove_file(&target)
    };
    match result {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{path}: {error}"))
        }
        _ => Ok(()),
    }
}

/// Removes the installed modules and their loading at boot; must run as root.
pub fn uninstall(sys: &Sys) -> Result<(), String> {
    // SAFETY: geteuid has no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err(format!(
            "Uninstalling needs root. Run `sudo {} module uninstall` or use the button in the window.",
            sys.exe.display()
        ));
    }
    for step in uninstall_plan(sys) {
        println!("==> {}", step.describe());
        match &step {
            Removal::File(path) => remove_path(sys, path, false)?,
            Removal::Tree(path) => remove_path(sys, path, true)?,
            // An earlier removal can take other entries of the same tree along.
            Removal::Dkms { package, version }
                if !sys.exists(&format!("/var/lib/dkms/{package}/{version}")) => {}
            Removal::Dkms { package, version } => external(
                Command::new("dkms").args(["remove", &format!("{package}/{version}"), "--all"]),
                "dkms remove",
            )?,
            Removal::Systemd(arguments) => external(
                Command::new("systemctl").args(*arguments),
                &format!("systemctl {}", arguments[0]),
            )?,
        }
    }
    if sys.module_loaded(Module::Policy.name()) {
        println!(
            "==> pingu_policy stays loaded until you reboot. Never unload it: games that already started keep working with it."
        );
    } else {
        println!("==> Done.");
    }
    Ok(())
}

/// Runs the installation as root through pkexec and streams its output.
pub fn run_elevated(
    sys: &Sys,
    module: Module,
    on_line: &(dyn Fn(&str) + Sync),
) -> Result<(), String> {
    elevate(sys, module.subcommand(), on_line)
}

/// Runs the uninstallation as root through pkexec and streams its output.
pub fn run_elevated_uninstall(sys: &Sys, on_line: &(dyn Fn(&str) + Sync)) -> Result<(), String> {
    elevate(sys, "uninstall", on_line)
}

fn elevate(sys: &Sys, subcommand: &str, on_line: &(dyn Fn(&str) + Sync)) -> Result<(), String> {
    let pkexec = sys.which("pkexec").ok_or(
        "pkexec (polkit) is needed to ask for the password. Run the steps with sudo instead.",
    )?;
    let mut command = Command::new(pkexec);
    command.arg(&sys.exe).args(["module", subcommand]);
    let status = cmd::stream(&mut command, on_line)?;
    match status.code() {
        Some(0) => Ok(()),
        Some(PKEXEC_DISMISSED) => Err("The authentication was cancelled.".into()),
        Some(PKEXEC_REFUSED) => Err(
            "polkit refused to run the installation. Is a polkit authentication agent running?"
                .into(),
        ),
        _ => Err(format!("The {subcommand} failed ({status}).")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn machine(name: &str) -> Sys {
        let root = crate::scratch(name);
        let write = |relative: &str, content: &str| {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        };
        write("proc/sys/kernel/osrelease", "7.3.5-test\n");
        Sys {
            root,
            env: HashMap::new(),
            cwd: PathBuf::new(),
            exe: PathBuf::from("/opt/pingu-launcher"),
            cpuid_faulting: || true,
            native_xcr0: || Some(0x2e7),
            arm_check: |_, _| Ok(()),
            steamos_modules: &[],
        }
    }

    fn write(sys: &Sys, relative: &str, content: &str) {
        let path = sys.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn a_fresh_machine_gets_every_step() {
        let sys = machine("install-fresh");
        assert_eq!(
            plan(&sys, Module::Policy),
            [
                Step::Export,
                Step::DkmsAdd,
                Step::DkmsInstall,
                Step::Modprobe,
                Step::Selftest,
                Step::Autoload
            ]
        );
    }

    #[test]
    fn an_older_loaded_version_is_replaced_without_loading_the_new_one() {
        let sys = machine("install-upgrade");
        write(&sys, "sys/module/pingu_policy/version", "0.3.0\n");
        write(&sys, "var/lib/dkms/pingu-policy/0.3.0/source", "");
        write(
            &sys,
            "etc/modprobe.d/pingu-policy.conf",
            "options pingu_policy experiment=1\n",
        );
        write(
            &sys,
            "etc/modules-load.d/pingu-policy.conf",
            "pingu_policy\n",
        );
        assert_eq!(
            plan(&sys, Module::Policy),
            [
                Step::RemoveFile(OPTIONS_FILE),
                Step::DkmsRemove {
                    package: "pingu-policy",
                    version: "0.3.0".into()
                },
                Step::Export,
                Step::DkmsAdd,
                Step::DkmsInstall,
            ]
        );
    }

    #[test]
    fn finished_work_is_skipped() {
        let sys = machine("install-done");
        let version = Module::Policy.version();
        write(
            &sys,
            &format!(
                "var/lib/dkms/pingu-policy/{version}/7.3.5-test/x86_64/module/pingu_policy.ko"
            ),
            "",
        );
        write(
            &sys,
            "sys/module/pingu_policy/version",
            &format!("{version}\n"),
        );
        write(
            &sys,
            "etc/modules-load.d/pingu-policy.conf",
            "pingu_policy\n",
        );
        assert!(built_for_running_kernel(&sys, Module::Policy));
        assert_eq!(plan(&sys, Module::Policy), [Step::Export]);
    }

    #[test]
    fn sources_that_differ_are_replaced_together_with_dkms_copy() {
        let sys = machine("install-stale-sources");
        let version = Module::Policy.version();
        let source = format!("usr/src/pingu-policy-{version}");
        write(&sys, &format!("{source}/Makefile"), "from an older build");
        write(
            &sys,
            &format!("var/lib/dkms/pingu-policy/{version}/source"),
            "",
        );
        write(
            &sys,
            &format!(
                "var/lib/dkms/pingu-policy/{version}/7.3.5-test/x86_64/module/pingu_policy.ko"
            ),
            "",
        );
        write(
            &sys,
            "sys/module/pingu_policy/version",
            &format!("{version}\n"),
        );
        write(
            &sys,
            "etc/modules-load.d/pingu-policy.conf",
            "pingu_policy\n",
        );
        assert_eq!(
            plan(&sys, Module::Policy),
            [
                Step::DkmsRemove {
                    package: "pingu-policy",
                    version: version.clone()
                },
                Step::RemoveTree(format!("/{source}")),
                Step::Export,
                Step::DkmsAdd,
                Step::DkmsInstall,
            ]
        );
    }

    #[test]
    fn exactly_matching_sources_stay_and_extra_files_do_not() {
        let sys = machine("install-matching-sources");
        let version = Module::Policy.version();
        let source = format!("usr/src/pingu-policy-{version}");
        assets::export_module(&sys.root.join(&source)).unwrap();
        assert!(
            !plan(&sys, Module::Policy)
                .iter()
                .any(|step| matches!(step, Step::RemoveTree(_)))
        );
        write(&sys, &format!("{source}/profile.py"), "left over");
        assert!(
            plan(&sys, Module::Policy)
                .iter()
                .any(|step| matches!(step, Step::RemoveTree(_)))
        );
    }

    #[test]
    fn the_deprecated_cpuid_module_is_removed_but_left_loaded() {
        let sys = machine("install-legacy-cpuid");
        write(&sys, "sys/module/cpuid_fault_emulation/version", "");
        write(&sys, "var/lib/dkms/cpuid_fault_emulation/0.1/source", "");
        write(&sys, "usr/src/cpuid_fault_emulation-0.1/Makefile", "");
        write(
            &sys,
            "etc/modules-load.d/cpuid_fault_emulation.conf",
            "cpuid_fault_emulation\n",
        );
        let legacy = legacy_cpuid(&sys);
        assert!(legacy.found() && legacy.loaded && legacy.autoload);
        assert_eq!(
            plan(&sys, Module::Policy),
            [
                Step::DkmsRemove {
                    package: "cpuid_fault_emulation",
                    version: "0.1".into()
                },
                Step::RemoveTree("/usr/src/cpuid_fault_emulation-0.1".into()),
                Step::RemoveFile(LEGACY_CPUID_AUTOLOAD),
                Step::Export,
                Step::DkmsAdd,
                Step::DkmsInstall,
                Step::Modprobe,
                Step::Selftest,
                Step::Autoload
            ]
        );
        assert!(!legacy_cpuid(&machine("install-no-legacy")).found());
    }

    #[test]
    fn installing_without_root_names_the_command() {
        // SAFETY: only reads the effective user id.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let sys = machine("install-root");
        let home = Home {
            root: sys.root.join("home"),
        };
        let error = run(&sys, &home, Module::Policy).unwrap_err();
        assert!(
            error.contains("sudo /opt/pingu-launcher module install"),
            "{error}"
        );
    }

    /// Embedded builds as a release would carry them, with a correct or a broken checksum list.
    fn builds(good: bool) -> &'static [assets::Asset] {
        let asset = |path: &str, data: &'static [u8]| assets::Asset {
            path: Box::leak(path.to_string().into_boxed_str()),
            mode: 0o644,
            data,
        };
        let digest = |data: &[u8]| {
            Sha256::digest(data)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let sums = format!(
            "{}  pingu_policy.ko\n{}  other.ko\n",
            digest(b"policy"),
            if good { digest(b"other") } else { digest(b"x") }
        );
        Box::leak(
            vec![
                asset("aa/pingu_policy.ko", b"policy"),
                asset("aa/other.ko", b"other"),
                asset(
                    "aa/SHA256SUMS",
                    Box::leak(sums.into_bytes().into_boxed_slice()),
                ),
            ]
            .into_boxed_slice(),
        )
    }

    fn steamos(name: &str) -> Sys {
        let mut sys = machine(name);
        write(&sys, "etc/os-release", "ID=steamos\n");
        sys.steamos_modules = builds(true);
        sys
    }

    #[test]
    fn steamos_installs_files_and_restarts_the_loader() {
        let sys = steamos("install-steamos-plan");
        let reload = Step::Systemd(&["daemon-reload"]);
        let enable = Step::Systemd(&["enable", STEAMOS_UNIT]);
        let restart = Step::Systemd(&["restart", STEAMOS_UNIT]);
        assert_eq!(
            plan(&sys, Module::Policy),
            [Step::SteamosFiles, reload, enable, restart, Step::Selftest]
        );
        // The opt-in file of the deprecated cpuid module goes away with the new loader.
        write(&sys, "var/lib/pingu-runtime/enable-cpuid-fault", "");
        assert_eq!(
            plan(&sys, Module::Policy)[..2],
            [Step::RemoveFile(LEGACY_CPUID_MARKER), Step::SteamosFiles]
        );
    }

    #[test]
    fn steamos_files_replace_the_old_builds_and_install_the_loader() {
        let sys = steamos("install-steamos-files");
        write(
            &sys,
            "var/lib/pingu-runtime/modules/stale/pingu_policy.ko",
            "old",
        );
        write_steamos_files(&sys).unwrap();
        let base = sys.root.join("var/lib/pingu-runtime");
        assert_eq!(
            fs::read(base.join("modules/aa/pingu_policy.ko")).unwrap(),
            b"policy"
        );
        assert!(!base.join("modules/stale").exists());
        let mode = |path: &std::path::Path| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&base.join("pingu-modules-load")), 0o755);
        assert_eq!(
            mode(&sys.root.join("etc/systemd/system/pingu-modules.service")),
            0o644
        );
    }

    #[test]
    fn a_build_that_does_not_match_its_checksums_is_refused() {
        let mut sys = steamos("install-steamos-broken");
        sys.steamos_modules = builds(false);
        let error = write_steamos_files(&sys).unwrap_err();
        assert!(error.contains("does not match its checksum"), "{error}");
        assert!(!sys.root.join("var/lib/pingu-runtime/modules/aa").exists());
    }

    #[test]
    fn installed_files_count_only_when_they_equal_the_embedded_ones() {
        let mut sys = steamos("install-steamos-current");
        write(&sys, "sys/kernel/notes", "");
        // The build ID decides, so give the machine the ID the assets are named by.
        let mut notes = Vec::new();
        for word in [4u32, 1, 3] {
            notes.extend(word.to_ne_bytes());
        }
        notes.extend(b"GNU\0");
        notes.push(0xaa);
        notes.extend([0u8; 3]);
        fs::write(sys.root.join("sys/kernel/notes"), notes).unwrap();
        sys.steamos_modules = builds(true);
        assert!(!installed_for_running_kernel(&sys, Module::Policy));
        write(
            &sys,
            "var/lib/pingu-runtime/modules/aa/pingu_policy.ko",
            "different",
        );
        assert!(!installed_for_running_kernel(&sys, Module::Policy));
        write(
            &sys,
            "var/lib/pingu-runtime/modules/aa/pingu_policy.ko",
            "policy",
        );
        assert!(installed_for_running_kernel(&sys, Module::Policy));
        assert!(prebuilt_available(&sys, Module::Policy));
    }

    /// A Bazzite-like machine: ostree, kernel build ID `aa`, headers and the build tools in `bin`.
    fn ostree(name: &str) -> Sys {
        use std::os::unix::fs::PermissionsExt;
        let mut sys = machine(name);
        sys.env.insert(
            "PATH".into(),
            sys.root.join("bin").to_string_lossy().into_owned(),
        );
        write(&sys, "run/ostree-booted", "");
        let mut notes = Vec::new();
        for word in [4u32, 1, 3] {
            notes.extend(word.to_ne_bytes());
        }
        notes.extend(b"GNU\0");
        notes.push(0xaa);
        notes.extend([0u8; 3]);
        fs::create_dir_all(sys.root.join("sys/kernel")).unwrap();
        fs::write(sys.root.join("sys/kernel/notes"), notes).unwrap();
        write(&sys, "lib/modules/7.3.5-test/build/Makefile", "");
        write(&sys, "usr/include/libelf.h", "");
        // The fake make builds a module where the real one would.
        write(
            &sys,
            "bin/make",
            "#!/bin/sh\necho \"make $*\"\ncd \"$2\" && printf built > pingu_policy.ko\n",
        );
        write(&sys, "bin/gcc", "#!/bin/sh\n");
        write(&sys, "bin/pkexec", "#!/bin/sh\n");
        for tool in ["make", "gcc", "pkexec"] {
            let path = sys.root.join("bin").join(tool);
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        sys
    }

    #[test]
    fn ostree_builds_here_and_loads_through_the_service() {
        let sys = ostree("install-ostree-plan");
        assert!(uses_loader(&sys) && available(&sys));
        let reload = Step::Systemd(&["daemon-reload"]);
        let enable = Step::Systemd(&["enable", STEAMOS_UNIT]);
        let restart = Step::Systemd(&["restart", STEAMOS_UNIT]);
        assert_eq!(
            plan(&sys, Module::Policy),
            [
                Step::LocalBuild,
                Step::LoaderFiles,
                reload,
                enable,
                restart,
                Step::Selftest
            ]
        );
    }

    #[test]
    fn ostree_skips_the_build_when_this_version_is_stored_for_the_kernel() {
        let sys = ostree("install-ostree-done");
        write(&sys, "var/lib/pingu-runtime/modules/aa/pingu_policy.ko", "");
        assert!(!installed_for_running_kernel(&sys, Module::Policy));
        write(&sys, "var/lib/pingu-runtime/modules/aa/VERSION", "0.0.1\n");
        assert!(!installed_for_running_kernel(&sys, Module::Policy));
        write(
            &sys,
            "var/lib/pingu-runtime/modules/aa/VERSION",
            &format!("{}\n", Module::Policy.version()),
        );
        assert!(installed_for_running_kernel(&sys, Module::Policy));
        assert!(!plan(&sys, Module::Policy).contains(&Step::LocalBuild));
    }

    #[test]
    fn ostree_names_what_the_build_lacks() {
        let sys = ostree("install-ostree-missing");
        assert!(local_missing(&sys).is_empty());
        fs::remove_dir_all(sys.root.join("lib/modules")).unwrap();
        fs::remove_file(sys.root.join("bin/gcc")).unwrap();
        let missing = local_missing(&sys);
        assert_eq!(missing, ["kernel-devel", "gcc"]);
        assert_eq!(
            layer_command(&missing),
            "sudo rpm-ostree install kernel-devel-$(uname -r) gcc"
        );
        assert!(!available(&sys));
    }

    #[test]
    fn a_kernel_that_demands_signatures_needs_a_key_before_anything_is_built() {
        let sys = ostree("install-ostree-signing");
        write(
            &sys,
            "sys/kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        );
        assert!(sys.module_signature_required() && signing_key_missing(&sys));
        assert!(!available(&sys));
        let error = local_build(&sys, Module::Policy).unwrap_err();
        assert!(error.contains("no signing key"), "{error}");
        assert!(!sys.root.join("var/lib/pingu-runtime/modules/aa").exists());
    }

    #[test]
    fn the_local_build_stores_the_module_signs_it_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt;
        let sys = ostree("install-ostree-build");
        write(&sys, "sys/module/module/parameters/sig_enforce", "Y\n");
        write(&sys, "var/lib/pingu-runtime/mok/MOK.priv", "key");
        write(&sys, "var/lib/pingu-runtime/mok/MOK.der", "cert");
        write(
            &sys,
            "lib/modules/7.3.5-test/build/scripts/sign-file",
            "#!/bin/sh\nprintf signed >> \"$4\"\n",
        );
        fs::set_permissions(
            sys.root
                .join("lib/modules/7.3.5-test/build/scripts/sign-file"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(available(&sys));
        local_build(&sys, Module::Policy).unwrap();
        let base = sys.root.join("var/lib/pingu-runtime");
        assert_eq!(
            fs::read(base.join("modules/aa/pingu_policy.ko")).unwrap(),
            b"builtsigned"
        );
        assert!(!base.join("build/aa").exists());
        assert!(
            fs::read_to_string(base.join("logs/aa.log"))
                .unwrap()
                .contains("make -C")
        );
        assert!(installed_for_running_kernel(&sys, Module::Policy));
        assert!(!built_without_vm_test(&sys, &Module::Policy.version()));
        write(
            &sys,
            "var/lib/pingu-runtime/logs/aa.log",
            &format!("pingu-module-tool: {UNVALIDATED_MARKER}\n"),
        );
        assert!(built_without_vm_test(&sys, &Module::Policy.version()));
    }

    #[test]
    fn a_failing_build_stores_nothing() {
        let sys = ostree("install-ostree-failed");
        write(&sys, "bin/make", "#!/bin/sh\nexit 2\n");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(sys.root.join("bin/make"), fs::Permissions::from_mode(0o755)).unwrap();
        let error = local_build(&sys, Module::Policy).unwrap_err();
        assert!(error.contains("failed"), "{error}");
        assert!(!sys.root.join("var/lib/pingu-runtime/modules/aa").exists());
    }

    #[test]
    fn the_loader_comes_with_a_copy_of_the_launcher_on_ostree() {
        use std::os::unix::fs::PermissionsExt;
        let mut sys = ostree("install-ostree-loader");
        let exe = sys.root.join("opt/pingu-launcher");
        write(&sys, "opt/pingu-launcher", "launcher bytes");
        sys.exe = exe;
        write_loader(&sys, true).unwrap();
        let base = sys.root.join("var/lib/pingu-runtime");
        assert_eq!(
            fs::read(base.join("pingu-launcher")).unwrap(),
            b"launcher bytes"
        );
        let mode =
            |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&base.join("pingu-launcher")), 0o755);
        assert_eq!(mode(&base.join("pingu-modules-load")), 0o755);
        assert!(
            sys.root
                .join("etc/systemd/system/pingu-modules.service")
                .exists()
        );
        // SteamOS keeps no copy.
        let other = steamos("install-steamos-no-copy");
        write_loader(&other, false).unwrap();
        assert!(
            !other
                .root
                .join("var/lib/pingu-runtime/pingu-launcher")
                .exists()
        );
    }

    #[test]
    fn uninstalling_on_ostree_removes_the_loader_and_everything_below_var() {
        let sys = ostree("uninstall-ostree");
        write(&sys, "etc/systemd/system/pingu-modules.service", "");
        write(&sys, "var/lib/pingu-runtime/modules/aa/pingu_policy.ko", "");
        assert_eq!(
            uninstall_plan(&sys),
            [
                Removal::Systemd(&["disable", "--now", STEAMOS_UNIT]),
                Removal::File("/etc/systemd/system/pingu-modules.service".into()),
                Removal::Systemd(&["daemon-reload"]),
                Removal::Tree(STEAMOS_BASE.into()),
            ]
        );
    }

    #[test]
    fn kvm_is_made_lazy_where_the_cpuid_emulation_runs() {
        let mut sys = machine("install-kvm-lazy");
        // Native faulting or a CPU without SVM: nothing to do.
        assert!(!kvm_lazy_missing(&sys));
        write(
            &sys,
            "proc/cpuinfo",
            "vendor_id\t: AuthenticAMD\nflags\t\t: fpu svm\n",
        );
        assert!(!kvm_lazy_missing(&sys));
        sys.cpuid_faulting = || false;
        assert!(kvm_lazy_missing(&sys));
        let steps = plan(&sys, Module::Policy);
        let lazy = steps
            .iter()
            .position(|step| *step == Step::KvmLazy)
            .unwrap();
        let modprobe = steps
            .iter()
            .position(|step| *step == Step::Modprobe)
            .unwrap();
        assert!(lazy < modprobe, "{steps:?}");

        write_kvm_lazy(&sys).unwrap();
        assert_eq!(sys.read(KVM_LAZY_FILE).as_deref(), Some(KVM_LAZY_TEXT));
        assert!(!kvm_lazy_missing(&sys));
        assert!(!plan(&sys, Module::Policy).contains(&Step::KvmLazy));

        // A loaded module that serves the faulting on demand also counts, whatever the probe says.
        sys.cpuid_faulting = || true;
        fs::remove_file(sys.root.join("etc/modprobe.d/pingu-kvm-lazy.conf")).unwrap();
        write(
            &sys,
            "sys/module/pingu_policy/parameters/cpuid_fault",
            "busy\n",
        );
        assert!(kvm_lazy_missing(&sys));
        write(
            &sys,
            "sys/module/pingu_policy/parameters/cpuid_fault",
            "native\n",
        );
        assert!(!kvm_lazy_missing(&sys));
    }

    #[test]
    fn ostree_makes_kvm_lazy_before_the_loader_starts_the_module() {
        let mut sys = ostree("install-ostree-kvm-lazy");
        write(
            &sys,
            "proc/cpuinfo",
            "vendor_id\t: AuthenticAMD\nflags\t\t: fpu svm\n",
        );
        sys.cpuid_faulting = || false;
        let steps = plan(&sys, Module::Policy);
        assert_eq!(
            steps[..3],
            [Step::LocalBuild, Step::KvmLazy, Step::LoaderFiles]
        );
        write(&sys, "etc/systemd/system/pingu-modules.service", "");
        write(&sys, "etc/modprobe.d/pingu-kvm-lazy.conf", "");
        assert!(uninstall_plan(&sys).contains(&Removal::File(KVM_LAZY_FILE.into())));
    }

    #[test]
    fn an_empty_machine_has_nothing_to_uninstall() {
        let sys = machine("uninstall-empty");
        assert!(uninstall_plan(&sys).is_empty());
        assert!(!installed(&sys));
    }

    #[test]
    fn uninstalling_removes_dkms_versions_sources_and_boot_loading() {
        let sys = machine("uninstall-dkms");
        write(&sys, "var/lib/dkms/pingu-policy/0.3.0/source", "");
        write(&sys, "var/lib/dkms/pingu-policy/0.4.0/source", "");
        write(&sys, "var/lib/dkms/cpuid_fault_emulation/0.1/source", "");
        // DKMS lists the built kernels as symlinks next to the versions.
        std::os::unix::fs::symlink(
            "0.4.0/7.3.5-test/x86_64",
            sys.root
                .join("var/lib/dkms/pingu-policy/kernel-7.3.5-test-x86_64"),
        )
        .unwrap();
        write(&sys, "usr/src/pingu-policy-0.4.0/dkms.conf", "");
        write(&sys, "usr/src/linux-headers-7.3/Makefile", "");
        write(
            &sys,
            "etc/modules-load.d/pingu-policy.conf",
            "pingu_policy\n",
        );
        write(
            &sys,
            "etc/modprobe.d/pingu-policy.conf",
            "options pingu_policy experiment=1\n",
        );
        assert!(installed(&sys));
        let dkms = |package, version: &str| Removal::Dkms {
            package,
            version: version.into(),
        };
        assert_eq!(
            uninstall_plan(&sys),
            [
                dkms("pingu-policy", "0.3.0"),
                dkms("pingu-policy", "0.4.0"),
                Removal::Tree("/usr/src/pingu-policy-0.4.0".into()),
                dkms("cpuid_fault_emulation", "0.1"),
                Removal::File("/etc/modules-load.d/pingu-policy.conf".into()),
                Removal::File(OPTIONS_FILE.into()),
            ]
        );
    }

    #[test]
    fn uninstalling_on_steamos_stops_and_removes_the_loader() {
        let sys = steamos("uninstall-steamos");
        write(&sys, "etc/systemd/system/pingu-modules.service", "");
        write(&sys, "var/lib/pingu-runtime/modules/aa/pingu_policy.ko", "");
        assert_eq!(
            uninstall_plan(&sys),
            [
                Removal::Systemd(&["disable", "--now", STEAMOS_UNIT]),
                Removal::File("/etc/systemd/system/pingu-modules.service".into()),
                Removal::Systemd(&["daemon-reload"]),
                Removal::Tree(STEAMOS_BASE.into()),
            ]
        );
    }

    #[test]
    fn tools_are_found_in_the_sbin_directories_too() {
        let sys = machine("install-tools");
        assert!(!available(&sys));
        write(&sys, "usr/sbin/dkms", "");
        assert!(dkms_available(&sys) && !available(&sys));
        write(&sys, "usr/bin/pkexec", "");
        assert!(available(&sys));
    }
}
