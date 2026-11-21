use std::fmt::Write as _;

use crate::assets;
use crate::home::Home;
use crate::hook;
use crate::install::{self, Module};
use crate::mode::{Detection, GameMode};
use crate::runtime::{self, RuntimeInfo, RuntimeMode};
use crate::sys::{CpuInfo, Sys, shell_quote};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Problem,
}

/// Work the window can do for the user, behind a button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    InstallPolicyModule,
}

impl Action {
    pub fn id(self) -> &'static str {
        match self {
            Self::InstallPolicyModule => "install-policy",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        [Self::InstallPolicyModule]
            .into_iter()
            .find(|action| action.id() == id)
    }

    pub fn module(self) -> Module {
        match self {
            Self::InstallPolicyModule => Module::Policy,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub title: &'static str,
    pub status: Status,
    pub detail: String,
    /// Instructions the user must follow; empty when there is nothing to do.
    pub fix: String,
    /// What the window can do instead of the user following `fix`.
    pub action: Option<Action>,
    /// The button's text; empty without an action.
    pub action_label: &'static str,
    /// A risk to point out that does not make the check fail; empty when there is none.
    pub warning: String,
}

impl Check {
    pub fn ok(title: &'static str, detail: impl Into<String>) -> Self {
        Self {
            title,
            status: Status::Ok,
            detail: detail.into(),
            fix: String::new(),
            action: None,
            action_label: "",
            warning: String::new(),
        }
    }

    pub fn problem(title: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            title,
            status: Status::Problem,
            detail: detail.into(),
            fix: fix.into(),
            action: None,
            action_label: "",
            warning: String::new(),
        }
    }
}

/// What this launch needs, decided by the game mode and the kernel's native XCR0.
#[derive(Clone, Debug)]
pub struct Plan {
    pub mode: GameMode,
    pub native_xcr0: Option<u64>,
    /// Whether the XCR0 restriction (module, runtime) is used.
    pub policy: bool,
    /// pingu-hook's Artifact protocol (PINGU_ARTIFACT_PROTOCOL), which needs XCR0 to be 7 at run time.
    pub artifact_protocol: bool,
    policy_disabled: bool,
}

impl Plan {
    pub fn new(sys: &Sys, detection: &Detection) -> Self {
        let native_xcr0 = (sys.native_xcr0)();
        let policy_disabled = sys.env("AVX2_POLICY") == Some("0");
        let artifact = detection.mode == GameMode::Artifact;
        let policy = artifact && native_xcr0 != Some(7) && !policy_disabled;
        Self {
            mode: detection.mode,
            native_xcr0,
            policy,
            artifact_protocol: artifact && (policy || native_xcr0 == Some(7)),
            policy_disabled,
        }
    }

    pub fn describe(&self) -> String {
        let mut text = self.mode.label().to_string();
        if self.mode == GameMode::Artifact {
            let xcr0 = self
                .native_xcr0
                .map_or_else(|| "unknown".to_string(), |value| format!("{value:#x}"));
            let verdict = if self.policy_disabled {
                "the restriction is disabled by AVX2_POLICY=0"
            } else if self.policy {
                "so pingu-policy is required"
            } else {
                "so pingu-policy is not needed"
            };
            let _ = write!(text, "\nNative XCR0 is {xcr0}, {verdict}.");
            if self.artifact_protocol {
                text.push_str("\npingu-hook's Artifact support active.");
            }
        }
        text
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    pub plan: Plan,
    pub checks: Vec<Check>,
    /// Only present when the XCR0 restriction is used.
    pub runtime: Option<RuntimeInfo>,
    /// Whether modules or their boot loading are installed, which the window can remove.
    pub installed: bool,
}

impl Report {
    fn runtime_usable(&self) -> bool {
        self.runtime.as_ref().is_none_or(RuntimeInfo::is_usable)
    }

    pub fn ok(&self) -> bool {
        self.checks.iter().all(|check| check.status == Status::Ok) && self.runtime_usable()
    }

    pub fn problem_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == Status::Problem)
            .count()
            + usize::from(!self.runtime_usable())
    }
}

/// The deprecated module that pingu_policy replaced.
const LEGACY_CPUID_MODULE: &str = "cpuid_fault_emulation";

/// What the loaded pingu_policy reports about its features; an older module has no such parameters.
struct PolicyState {
    loaded: bool,
    umip_fixup: bool,
    cpuid_fault: Option<String>,
}

impl PolicyState {
    fn read(sys: &Sys) -> Self {
        let parameter = |name: &str| {
            sys.read(&format!("/sys/module/pingu_policy/parameters/{name}"))
                .map(|text| text.trim().to_string())
        };
        Self {
            loaded: sys.module_loaded("pingu_policy"),
            umip_fixup: parameter("umip_fixup").as_deref() == Some("Y"),
            cpuid_fault: parameter("cpuid_fault"),
        }
    }
}

pub fn run_all(sys: &Sys, home: &Home, mode: RuntimeMode, detection: &Detection) -> Report {
    let plan = Plan::new(sys, detection);
    let cpu = CpuInfo::read(sys);
    let params = sys.kernel_params();

    let mut checks = vec![
        check_umip(sys, &cpu, &params),
        check_cpuid_faulting(sys, &cpu),
        check_hook(sys, home),
    ];
    // The module also serves UMIP and the CPUID faulting emulation, whatever the game mode.
    let emulation = !(sys.cpuid_faulting)() && can_emulate_cpuid_faulting(&cpu);
    if plan.policy || cpu.has("umip") || emulation {
        checks.push(check_policy_module(sys, emulation));
    }
    checks.extend(check_deprecated(sys, &params, plan.policy || emulation));
    let runtime = plan.policy.then(|| runtime::detect(sys, home, mode));
    Report {
        plan,
        checks,
        runtime,
        installed: install::installed(sys),
    }
}

fn check_umip(sys: &Sys, cpu: &CpuInfo, params: &[String]) -> Check {
    const TITLE: &str = "UMIP";
    if !cpu.has("umip") {
        let note = if has_param(params, "clearcpuid=umip") {
            "disabled by clearcpuid=umip"
        } else {
            "not reported by this CPU"
        };
        return Check::ok(TITLE, format!("UMIP is not active ({note})."));
    }
    let policy = PolicyState::read(sys);
    if policy.umip_fixup {
        return Check::ok(
            TITLE,
            "UMIP is active; pingu_policy makes SGDT and SIDT report the limits of a system without it.",
        );
    }
    if has_param(params, "clearcpuid=umip") {
        return Check::problem(
            TITLE,
            "UMIP is still active although clearcpuid=umip is on the kernel command line.",
            "Reboot after changing the boot configuration, or check that the bootloader passes the parameter. With the current pingu_policy the parameter is no longer needed.",
        );
    }
    if policy.loaded {
        return Check::problem(
            TITLE,
            "UMIP is active and the loaded pingu_policy module does not handle it (an older version, or its hook failed).",
            "Install the current pingu-policy (see its card) and reboot. If it is current: sudo dmesg | grep -i xcr0_probe",
        );
    }
    Check::problem(
        TITLE,
        "UMIP is active, and the pingu_policy module handles it once it is loaded.",
        "Install and load pingu_policy (see its card).",
    )
}

fn numbered(items: &[String]) -> String {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| format!("{}. {item}", index + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Deprecated settings still work, so this card never fails; it tells how to move to pingu_policy.
/// `module_needed`: the module is wanted for more than UMIP, so the old boot parameters can go.
fn check_deprecated(sys: &Sys, params: &[String], module_needed: bool) -> Option<Check> {
    let legacy = install::legacy_cpuid(sys);
    // With UMIP disabled by the user and nothing else asking for pingu_policy, the parameter is fine.
    let parameters: Vec<&str> = if module_needed || legacy.found() {
        ["clearcpuid=umip", "fred=off", "ibt=off"]
            .into_iter()
            .filter(|param| has_param(params, param))
            .collect()
    } else {
        Vec::new()
    };
    if !legacy.found() && parameters.is_empty() {
        return None;
    }
    let mut found = Vec::new();
    let mut steps = Vec::new();
    // Without the current module, dropping clearcpuid=umip would leave UMIP active and unhandled.
    let policy = PolicyState::read(sys);
    let umip_needs_module = parameters.contains(&"clearcpuid=umip") && !policy.umip_fixup;
    if legacy.found() {
        found.push("the cpuid_fault_emulation module".to_string());
    }
    if legacy.found() || umip_needs_module {
        let exe = shell_quote(&sys.exe);
        let mut step = format!(
            "Install the current pingu-policy first (its card has the button, or run `sudo {exe} module install`). It handles UMIP and emulates CPUID faulting itself."
        );
        if legacy.found() {
            step.push_str(" The installation removes the cpuid_fault_emulation package and its loading at boot.");
        }
        if legacy.loaded {
            step.push_str(" The loaded module keeps working until you reboot; unload it only while no game runs (sudo modprobe -r cpuid_fault_emulation).");
        }
        steps.push(step);
    }
    if !parameters.is_empty() {
        let list = parameters.join(" ");
        found.push(format!("{list} on the kernel command line"));
        let reason = if parameters.contains(&"clearcpuid=umip") {
            "pingu_policy handles UMIP, and works with FRED and IBT"
        } else {
            "pingu_policy works with FRED and IBT"
        };
        let how = bootloader_remove_steps(detect_bootloader(sys, params), &list);
        steps.push(format!(
            "Remove {list} from the kernel command line ({reason}). {}",
            how.replace('\n', "\n   ")
        ));
    }
    steps.push("Reboot, then press Check again.".to_string());
    Some(Check {
        warning: format!(
            "These settings of the previous setup are deprecated and still work. To migrate:\n{}",
            numbered(&steps)
        ),
        ..Check::ok(
            "Deprecated setup",
            format!("Found {}.", found.join(" and ")),
        )
    })
}

/// Whether `param` is on the kernel command line; `clearcpuid=` takes a comma separated list.
pub fn has_param(params: &[String], param: &str) -> bool {
    match param.split_once('=') {
        Some(("clearcpuid", wanted)) => params
            .iter()
            .filter_map(|candidate| candidate.strip_prefix("clearcpuid="))
            .any(|list| list.split(',').any(|item| item == wanted)),
        _ => params.iter().any(|candidate| candidate == param),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bootloader {
    Grub,
    SdbootManage,
    KernelCmdline,
    LoaderEntries,
    Unknown,
}

pub fn detect_bootloader(sys: &Sys, params: &[String]) -> Bootloader {
    let grub = sys.exists("/etc/default/grub");
    if grub && params.iter().any(|param| param.starts_with("BOOT_IMAGE=")) {
        Bootloader::Grub
    } else if sys.exists("/etc/sdboot-manage.conf") {
        Bootloader::SdbootManage
    } else if sys.exists("/etc/kernel/cmdline") {
        Bootloader::KernelCmdline
    } else if sys.exists("/boot/loader/entries") || sys.exists("/efi/loader/entries") {
        Bootloader::LoaderEntries
    } else if grub {
        Bootloader::Grub
    } else {
        Bootloader::Unknown
    }
}

pub fn bootloader_remove_steps(bootloader: Bootloader, removed: &str) -> String {
    match bootloader {
        Bootloader::Grub => format!(
            "Delete \"{removed}\" from GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then run:\n  sudo grub-mkconfig -o /boot/grub/grub.cfg"
        ),
        Bootloader::SdbootManage => format!(
            "Delete \"{removed}\" from LINUX_OPTIONS in /etc/sdboot-manage.conf, then run:\n  sudo sdboot-manage gen"
        ),
        Bootloader::KernelCmdline => format!(
            "Delete \"{removed}\" from /etc/kernel/cmdline, then regenerate your boot entries (on CachyOS: sudo reinstall-kernels)."
        ),
        Bootloader::LoaderEntries => format!(
            "Delete \"{removed}\" from the options line of your entry in /boot/loader/entries/ (or /efi/loader/entries/)."
        ),
        Bootloader::Unknown => {
            format!("Delete \"{removed}\" from your bootloader's kernel command line.")
        }
    }
}

fn check_hook(sys: &Sys, home: &Home) -> Check {
    match hook::resolve(sys, home) {
        Ok(library) => {
            let variant = library
                .variant
                .map(|name| format!(" (variant {name})"))
                .unwrap_or_default();
            let mut detail = format!("Using {}{variant}.", library.path.display());
            if let Some(warning) = library.warning {
                detail.push_str(" Warning: ");
                detail.push_str(&warning);
                detail.push('.');
            }
            Check::ok("pingu-hook", detail)
        }
        Err(missing) => Check::problem("pingu-hook", missing.detail, missing.fix),
    }
}

/// Whether the CPU could run the SVM based CPUID faulting emulation of pingu_policy.
fn can_emulate_cpuid_faulting(cpu: &CpuInfo) -> bool {
    cpu.vendor == "AuthenticAMD" && cpu.has("svm")
}

/// Why the on-demand emulation cannot start now, and what to do about it.
fn busy_fix(sys: &Sys) -> String {
    let exe = shell_quote(&sys.exe);
    let eager = sys
        .read("/sys/module/kvm/parameters/enable_virt_at_load")
        .is_some_and(|text| text.trim() == "Y");
    if !sys.exists(install::KVM_LAZY_FILE) {
        format!(
            "kvm holds SVM all the time. Run `sudo {exe} module install`: it makes kvm claim SVM only while a virtual machine runs. Virtual machines have to be stopped for that."
        )
    } else if eager {
        format!(
            "{} is not active yet. Reboot, or stop all virtual machines and run:\n  sudo modprobe -r kvm_amd kvm && sudo modprobe kvm_amd",
            install::KVM_LAZY_FILE
        )
    } else {
        "Stop the virtual machine and launch the game again. The emulation starts by itself once SVM is free.".into()
    }
}

fn check_cpuid_faulting(sys: &Sys, cpu: &CpuInfo) -> Check {
    const TITLE: &str = "CPUID faulting";
    let policy = PolicyState::read(sys);
    if policy.cpuid_fault.as_deref() == Some("busy") {
        return Check::problem(
            TITLE,
            "pingu_policy emulates CPUID faulting when a game asks for it, but SVM is in use right now: a KVM virtual machine is running, or kvm holds SVM all the time.",
            busy_fix(sys),
        );
    }
    if (sys.cpuid_faulting)() {
        let detail = if sys.module_loaded(LEGACY_CPUID_MODULE) {
            "Provided by the deprecated cpuid_fault_emulation module."
        } else if policy.cpuid_fault.as_deref() == Some("emulated") {
            "Emulated by the pingu_policy module; its hypervisor is running now."
        } else if policy.cpuid_fault.as_deref() == Some("on_demand") {
            "Emulated on demand by the pingu_policy module: its hypervisor runs while a game uses CPUID faulting, and KVM virtual machines cannot start then."
        } else {
            "Supported natively by this CPU."
        };
        return Check::ok(TITLE, detail);
    }
    if policy.loaded && policy.cpuid_fault.is_none() {
        return Check::problem(
            TITLE,
            "The loaded pingu_policy module predates its CPUID faulting emulation.",
            "Install the current pingu-policy (see its card) and reboot.",
        );
    }
    if policy.loaded {
        let reason = if !can_emulate_cpuid_faulting(cpu) {
            "The CPU has no usable SVM: only AMD CPUs with SVM (AMD-V enabled in the firmware setup) can be emulated."
        } else {
            "The module did not offer the emulation: SVM or its NRIP save feature is disabled, emulate_cpuid_fault is 0, or the kernel functions it hooks were not found."
        };
        return Check::problem(
            TITLE,
            format!(
                "This CPU cannot fault CPUID natively and pingu_policy could not emulate it. {reason}"
            ),
            "The reason is in the kernel log: sudo dmesg | grep -iE 'xcr0_probe|cpuid fault'",
        );
    }
    if !can_emulate_cpuid_faulting(cpu) {
        return Check::problem(
            TITLE,
            "This CPU cannot fault CPUID, and the pingu_policy emulation needs an AMD CPU with SVM.",
            "If this is an AMD CPU, enable SVM (AMD-V) in the firmware setup. Otherwise CPUID faulting is not available on this machine.",
        );
    }
    Check::problem(
        TITLE,
        "This CPU cannot fault CPUID natively. The pingu_policy module emulates it.",
        "Install and load pingu_policy (see its card).",
    )
}

const SAVE_WORK: &str = "Save your work first: on this CPU the module runs the whole system as a guest of a thin hypervisor while a game uses CPUID faulting.";

const DKMS_LABEL: &str = "Install DKMS module";
const PREBUILT_LABEL: &str = "Install prebuilt module";
const LOCAL_LABEL: &str = "Build and install module";

/// Adds the install button when the tools are there, or says what is missing.
fn offer(sys: &Sys, mut check: Check, action: Action) -> Check {
    if sys.is_steamos() {
        // SteamOS has no DKMS; the launcher carries modules built for Valve's kernels.
        if install::prebuilt_available(sys, action.module()) && install::available(sys) {
            check.action = Some(action);
            check.action_label = PREBUILT_LABEL;
        }
        return check;
    }
    if sys.is_ostree() {
        // The problem text of an ostree image already names what is missing.
        if install::available(sys) {
            check.action = Some(action);
            check.action_label = LOCAL_LABEL;
            if install::plan(sys, action.module()).contains(&install::Step::LocalBuild)
                && let Some(problem) = install::vm_test_problem(sys)
            {
                check.warning = install::vm_warning(sys, problem);
            }
        }
        return check;
    }
    if install::available(sys) {
        check.action = Some(action);
        check.action_label = DKMS_LABEL;
        if action == Action::InstallPolicyModule
            && install::plan(sys, action.module()).contains(&install::Step::DkmsInstall)
            && let Some(problem) = install::vm_test_problem(sys)
        {
            check.warning = install::vm_warning(sys, problem);
        }
    } else if !install::dkms_available(sys) {
        check.fix.push_str(
            "\n\nDKMS is not installed. Install the dkms package first; the package names are in pingu-policy/README.md.",
        );
    }
    check
}

/// SteamOS has a read-only root and no DKMS: the launcher carries modules built for Valve's kernels and
/// installs them under `/var/lib/pingu-runtime` (it survives updates), where `pingu-modules.service`
/// loads the ones that match the running kernel build.
const STEAMOS_MODULES: &str = "/var/lib/pingu-runtime";

/// The problem and its fix for a module that is not loaded on SteamOS; None on other systems.
fn steamos_problem(sys: &Sys, module: Module) -> Option<(String, String)> {
    if !sys.is_steamos() {
        return None;
    }
    let name = module.name();
    let release = sys.kernel_release();
    // The same release string is a different build in each SteamOS channel, so the build ID decides.
    let build_id = sys.kernel_build_id().unwrap_or_default();
    if !install::prebuilt_available(sys, module) {
        return Some((
            format!("This launcher has no prebuilt {name} module for SteamOS kernel {release} (build ID {build_id}), and SteamOS has no DKMS."),
            "Use a pingu-launcher release that lists this build ID.\nA maintainer adds it with `make steamos-modules` and rebuilds the launcher with `make launcher-dist`.".into(),
        ));
    }
    let exe = shell_quote(&sys.exe);
    let command = format!("sudo {exe} module {}", module.subcommand());
    if !sys.exists(&format!("{STEAMOS_MODULES}/modules/{build_id}/{name}.ko")) {
        return Some((
            format!("The prebuilt {name} module for this SteamOS kernel is not installed."),
            command,
        ));
    }
    Some((
        format!("The {name} module is installed for this SteamOS kernel but not loaded."),
        "sudo systemctl restart pingu-modules.service\njournalctl -b -u pingu-modules.service"
            .into(),
    ))
}

/// The problem and its fix for a module that is not loaded on an ostree image (Bazzite, Silverblue); None on other systems.
/// /usr is read-only there, so DKMS cannot install: the module is built here and `pingu-modules.service` loads it.
fn ostree_problem(sys: &Sys, module: Module) -> Option<(String, String)> {
    if !sys.is_ostree() {
        return None;
    }
    let name = module.name();
    let release = sys.kernel_release();
    let missing = install::local_missing(sys);
    if !missing.is_empty() {
        return Some((
            format!(
                "This system has a read-only /usr, so {name} is built here for kernel {release} instead of through DKMS. The build needs {}, which {} not installed.",
                missing.join(", "),
                if missing.len() == 1 { "is" } else { "are" }
            ),
            format!(
                "{}\nsystemctl reboot\nThen press Check again. The kernel headers must be those of the running kernel ({release}).",
                install::layer_command(&missing)
            ),
        ));
    }
    if install::signing_key_missing(sys) {
        return Some((
            format!(
                "This kernel only loads signed modules (Secure Boot), and {name} needs a signing key that the firmware trusts."
            ),
            install::signing_steps(),
        ));
    }
    let exe = shell_quote(&sys.exe);
    if !install::installed_for_running_kernel(sys, module) {
        return Some((
            format!("The {name} module is not built for kernel {release} yet."),
            format!("sudo {exe} module {}", module.subcommand()),
        ));
    }
    Some((
        format!("The {name} module is built for this kernel but not loaded."),
        format!(
            "sudo systemctl restart pingu-modules.service\njournalctl -b -u pingu-modules.service -u {}\nIf the log says the key was rejected, enroll the signing key (see the steps above) and reboot.",
            install::REBUILD_UNIT
        ),
    ))
}

const MODULE_OPTIONS_FILE: &str = "/etc/modprobe.d/pingu-policy.conf";

fn module_ready(sys: &Sys, module: &str) -> bool {
    sys.read(&format!("/sys/module/{module}/parameters/ready"))
        .as_deref()
        .map(str::trim)
        == Some("Y")
}

/// How to replace a loaded module by the version this launcher ships. The loaded one cannot be unloaded, so the new one takes over at the next boot.
fn module_update_steps(sys: &Sys, loaded: Option<&str>, version: &str) -> String {
    const MODULE: &str = "pingu_policy";
    let exe = shell_quote(&sys.exe);
    let source = format!("/usr/src/pingu-policy-{version}");
    let mut text = String::new();
    if install::uses_loader(sys) {
        let _ = writeln!(text, "sudo {exe} module install");
    } else {
        if sys.exists(MODULE_OPTIONS_FILE) {
            let _ = writeln!(
                text,
                "sudo rm {MODULE_OPTIONS_FILE}   (options of version 0.3.0, which the new version refuses)"
            );
        }
        if let Some(loaded) = loaded {
            let _ = writeln!(text, "sudo dkms remove pingu-policy/{loaded} --all");
        }
        let _ = write!(
            text,
            "sudo {exe} module export {source}\nsudo dkms add -m pingu-policy -v {version}\nsudo dkms install -m pingu-policy -v {version} -k \"$(uname -r)\"\n"
        );
    }
    let _ = write!(
        text,
        "Stop at the first failing step. Then reboot to load version {version}. Never unload {MODULE}: the loaded one keeps running until then."
    );
    text
}

/// The card of the module; `emulation` is true when loading it also starts the CPUID faulting hypervisor.
fn check_policy_module(sys: &Sys, emulation: bool) -> Check {
    let mut check = policy_module_state(sys);
    if emulation && check.status == Status::Problem && !sys.module_loaded("pingu_policy") {
        if !check.warning.is_empty() {
            check.warning.push(' ');
        }
        check.warning.push_str(SAVE_WORK);
    }
    check
}

fn policy_module_state(sys: &Sys) -> Check {
    const TITLE: &str = "pingu-policy";
    const MODULE: &str = "pingu_policy";
    let version = assets::module_version();
    let exe = shell_quote(&sys.exe);
    let source = format!("/usr/src/pingu-policy-{version}");

    if sys.module_loaded(MODULE) {
        if !module_ready(sys, MODULE) {
            return Check::problem(
                TITLE,
                format!(
                    "The {MODULE} module is loaded but not ready. It declines to patch the kernel when a requirement is not met."
                ),
                "Read the reason in the kernel log: sudo dmesg | grep -i xcr0\nNever force-unload the module; reboot after fixing the cause.",
            );
        }
        let loaded = sys
            .read(&format!("/sys/module/{MODULE}/version"))
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty());
        return match loaded {
            Some(loaded) if loaded != version => {
                if install::installed_for_running_kernel(sys, Module::Policy) {
                    Check::problem(
                        TITLE,
                        format!(
                            "{MODULE} {loaded} is loaded and ready. Version {version} is installed for this kernel and replaces it at the next reboot."
                        ),
                        "Reboot to load it.",
                    )
                } else {
                    offer(
                        sys,
                        Check::problem(
                            TITLE,
                            format!(
                                "{MODULE} {loaded} is loaded and ready, but this launcher ships version {version}."
                            ),
                            module_update_steps(sys, Some(&loaded), &version),
                        ),
                        Action::InstallPolicyModule,
                    )
                }
            }
            Some(loaded) => {
                let mut check = Check::ok(TITLE, format!("{MODULE} {loaded} is loaded and ready."));
                if install::built_without_vm_test(sys, &loaded) {
                    check.warning = if sys.is_ostree() {
                        format!(
                            "The module was built without its VM test, because QEMU or KVM was missing then. That test boots the kernel with the module in a throwaway virtual machine, where a faulty kernel patch only crashes the VM. Layer QEMU (sudo rpm-ostree install qemu-system-x86-core), reboot, then run `sudo rm -r {}` and `sudo {exe} module install` to get it.",
                            install::local_module_dir(sys).unwrap_or_default()
                        )
                    } else {
                        format!(
                            "DKMS built this module without its VM test, because QEMU or KVM was missing then. That test boots the kernel with the module in a throwaway virtual machine, where a faulty kernel patch only crashes the VM. Install QEMU and rebuild with `sudo dkms install -m pingu-policy -v {loaded} -k {} --force` to get it.",
                            sys.kernel_release()
                        )
                    };
                }
                check
            }
            None => Check::ok(TITLE, format!("{MODULE} is loaded and ready.")),
        };
    }

    if let Some((detail, fix)) =
        steamos_problem(sys, Module::Policy).or_else(|| ostree_problem(sys, Module::Policy))
    {
        return offer(
            sys,
            Check::problem(TITLE, detail, fix),
            Action::InstallPolicyModule,
        );
    }
    let mut notes = String::new();
    // Versions before 0.4.0 needed options that the module no longer accepts.
    if sys.exists(MODULE_OPTIONS_FILE) {
        let _ = write!(
            notes,
            "{MODULE_OPTIONS_FILE} sets options that {MODULE} no longer takes, so modprobe refuses to load it. Remove it first:\n  sudo rm {MODULE_OPTIONS_FILE}\n\n"
        );
    }
    let persist = format!(
        "\nTo load it on every boot, after `{exe} selftest` passes:\n  sudo install -Dm644 {source}/modules-load.d/pingu-policy.conf /etc/modules-load.d/pingu-policy.conf"
    );
    if sys.module_installed(MODULE) {
        return offer(
            sys,
            Check::problem(
                TITLE,
                "The pingu_policy module is installed but not loaded.",
                format!("{notes}sudo modprobe {MODULE}\n{persist}"),
            ),
            Action::InstallPolicyModule,
        );
    }
    let mut steps = String::new();
    let _ = write!(
        steps,
        "{notes}sudo {exe} module export {source}\nsudo dkms add -m pingu-policy -v {version}\nsudo dkms install -m pingu-policy -v {version} -k \"$(uname -r)\"\nsudo modprobe {MODULE}\n{persist}"
    );
    offer(
        sys,
        Check::problem(
            TITLE,
            "The pingu_policy module is not installed for this kernel.",
            steps,
        ),
        Action::InstallPolicyModule,
    )
}

/// Plain-text rendering used by `--check` and when no window can be opened.
pub fn render_text(report: &Report) -> String {
    let mut text = format!("{}\n\n", report.plan.describe());
    let runtime = report.runtime.as_ref().map(RuntimeInfo::as_check);
    for check in report.checks.iter().chain(runtime.iter()) {
        let mark = if check.status == Status::Ok {
            " ok "
        } else {
            "FAIL"
        };
        let _ = writeln!(text, "[{mark}] {}: {}", check.title, check.detail);
        for (index, line) in check.warning.lines().enumerate() {
            let label = if index == 0 { "Warning: " } else { "         " };
            let _ = writeln!(text, "         {label}{line}");
        }
        if !check.fix.is_empty() {
            for line in check.fix.lines() {
                let _ = writeln!(text, "         {line}");
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn clearcpuid_matches_inside_lists() {
        assert!(has_param(
            &params(&["quiet", "clearcpuid=umip"]),
            "clearcpuid=umip"
        ));
        assert!(has_param(
            &params(&["clearcpuid=avx512f,umip"]),
            "clearcpuid=umip"
        ));
        assert!(!has_param(
            &params(&["clearcpuid=avx512f"]),
            "clearcpuid=umip"
        ));
        assert!(has_param(&params(&["fred=off"]), "fred=off"));
        assert!(!has_param(&params(&["fred=on"]), "fred=off"));
    }
}
