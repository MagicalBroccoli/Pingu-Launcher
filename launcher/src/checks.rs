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
    InstallCpuidModule,
}

impl Action {
    pub fn id(self) -> &'static str {
        match self {
            Self::InstallPolicyModule => "install-policy",
            Self::InstallCpuidModule => "install-cpuid",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        [Self::InstallPolicyModule, Self::InstallCpuidModule]
            .into_iter()
            .find(|action| action.id() == id)
    }

    pub fn module(self) -> Module {
        match self {
            Self::InstallPolicyModule => Module::Policy,
            Self::InstallCpuidModule => Module::CpuidFault,
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
    /// Whether the XCR0 restriction (module, FRED/IBT, runtime) is used.
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

struct Feature {
    title: &'static str,
    flag: &'static str,
    param: &'static str,
    why: &'static str,
}

const FEATURES: [Feature; 3] = [
    Feature {
        title: "UMIP",
        flag: "umip",
        param: "clearcpuid=umip",
        why: "it must be disabled",
    },
    Feature {
        title: "FRED",
        flag: "fred",
        param: "fred=off",
        why: "the pingu-policy module refuses to load while it is active",
    },
    Feature {
        title: "IBT",
        flag: "ibt",
        param: "ibt=off",
        why: "the pingu-policy module refuses to load while it is active",
    },
];

pub fn run_all(sys: &Sys, home: &Home, mode: RuntimeMode, detection: &Detection) -> Report {
    let plan = Plan::new(sys, detection);
    let cpu = CpuInfo::read(sys);
    let params = sys.kernel_params();
    let features = if plan.policy {
        &FEATURES[..]
    } else {
        &FEATURES[..1]
    };

    let mut feature_checks = Vec::new();
    let mut missing_params = Vec::new();
    for feature in features {
        let (check, needed) = check_feature(feature, &cpu, &params);
        feature_checks.push(check);
        missing_params.extend(needed);
    }
    let mut feature_checks = feature_checks.into_iter();

    let mut checks = Vec::new();
    checks.extend(feature_checks.next());
    checks.push(check_cpuid_faulting(sys, &cpu));
    checks.push(check_hook(sys, home));
    if plan.policy {
        checks.extend(feature_checks);
        if !missing_params.is_empty() {
            checks.push(kernel_command_line(sys, &params, &missing_params));
        }
        let kernel_blocked = FEATURES.iter().skip(1).any(|feature| cpu.has(feature.flag));
        checks.push(check_policy_module(sys, kernel_blocked));
    } else if !missing_params.is_empty() {
        checks.insert(1, kernel_command_line(sys, &params, &missing_params));
    }
    let runtime = plan.policy.then(|| runtime::detect(sys, home, mode));
    Report {
        plan,
        checks,
        runtime,
        installed: install::installed(sys),
    }
}

fn kernel_command_line(sys: &Sys, params: &[String], missing: &[&str]) -> Check {
    let added = missing.join(" ");
    Check::problem(
        "Kernel command line",
        format!("Add {added} to the kernel command line and reboot."),
        bootloader_steps(detect_bootloader(sys, params), &added),
    )
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

fn check_feature(
    feature: &Feature,
    cpu: &CpuInfo,
    params: &[String],
) -> (Check, Option<&'static str>) {
    let configured = has_param(params, feature.param);
    if !cpu.has(feature.flag) {
        let note = if configured {
            format!("disabled by {}", feature.param)
        } else {
            "not reported by this CPU".into()
        };
        return (
            Check::ok(
                feature.title,
                format!("{} is not active ({note}).", feature.title),
            ),
            None,
        );
    }
    if configured {
        let detail = format!(
            "{0} is still active although {1} is on the kernel command line. Reboot after changing the boot configuration, or check that the bootloader passes the parameter.",
            feature.title, feature.param
        );
        return (Check::problem(feature.title, detail, String::new()), None);
    }
    let detail = format!("{} is active, but {}.", feature.title, feature.why);
    (
        Check::problem(feature.title, detail, String::new()),
        Some(feature.param),
    )
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

pub fn bootloader_steps(bootloader: Bootloader, added: &str) -> String {
    match bootloader {
        Bootloader::Grub => format!(
            "Append \"{added}\" to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then run:\n  sudo grub-mkconfig -o /boot/grub/grub.cfg\nReboot afterwards."
        ),
        Bootloader::SdbootManage => format!(
            "Append \"{added}\" to LINUX_OPTIONS in /etc/sdboot-manage.conf, then run:\n  sudo sdboot-manage gen\nReboot afterwards."
        ),
        Bootloader::KernelCmdline => format!(
            "Append \"{added}\" to /etc/kernel/cmdline, then regenerate your boot entries (on CachyOS: sudo reinstall-kernels).\nReboot afterwards."
        ),
        Bootloader::LoaderEntries => format!(
            "Append \"{added}\" to the options line of your entry in /boot/loader/entries/ (or /efi/loader/entries/).\nReboot afterwards."
        ),
        Bootloader::Unknown => {
            format!("Add \"{added}\" to your bootloader's kernel command line and reboot.")
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

fn check_cpuid_faulting(sys: &Sys, cpu: &CpuInfo) -> Check {
    const TITLE: &str = "CPUID faulting";
    const MODULE: &str = "cpuid_fault_emulation";
    let loaded = sys.module_loaded(MODULE);
    if (sys.cpuid_faulting)() {
        let detail = if loaded {
            "Provided by the cpuid_fault_emulation module."
        } else {
            "Supported natively by this CPU, so the cpuid_fault_emulation module is not needed."
        };
        return Check::ok(TITLE, detail);
    }
    if loaded {
        return Check::problem(
            TITLE,
            "The cpuid_fault_emulation module is loaded but the kernel still reports no CPUID faulting.",
            "Check the kernel log for the reason: sudo dmesg | grep -i cpuid",
        );
    }
    if cpu.vendor != "AuthenticAMD" || !cpu.has("svm") {
        return Check::problem(
            TITLE,
            "This CPU cannot fault CPUID, and the cpuid_fault_emulation module needs an AMD CPU with SVM.",
            "If this is an AMD CPU, enable SVM (AMD-V) in the firmware setup. Otherwise CPUID faulting is not available on this machine.",
        );
    }
    if let Some((detail, fix)) = steamos_problem(sys, Module::CpuidFault) {
        return offer(
            sys,
            Check::problem(TITLE, detail, fix),
            Action::InstallCpuidModule,
            false,
        );
    }
    if sys.module_installed(MODULE) {
        return offer(
            sys,
            Check::problem(
                TITLE,
                format!(
                    "This CPU cannot fault CPUID natively. The cpuid_fault_emulation module is installed but not loaded. {SAVE_WORK}"
                ),
                format!(
                    "sudo modprobe {MODULE}\n\nTo load it on every boot:\n  echo {MODULE} | sudo tee /etc/modules-load.d/{MODULE}.conf"
                ),
            ),
            Action::InstallCpuidModule,
            false,
        );
    }
    let version = assets::cpuid_module_version();
    let exe = shell_quote(&sys.exe);
    let source = format!("/usr/src/{MODULE}-{version}");
    let missing = Check::problem(
        TITLE,
        format!(
            "This CPU cannot fault CPUID natively. The cpuid_fault_emulation module is not installed. {SAVE_WORK}"
        ),
        format!(
            "sudo {exe} module export-cpuid {source}\nsudo dkms add -m {MODULE} -v {version}\nsudo dkms install -m {MODULE} -v {version} -k \"$(uname -r)\"\nsudo modprobe {MODULE}\n\nTo load it on every boot:\n  echo {MODULE} | sudo tee /etc/modules-load.d/{MODULE}.conf"
        ),
    );
    offer(sys, missing, Action::InstallCpuidModule, false)
}

const SAVE_WORK: &str =
    "Save your work first: loading it runs the whole system as a guest of a thin hypervisor.";

const DKMS_LABEL: &str = "Install DKMS module";
const PREBUILT_LABEL: &str = "Install prebuilt module";

/// Adds the install button when the tools are there, or says what is missing.
fn offer(sys: &Sys, mut check: Check, action: Action, blocked: bool) -> Check {
    if blocked {
        return check;
    }
    if sys.is_steamos() {
        // SteamOS has no DKMS; the launcher carries modules built for Valve's kernels.
        if install::prebuilt_available(sys, action.module()) && install::available(sys) {
            check.action = Some(action);
            check.action_label = PREBUILT_LABEL;
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
            check.warning = install::vm_warning(problem);
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
    if module == Module::CpuidFault && !sys.exists(&format!("{STEAMOS_MODULES}/enable-cpuid-fault"))
    {
        return Some((
            "The cpuid_fault_emulation module is installed but not enabled.".into(),
            command,
        ));
    }
    Some((
        format!("The {name} module is installed for this SteamOS kernel but not loaded."),
        "sudo systemctl restart pingu-modules.service\njournalctl -b -u pingu-modules.service"
            .into(),
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
    if sys.is_steamos() {
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

fn check_policy_module(sys: &Sys, kernel_blocked: bool) -> Check {
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
                        kernel_blocked,
                    )
                }
            }
            Some(loaded) => {
                let mut check = Check::ok(TITLE, format!("{MODULE} {loaded} is loaded and ready."));
                if install::built_without_vm_test(sys, &loaded) {
                    check.warning = format!(
                        "DKMS built this module without its VM test, because QEMU or KVM was missing then. That test boots the kernel with the module in a throwaway virtual machine, where a faulty kernel patch only crashes the VM. Install QEMU and rebuild with `sudo dkms install -m pingu-policy -v {loaded} -k {} --force` to get it.",
                        sys.kernel_release()
                    );
                }
                check
            }
            None => Check::ok(TITLE, format!("{MODULE} is loaded and ready.")),
        };
    }

    let blocked = if kernel_blocked {
        "Fix the kernel command line first; the module refuses to load while FRED or IBT is active.\n\n"
    } else {
        ""
    };
    if let Some((detail, fix)) = steamos_problem(sys, Module::Policy) {
        return offer(
            sys,
            Check::problem(TITLE, detail, format!("{blocked}{fix}")),
            Action::InstallPolicyModule,
            kernel_blocked,
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
                format!("{notes}{blocked}sudo modprobe {MODULE}\n{persist}"),
            ),
            Action::InstallPolicyModule,
            kernel_blocked,
        );
    }
    let mut steps = String::new();
    let _ = write!(
        steps,
        "{notes}{blocked}sudo {exe} module export {source}\nsudo dkms add -m pingu-policy -v {version}\nsudo dkms install -m pingu-policy -v {version} -k \"$(uname -r)\"\nsudo modprobe {MODULE}\n{persist}"
    );
    offer(
        sys,
        Check::problem(
            TITLE,
            "The pingu_policy module is not installed for this kernel.",
            steps,
        ),
        Action::InstallPolicyModule,
        kernel_blocked,
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
        if !check.warning.is_empty() {
            let _ = writeln!(text, "         Warning: {}", check.warning);
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
