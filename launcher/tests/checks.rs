mod common;

use std::fs;
use std::path::PathBuf;

use pingu_launcher::assets::{self, Asset};
use pingu_launcher::checks::{self, Action, Bootloader, Check, Report, Status};
use pingu_launcher::mode::GameMode;
use pingu_launcher::runtime::{RuntimeMode, RuntimeState};

use common::{Fixture, narrow_xcr0, no_faulting, titles};

fn find<'a>(report: &'a Report, title: &str) -> &'a Check {
    report
        .checks
        .iter()
        .find(|check| check.title == title)
        .unwrap_or_else(|| panic!("no check {title}"))
}

fn assert_problem(report: &Report, title: &str) -> Check {
    let check = find(report, title).clone();
    assert_eq!(check.status, Status::Problem, "{title}: {}", check.detail);
    check
}

#[test]
fn healthy_machine_passes() {
    let fixture = Fixture::healthy("healthy");
    let report = fixture.report();
    assert!(report.ok(), "{}", checks::render_text(&report));
    assert_eq!(report.problem_count(), 0);
    assert!(matches!(
        report.runtime.unwrap().state,
        RuntimeState::NotRequired(_)
    ));
}

#[test]
fn legacy_mode_only_requires_umip_cpuid_faulting_and_the_hook() {
    let mut fixture = Fixture::healthy("legacy");
    // Everything the restriction needs is broken, and none of it matters.
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu fred ibt svm\n",
    );
    fixture.remove("sys/module/pingu_policy");
    fixture.set_env("AVX2_RUNTIME", "/nonexistent");
    let report = fixture.report_in(GameMode::Legacy);
    assert_eq!(titles(&report), ["UMIP", "CPUID faulting", "pingu-hook"]);
    assert!(report.runtime.is_none());
    assert!(!report.plan.policy);
    assert!(report.ok(), "{}", checks::render_text(&report));
}

#[test]
fn legacy_mode_still_needs_its_three_requirements() {
    let mut fixture = Fixture::healthy("legacy-broken");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: GenuineIntel\nflags\t\t: umip\n",
    );
    fixture.remove("sys/module/pingu_policy");
    fixture.sys.cpuid_faulting = no_faulting;
    fixture.break_hook();
    let report = fixture.report_in(GameMode::Legacy);
    assert_problem(&report, "UMIP");
    assert_problem(&report, "CPUID faulting");
    assert_problem(&report, "pingu-hook");
    // An active UMIP needs the module even without the restriction.
    assert_eq!(
        titles(&report),
        ["UMIP", "CPUID faulting", "pingu-hook", "pingu-policy"]
    );
}

#[test]
fn artifact_mode_with_native_xcr0_7_needs_no_restriction() {
    let mut fixture = Fixture::healthy("artifact-xcr0-7");
    fixture.sys.native_xcr0 = narrow_xcr0;
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu fred ibt svm\n",
    );
    fixture.remove("sys/module/pingu_policy");
    let report = fixture.report();
    assert_eq!(titles(&report), ["UMIP", "CPUID faulting", "pingu-hook"]);
    assert!(report.runtime.is_none() && !report.plan.policy);
    assert!(report.ok());
    assert!(report.plan.describe().contains("not needed"));
}

#[test]
fn artifact_mode_with_a_wide_native_xcr0_adds_the_restriction_checks() {
    let fixture = Fixture::healthy("artifact-wide");
    let report = fixture.report();
    assert_eq!(
        titles(&report),
        ["UMIP", "CPUID faulting", "pingu-hook", "pingu-policy"]
    );
    assert!(report.runtime.is_some() && report.plan.policy);
    assert!(report.plan.describe().contains("0x2e7"));
}

#[test]
fn unknown_native_xcr0_is_treated_as_wide() {
    let mut fixture = Fixture::healthy("xcr0-unknown");
    fixture.sys.native_xcr0 = || None;
    assert!(fixture.report().plan.policy);
}

#[test]
fn avx2_policy_zero_turns_the_restriction_off() {
    let mut fixture = Fixture::healthy("policy-off");
    fixture.set_env("AVX2_POLICY", "0");
    let report = fixture.report();
    assert!(!report.plan.policy);
    assert_eq!(titles(&report), ["UMIP", "CPUID faulting", "pingu-hook"]);
    assert!(report.plan.describe().contains("AVX2_POLICY=0"));
}

#[test]
fn active_umip_needs_the_module_and_its_card_appears_in_every_mode() {
    let fixture = Fixture::healthy("umip");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu umip svm\n",
    );
    fixture.remove("sys/module/pingu_policy");
    let report = fixture.report_in(GameMode::Legacy);
    let umip = assert_problem(&report, "UMIP");
    assert!(umip.fix.contains("pingu_policy"), "{}", umip.fix);
    assert_problem(&report, "pingu-policy");
    assert!(!report.ok());
}

#[test]
fn the_module_handles_an_active_umip_without_a_boot_parameter() {
    let fixture = Fixture::healthy("umip-handled");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu umip svm\n",
    );
    let report = fixture.report();
    let umip = find(&report, "UMIP");
    assert_eq!(umip.status, Status::Ok);
    assert!(umip.detail.contains("pingu_policy"), "{}", umip.detail);
    assert!(report.ok(), "{}", checks::render_text(&report));
}

#[test]
fn fred_and_ibt_need_no_boot_parameters() {
    let fixture = Fixture::healthy("fred-ibt");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: GenuineIntel\nflags\t\t: fpu fred ibt\n",
    );
    let report = fixture.report();
    assert_eq!(
        titles(&report),
        ["UMIP", "CPUID faulting", "pingu-hook", "pingu-policy"]
    );
    assert!(report.ok(), "{}", checks::render_text(&report));
}

#[test]
fn umip_still_active_with_the_old_parameter_asks_for_a_reboot() {
    let fixture = Fixture::healthy("reboot");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu umip svm\n",
    );
    fixture.write("proc/cmdline", "root=/dev/sda1 clearcpuid=umip\n");
    fixture.remove("sys/module/pingu_policy/parameters/umip_fixup");
    let report = fixture.report();
    let umip = assert_problem(&report, "UMIP");
    assert!(umip.detail.contains("still active"), "{}", umip.detail);
    assert!(umip.fix.contains("Reboot"), "{}", umip.fix);
}

#[test]
fn deprecated_settings_get_migration_guidance_without_failing_the_check() {
    let fixture = Fixture::healthy("deprecated");
    fixture.write(
        "proc/cmdline",
        "BOOT_IMAGE=/vmlinuz root=/dev/sda1 clearcpuid=umip fred=off ibt=off\n",
    );
    fixture.write("etc/default/grub", "");
    fixture.write("sys/module/cpuid_fault_emulation/initstate", "live\n");
    fixture.write("var/lib/dkms/cpuid_fault_emulation/0.1/source", "");
    let report = fixture.report();
    let deprecated = find(&report, "Deprecated setup");
    assert_eq!(deprecated.status, Status::Ok);
    assert!(
        deprecated.detail.contains("cpuid_fault_emulation")
            && deprecated
                .detail
                .contains("clearcpuid=umip fred=off ibt=off"),
        "{}",
        deprecated.detail
    );
    let steps = &deprecated.warning;
    for needle in [
        "sudo /opt/pingu-launcher module install",
        "modprobe -r cpuid_fault_emulation",
        "GRUB_CMDLINE_LINUX_DEFAULT",
        "grub-mkconfig",
        "Reboot",
    ] {
        assert!(steps.contains(needle), "{needle} missing in {steps}");
    }
    assert!(report.ok(), "{}", checks::render_text(&report));
    assert!(checks::render_text(&report).contains("[ ok ] Deprecated setup"));

    // A clean machine has no such card.
    let clean = Fixture::healthy("not-deprecated");
    assert!(!titles(&clean.report()).contains(&"Deprecated setup"));
}

#[test]
fn clearcpuid_umip_is_fine_when_the_module_would_only_serve_umip() {
    let fixture = Fixture::healthy("umip-only");
    fixture.write("proc/cmdline", "root=/dev/sda1 clearcpuid=umip fred=off\n");
    fixture.remove("sys/module/pingu_policy");
    let report = fixture.report_in(GameMode::Legacy);
    assert_eq!(titles(&report), ["UMIP", "CPUID faulting", "pingu-hook"]);
    assert!(report.ok(), "{}", checks::render_text(&report));

    // The same parameters are deprecated once the restriction needs the module anyway.
    let report = fixture.report();
    assert!(titles(&report).contains(&"Deprecated setup"));
    assert!(titles(&report).contains(&"pingu-policy"));
}

#[test]
fn dropping_clearcpuid_waits_for_a_module_that_handles_umip() {
    let fixture = Fixture::healthy("deprecated-order");
    fixture.write("proc/cmdline", "root=/dev/sda1 clearcpuid=umip\n");
    fixture.remove("sys/module/pingu_policy/parameters/umip_fixup");
    let warning = find(&fixture.report(), "Deprecated setup").warning.clone();
    let install = warning
        .find("1. Install the current pingu-policy first")
        .unwrap();
    assert!(
        install < warning.find("2. Remove clearcpuid=umip").unwrap(),
        "{warning}"
    );

    // Once the module handles UMIP the install step is not needed.
    fixture.write("sys/module/pingu_policy/parameters/umip_fixup", "Y\n");
    let warning = find(&fixture.report(), "Deprecated setup").warning.clone();
    assert!(warning.contains("1. Remove clearcpuid=umip"), "{warning}");
}

#[test]
fn bootloader_detection_prefers_the_one_that_booted() {
    let fixture = Fixture::healthy("bootloader");
    let sys = &fixture.sys;
    assert_eq!(checks::detect_bootloader(sys, &[]), Bootloader::Unknown);
    fixture.write("boot/loader/entries/a.conf", "");
    assert_eq!(
        checks::detect_bootloader(sys, &[]),
        Bootloader::LoaderEntries
    );
    fixture.write("etc/kernel/cmdline", "");
    assert_eq!(
        checks::detect_bootloader(sys, &[]),
        Bootloader::KernelCmdline
    );
    fixture.write("etc/sdboot-manage.conf", "");
    assert_eq!(
        checks::detect_bootloader(sys, &[]),
        Bootloader::SdbootManage
    );
    fixture.write("etc/default/grub", "");
    assert_eq!(
        checks::detect_bootloader(sys, &["BOOT_IMAGE=/vmlinuz".to_string()]),
        Bootloader::Grub
    );
}

#[test]
fn the_hook_is_installed_from_the_binary() {
    let mut fixture = Fixture::healthy("hook");
    let check = find(&fixture.report(), "pingu-hook").clone();
    assert_eq!(check.status, Status::Ok);
    assert!(check.detail.contains("pingu-hook.so"), "{}", check.detail);
    assert!(fixture.home.hook().is_file());

    fixture.break_hook();
    let missing = assert_problem(&fixture.report(), "pingu-hook");
    assert!(
        missing.detail.contains("could not be installed"),
        "{}",
        missing.detail
    );
    assert!(missing.fix.contains("PINGU_RUNTIME_DIR"));
}

#[test]
fn hook_variant_comes_from_the_environment_or_the_variant_file() {
    let mut fixture = Fixture::healthy("variant");
    fixture.write_data("variants/pingu-hook.pr57.so", "v");
    fixture.write_data("variants/pingu-hook.other.so", "v");
    fixture.write_data("variant", " pr57 \nignored\n");
    let report = fixture.report();
    assert!(find(&report, "pingu-hook").detail.contains("variant pr57"));

    fixture.set_env("PINGU_HOOK_VARIANT", "other");
    assert!(
        find(&fixture.report(), "pingu-hook")
            .detail
            .contains("variant other")
    );
}

#[test]
fn unknown_variant_falls_back_to_the_default_with_a_warning() {
    let mut fixture = Fixture::healthy("variant-missing");
    fixture.set_env("PINGU_HOOK_VARIANT", "../escape");
    let check = find(&fixture.report(), "pingu-hook").clone();
    assert_eq!(check.status, Status::Ok);
    assert!(check.detail.contains("pingu-hook.so"), "{}", check.detail);
    assert!(
        check.detail.contains("Warning: variant not found"),
        "{}",
        check.detail
    );
}

#[test]
fn colon_in_the_library_path_is_rejected() {
    let mut fixture = Fixture::healthy("colon");
    fixture.home.root = fixture.root.join("we:ird");
    let check = assert_problem(&fixture.report(), "pingu-hook");
    assert!(check.detail.contains("':'"), "{}", check.detail);
}

#[test]
fn missing_cpuid_faulting_walks_through_the_module_states() {
    let mut fixture = Fixture::healthy("cpuid-faulting");
    fixture.sys.cpuid_faulting = no_faulting;
    fixture.remove("sys/module/pingu_policy");

    // Not loaded yet: the module card carries the install steps and the hypervisor warning.
    let report = fixture.report();
    let not_loaded = assert_problem(&report, "CPUID faulting");
    assert!(
        not_loaded.fix.contains("pingu_policy"),
        "{}",
        not_loaded.fix
    );
    let card = assert_problem(&report, "pingu-policy");
    assert!(
        card.warning.contains("Save your work first"),
        "{}",
        card.warning
    );

    // Loaded, but SVM was taken by KVM.
    fixture.write("sys/module/pingu_policy/parameters/ready", "Y\n");
    fixture.write(
        "sys/module/pingu_policy/parameters/cpuid_fault",
        "unavailable\n",
    );
    let blocked = assert_problem(&fixture.report(), "CPUID faulting");
    assert!(
        blocked.detail.contains("kvm_amd") && blocked.detail.contains("could not emulate"),
        "{}",
        blocked.detail
    );

    // A module from before the emulation existed.
    fixture.remove("sys/module/pingu_policy/parameters/cpuid_fault");
    assert!(
        assert_problem(&fixture.report(), "CPUID faulting")
            .detail
            .contains("predates")
    );

    fixture.remove("sys/module/pingu_policy");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: GenuineIntel\nflags\t\t: fpu\n",
    );
    assert!(
        assert_problem(&fixture.report(), "CPUID faulting")
            .detail
            .contains("needs an AMD CPU with SVM")
    );
}

#[test]
fn the_providers_of_cpuid_faulting_are_named() {
    let fixture = Fixture::healthy("cpuid-providers");
    let detail = |fixture: &Fixture| find(&fixture.report(), "CPUID faulting").detail.clone();
    assert!(detail(&fixture).contains("natively"));

    fixture.write(
        "sys/module/pingu_policy/parameters/cpuid_fault",
        "emulated\n",
    );
    assert!(detail(&fixture).contains("Emulated by the pingu_policy module"));

    fixture.write("sys/module/cpuid_fault_emulation/initstate", "live\n");
    let report = fixture.report();
    let check = find(&report, "CPUID faulting");
    assert_eq!(check.status, Status::Ok);
    assert!(check.detail.contains("deprecated cpuid_fault_emulation"));
}

#[test]
fn xcr0_module_states() {
    let fixture = Fixture::healthy("xcr0");

    fixture.write("sys/module/pingu_policy/parameters/ready", "N\n");
    assert!(
        assert_problem(&fixture.report(), "pingu-policy")
            .detail
            .contains("not ready")
    );

    fixture.remove("sys/module/pingu_policy");
    let missing = assert_problem(&fixture.report(), "pingu-policy");
    let version = assets::module_version();
    assert!(
        missing
            .fix
            .contains(&format!("dkms install -m pingu-policy -v {version}"))
    );
    assert!(
        missing.fix.contains(&format!(
            "/opt/pingu-launcher module export /usr/src/pingu-policy-{version}"
        )),
        "{}",
        missing.fix
    );

    fixture.write(
        "lib/modules/7.3.3-test/modules.dep",
        "updates/dkms/pingu_policy.ko.zst:\n",
    );
    let installed = assert_problem(&fixture.report(), "pingu-policy");
    assert!(
        installed.fix.starts_with("sudo modprobe pingu_policy\n"),
        "{}",
        installed.fix
    );
    assert!(!installed.fix.contains("experiment"), "{}", installed.fix);

    // The options file of version 0.3.0 would make modprobe refuse the module.
    fixture.write(
        "etc/modprobe.d/pingu-policy.conf",
        "options pingu_policy experiment=1 allow_host=1\n",
    );
    let configured = assert_problem(&fixture.report(), "pingu-policy");
    assert!(
        configured
            .fix
            .starts_with("/etc/modprobe.d/pingu-policy.conf sets options"),
        "{}",
        configured.fix
    );
    assert!(
        configured
            .fix
            .contains("sudo rm /etc/modprobe.d/pingu-policy.conf")
    );
}

const BUILD_ID: &str = "0102030405060708090a0b0c0d0e0f1011121314";

static PREBUILT: &[Asset] = &[Asset {
    path: "0102030405060708090a0b0c0d0e0f1011121314/pingu_policy.ko",
    mode: 0o644,
    data: b"policy module",
}];

/// A SteamOS machine whose kernel has the GNU build ID `BUILD_ID`.
fn steamos(name: &str) -> Fixture {
    let mut fixture = Fixture::healthy(name);
    fixture.remove("sys/module/pingu_policy");
    fixture.write("etc/os-release", "NAME=\"SteamOS\"\nID=steamos\n");
    // An unrelated note first, then the GNU build ID 01..14.
    let mut notes = Vec::new();
    for (name, kind, desc) in [
        (&b"ABC\0"[..], 1u32, vec![9u8; 4]),
        (b"GNU\0", 3, (1..=20).collect()),
    ] {
        for word in [name.len() as u32, desc.len() as u32, kind] {
            notes.extend(word.to_ne_bytes());
        }
        notes.extend(name);
        notes.extend(&desc);
    }
    let notes_path = fixture.root.join("sys/kernel/notes");
    std::fs::create_dir_all(notes_path.parent().unwrap()).unwrap();
    std::fs::write(notes_path, notes).unwrap();
    assert_eq!(fixture.sys.kernel_build_id().as_deref(), Some(BUILD_ID));
    fixture.sys.steamos_modules = &[];
    fixture
}

#[test]
fn steamos_without_a_prebuilt_module_for_the_kernel_names_the_build() {
    let fixture = steamos("steamos-unknown");
    let missing = assert_problem(&fixture.report(), "pingu-policy");
    assert!(
        missing
            .detail
            .contains("no prebuilt pingu_policy module for SteamOS kernel 7.3.3-test")
    );
    assert!(missing.detail.contains(BUILD_ID), "{}", missing.detail);
    assert!(
        missing.fix.contains("make steamos-modules"),
        "{}",
        missing.fix
    );
    assert!(!missing.fix.contains("dkms"), "{}", missing.fix);
    assert_eq!(missing.action, None);
}

#[test]
fn steamos_offers_to_install_the_embedded_modules() {
    let mut fixture = steamos("steamos-install");
    fixture.sys.steamos_modules = PREBUILT;
    // Without pkexec only the command is shown.
    let manual = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(manual.action, None);
    assert_eq!(manual.fix, "sudo /opt/pingu-launcher module install");

    fixture.executable("bin/pkexec");
    let missing = assert_problem(&fixture.report(), "pingu-policy");
    assert!(
        missing.detail.contains("is not installed"),
        "{}",
        missing.detail
    );
    assert_eq!(missing.action, Some(Action::InstallPolicyModule));
    assert_eq!(missing.action_label, "Install prebuilt module");

    // A module for the same release string but another build does not count.
    fixture.write(
        "var/lib/pingu-runtime/modules/ffffffffffffffffffffffffffffffffffffffff/pingu_policy.ko",
        "",
    );
    assert!(
        assert_problem(&fixture.report(), "pingu-policy")
            .detail
            .contains("is not installed")
    );

    fixture.write(
        &format!("var/lib/pingu-runtime/modules/{BUILD_ID}/pingu_policy.ko"),
        "policy module",
    );
    let installed = assert_problem(&fixture.report(), "pingu-policy");
    assert!(
        installed
            .fix
            .starts_with("sudo systemctl restart pingu-modules.service")
    );
    assert_eq!(installed.action, Some(Action::InstallPolicyModule));
}

#[test]
fn steamos_offers_the_one_module_for_cpuid_faulting_too() {
    let mut fixture = steamos("steamos-cpuid");
    fixture.sys.steamos_modules = PREBUILT;
    fixture.sys.cpuid_faulting = no_faulting;
    fixture.executable("bin/pkexec");
    let report = fixture.report();
    assert!(
        assert_problem(&report, "CPUID faulting")
            .fix
            .contains("pingu_policy")
    );
    let card = assert_problem(&report, "pingu-policy");
    assert_eq!(card.action, Some(Action::InstallPolicyModule));
    assert_eq!(card.action_label, "Install prebuilt module");
    assert!(card.warning.contains("Save your work first"));
}

#[test]
fn an_older_loaded_module_fails_the_check_with_update_steps() {
    let fixture = Fixture::healthy("loaded-version");
    fixture.write("sys/module/pingu_policy/version", "0.3.0\n");
    fixture.write(
        "etc/modprobe.d/pingu-policy.conf",
        "options pingu_policy experiment=1 allow_host=1\n",
    );
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert!(
        check.detail.contains("pingu_policy 0.3.0 is loaded"),
        "{}",
        check.detail
    );
    let steps: Vec<&str> = check.fix.lines().collect();
    let position = |needle: &str| {
        steps
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no {needle} in {}", check.fix))
    };
    assert!(
        position("sudo rm /etc/modprobe.d/pingu-policy.conf")
            < position("dkms remove pingu-policy/0.3.0 --all")
    );
    let version = assets::module_version();
    assert!(
        position("dkms remove pingu-policy/0.3.0 --all")
            < position(&format!("module export /usr/src/pingu-policy-{version}"))
    );
    assert!(
        position(&format!("dkms add -m pingu-policy -v {version}"))
            < position(&format!("dkms install -m pingu-policy -v {version}"))
    );
    assert!(check.fix.contains("Then reboot"), "{}", check.fix);

    fixture.write("sys/module/pingu_policy/version", &format!("{version}\n"));
    let current = find(&fixture.report(), "pingu-policy").clone();
    assert_eq!(current.status, Status::Ok);
    assert!(current.fix.is_empty(), "{}", current.fix);
}

fn with_install_tools(fixture: &Fixture) {
    fixture.executable("bin/dkms");
    fixture.executable("bin/pkexec");
}

#[test]
fn the_module_check_offers_the_install_button_when_dkms_and_pkexec_exist() {
    let fixture = Fixture::healthy("install-button");
    fixture.remove("sys/module/pingu_policy");
    assert_eq!(
        assert_problem(&fixture.report(), "pingu-policy").action,
        None
    );

    with_install_tools(&fixture);
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, Some(Action::InstallPolicyModule));
    assert!(check.fix.contains("dkms install"), "{}", check.fix);
}

#[test]
fn a_missing_qemu_is_a_warning_before_the_module_is_built() {
    let fixture = Fixture::healthy("install-no-qemu");
    fixture.remove("sys/module/pingu_policy");
    with_install_tools(&fixture);
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, Some(Action::InstallPolicyModule));
    assert!(check.warning.contains("QEMU"), "{}", check.warning);
    assert!(
        check.warning.contains("without its VM test"),
        "{}",
        check.warning
    );
    assert!(checks::render_text(&fixture.report()).contains("Warning: QEMU"));

    fixture.executable("bin/qemu-system-x86_64");
    assert!(
        assert_problem(&fixture.report(), "pingu-policy")
            .warning
            .contains("/dev/kvm")
    );

    fixture.write("dev/kvm", "");
    assert_eq!(
        assert_problem(&fixture.report(), "pingu-policy").warning,
        ""
    );
}

#[test]
fn a_loaded_module_built_without_the_vm_test_is_flagged_but_ok() {
    let fixture = Fixture::healthy("loaded-untested");
    let version = assets::module_version();
    fixture.write("sys/module/pingu_policy/version", &format!("{version}\n"));
    let clean = find(&fixture.report(), "pingu-policy").clone();
    assert_eq!(clean.status, Status::Ok);
    assert_eq!(clean.warning, "");

    fixture.write(
        &format!("var/lib/dkms/pingu-policy/{version}/7.3.3-test/x86_64/log/make.log"),
        "*** WARNING: pingu-policy is built WITHOUT its VM test ***\n",
    );
    let flagged = find(&fixture.report(), "pingu-policy").clone();
    assert_eq!(flagged.status, Status::Ok);
    assert!(
        flagged.warning.contains("rebuild with"),
        "{}",
        flagged.warning
    );
    assert!(
        flagged
            .warning
            .contains(&format!("-v {version} -k 7.3.3-test")),
        "{}",
        flagged.warning
    );
}

#[test]
fn the_report_knows_whether_anything_is_installed() {
    let fixture = Fixture::healthy("report-installed");
    assert!(!fixture.report().installed);
    fixture.write(
        &format!(
            "var/lib/dkms/pingu-policy/{}/source",
            assets::module_version()
        ),
        "",
    );
    assert!(fixture.report().installed);
}

#[test]
fn a_missing_dkms_is_named_instead_of_offering_the_button() {
    let fixture = Fixture::healthy("install-no-dkms");
    fixture.remove("sys/module/pingu_policy");
    fixture.executable("bin/pkexec");
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, None);
    assert!(check.fix.contains("DKMS is not installed"), "{}", check.fix);
}

#[test]
fn the_install_button_is_offered_on_fred_and_ibt_machines() {
    let fixture = Fixture::healthy("install-fred");
    fixture.remove("sys/module/pingu_policy");
    with_install_tools(&fixture);
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu avx2 avx512f svm fred ibt\n",
    );
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, Some(Action::InstallPolicyModule));
}

#[test]
fn an_installed_update_waits_for_the_reboot_instead_of_offering_another_install() {
    let fixture = Fixture::healthy("install-pending-reboot");
    with_install_tools(&fixture);
    fixture.write("sys/module/pingu_policy/version", "0.3.0\n");
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, Some(Action::InstallPolicyModule));

    fixture.write(
        &format!(
            "var/lib/dkms/pingu-policy/{}/7.3.3-test/x86_64/module/pingu_policy.ko",
            assets::module_version()
        ),
        "",
    );
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, None);
    assert!(
        check.detail.contains("replaces it at the next reboot"),
        "{}",
        check.detail
    );
    assert_eq!(check.fix, "Reboot to load it.");
}

#[test]
fn the_module_card_warns_before_starting_the_hypervisor() {
    let mut fixture = Fixture::healthy("install-cpuid");
    fixture.sys.cpuid_faulting = no_faulting;
    fixture.remove("sys/module/pingu_policy");
    with_install_tools(&fixture);
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(check.action, Some(Action::InstallPolicyModule));
    assert!(
        check.warning.contains("Save your work first"),
        "{}",
        check.warning
    );
}

#[test]
fn steamos_updates_by_installing_the_embedded_modules() {
    let mut fixture = steamos("steamos-update");
    fixture.sys.steamos_modules = PREBUILT;
    fixture.executable("bin/pkexec");
    fixture.write("sys/module/pingu_policy/version", "0.3.0\n");
    fixture.write("sys/module/pingu_policy/parameters/ready", "Y\n");
    let check = assert_problem(&fixture.report(), "pingu-policy");
    assert!(check.fix.contains("module install"), "{}", check.fix);
    assert!(!check.fix.contains("dkms"), "{}", check.fix);
    assert_eq!(check.action_label, "Install prebuilt module");

    fixture.write(
        &format!("var/lib/pingu-runtime/modules/{BUILD_ID}/pingu_policy.ko"),
        "policy module",
    );
    let pending = assert_problem(&fixture.report(), "pingu-policy");
    assert_eq!(pending.action, None);
    assert!(
        pending.detail.contains("replaces it at the next reboot"),
        "{}",
        pending.detail
    );
}

fn avx512_host(fixture: &Fixture) {
    fixture.write(
        "var/lib/pacman/local/glibc-2.44-1/desc",
        "%NAME%\nglibc\n\n%VERSION%\n2.44-1\n\n%ARCH%\nx86_64_v4\n",
    );
}

fn write_runtime(fixture: &Fixture, glibc: &str, schema: i64) -> PathBuf {
    let generation = fixture.home.generations().join("nvidia-abc");
    fs::create_dir_all(&generation).unwrap();
    fs::write(
        generation.join("runtime.json"),
        format!("{{\"schema\": {schema}, \"gpu\": \"nvidia\", \"glibc\": \"{glibc}\"}}"),
    )
    .unwrap();
    let link = generation.parent().unwrap().join("nvidia-current");
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&generation, &link).unwrap();
    generation
}

fn runtime_state(fixture: &Fixture) -> RuntimeState {
    fixture.report().runtime.expect("restriction is used").state
}

#[test]
fn runtime_is_only_required_for_avx512_hosts() {
    let fixture = Fixture::healthy("runtime-required");
    assert!(matches!(
        runtime_state(&fixture),
        RuntimeState::NotRequired(_)
    ));

    avx512_host(&fixture);
    assert_eq!(runtime_state(&fixture), RuntimeState::Missing);

    // A v4 repository counts even before its packages replace the installed ones.
    let other = Fixture::healthy("runtime-repo");
    other.write(
        "etc/pacman.conf",
        "[options]\n[cachyos-znver4]\nInclude = x\n[core]\n",
    );
    assert_eq!(runtime_state(&other), RuntimeState::Missing);

    let never = checks::run_all(
        &fixture.sys,
        &fixture.home,
        RuntimeMode::Never,
        &Fixture::detection(GameMode::Artifact),
    );
    assert!(matches!(
        never.runtime.unwrap().state,
        RuntimeState::NotRequired(_)
    ));
    let always = checks::run_all(
        &other.sys,
        &other.home,
        RuntimeMode::Always,
        &Fixture::detection(GameMode::Artifact),
    );
    assert_eq!(always.runtime.unwrap().state, RuntimeState::Missing);
}

#[test]
fn runtime_states_follow_the_selected_generation() {
    let fixture = Fixture::healthy("runtime-states");
    avx512_host(&fixture);

    let report = fixture.report();
    let info = report.runtime.clone().unwrap();
    let missing = info.as_check();
    assert_eq!(missing.status, Status::Problem);
    assert_eq!(
        info.action().map(|action| action.label()),
        Some("Generate runtime")
    );
    assert!(
        missing.fix.contains("runtime provision --gpu nvidia"),
        "{}",
        missing.fix
    );

    write_runtime(&fixture, "2.43-1", 2);
    let info = fixture.report().runtime.unwrap();
    assert_eq!(
        info.state,
        RuntimeState::Stale {
            selected: "2.43-1".into(),
            host: "2.44-1".into()
        }
    );
    assert_eq!(
        info.action().map(|action| action.label()),
        Some("Upgrade runtime")
    );

    write_runtime(&fixture, "2.44-1", 2);
    let report = fixture.report();
    let info = report.runtime.clone().unwrap();
    assert_eq!(
        info.state,
        RuntimeState::Ready {
            glibc: "2.44-1".into()
        }
    );
    assert!(report.ok(), "{}", checks::render_text(&report));
    assert!(info.action().is_none());

    write_runtime(&fixture, "2.44-1", 1);
    assert!(matches!(runtime_state(&fixture), RuntimeState::Invalid(_)));
}

#[test]
fn explicit_runtime_settings_override_detection() {
    let mut fixture = Fixture::healthy("runtime-env");
    avx512_host(&fixture);
    let generation = write_runtime(&fixture, "2.44-1", 2);
    fs::remove_file(fixture.home.generations().join("nvidia-current")).unwrap();
    assert_eq!(runtime_state(&fixture), RuntimeState::Missing);

    fixture.set_env("AVX2_RUNTIME", &generation.to_string_lossy());
    assert!(matches!(
        runtime_state(&fixture),
        RuntimeState::Ready { .. }
    ));

    fixture.set_env("AVX2_RUNTIME", "none");
    assert!(matches!(
        runtime_state(&fixture),
        RuntimeState::NotRequired(_)
    ));

    // An explicit path means the user wants the runtime even on a generic host.
    let mut generic = Fixture::healthy("runtime-explicit");
    generic.set_env("AVX2_RUNTIME", "/nonexistent");
    assert_eq!(runtime_state(&generic), RuntimeState::Missing);

    fixture.sys.env.remove("AVX2_RUNTIME");
    fixture.set_env("AVX2_GPU", "amd");
    assert_eq!(fixture.report().runtime.unwrap().gpu, "amd");
}

#[test]
fn gpu_is_detected_from_drm_vendors() {
    let fixture = Fixture::healthy("gpu");
    fixture.write("sys/class/drm/card0/device/vendor", "0x8086\n");
    fixture.write("sys/class/drm/card1/device/vendor", "0x10de\n");
    fixture.write("sys/class/drm/card1-DP-1/device/vendor", "0x1002\n");
    assert_eq!(fixture.report().runtime.unwrap().gpu, "nvidia");
    fixture.remove("sys/class/drm/card1");
    assert_eq!(fixture.report().runtime.unwrap().gpu, "intel");
}

#[test]
fn text_report_names_the_mode_and_lists_every_check() {
    let fixture = Fixture::healthy("text");
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: AuthenticAMD\nflags\t\t: fpu umip svm\n",
    );
    fixture.remove("sys/module/pingu_policy/parameters/umip_fixup");
    let text = checks::render_text(&fixture.report());
    assert!(text.starts_with("Artifact mode\n"));
    assert!(text.contains("Native XCR0 is 0x2e7"));
    assert!(text.contains("[FAIL] UMIP"));
    assert!(text.contains("[ ok ] pingu-hook"));
    assert!(text.contains("[ ok ] Private runtime"));
}
