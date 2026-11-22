mod common;

use std::fs;
use std::path::PathBuf;

use pingu_launcher::launch::{self, Launch};
use pingu_launcher::mode::GameMode;

use common::Fixture;

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn build(fixture: &Fixture, mode: GameMode, command: &[&str]) -> Launch {
    let report = fixture.report_in(mode);
    launch::build(&fixture.sys, &fixture.home, &report, &words(command)).unwrap()
}

fn env<'a>(launch: &'a Launch, key: &str) -> Option<&'a str> {
    launch
        .env
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn library(fixture: &Fixture) -> String {
    fixture.home.hook().to_string_lossy().into_owned()
}

/// An original Proton, bubblewrap on PATH and `AVX2_PROTON_PATH` pointing at the Proton.
fn proton(fixture: &mut Fixture) -> PathBuf {
    let original = fixture.root.join("Proton");
    fs::create_dir_all(original.join("files")).unwrap();
    fs::write(original.join("proton"), "proton\n").unwrap();
    fs::write(
        original.join("toolmanifest.vdf"),
        "\"manifest\"\n{\n\t\"commandline\" \"/proton %verb%\"\n\t\"require_tool_appid\" \"4183110\"\n\t\"compatmanager_layer_name\" \"proton\"\n}\n",
    )
    .unwrap();
    fixture.executable("bin/bwrap");
    fixture.set_env("AVX2_PROTON_PATH", &original.to_string_lossy());
    original
}

fn avx512_host(fixture: &Fixture) {
    fixture.write(
        "var/lib/pacman/local/glibc-2.44-1/desc",
        "%NAME%\nglibc\n\n%VERSION%\n2.44-1\n\n%ARCH%\nx86_64_v4\n",
    );
}

/// A selected nvidia generation for glibc 2.44-1, with the host directories it overlays.
fn generation(fixture: &Fixture) -> PathBuf {
    let libraries = fixture.home.generations().join("nvidia-abc");
    for directory in [
        "usr/lib",
        "usr/lib32",
        "usr/share/vulkan/icd.d",
        "usr/share/glvnd/egl_vendor.d",
    ] {
        fs::create_dir_all(libraries.join(directory)).unwrap();
        fs::create_dir_all(fixture.root.join(directory)).unwrap();
    }
    fs::write(
        libraries.join("runtime.json"),
        "{\"schema\": 2, \"gpu\": \"nvidia\", \"glibc\": \"2.44-1\"}",
    )
    .unwrap();
    fs::write(libraries.join("VERSION"), "2.44-1\n").unwrap();
    std::os::unix::fs::symlink(
        &libraries,
        fixture.home.generations().join("nvidia-current"),
    )
    .unwrap();
    fixture.write("usr/share/vulkan/icd.d/nvidia_icd.json", "{}");
    fixture.write("usr/share/glvnd/egl_vendor.d/10_nvidia.json", "{}");
    libraries
}

#[test]
fn legacy_mode_runs_the_command_directly_under_the_preload() {
    let fixture = Fixture::healthy("launch-legacy");
    let launch = build(&fixture, GameMode::Legacy, &["umu-run", "game.exe"]);
    assert_eq!(launch.program, "umu-run");
    assert_eq!(launch.args, ["game.exe"]);
    assert_eq!(env(&launch, "LD_PRELOAD"), Some(library(&fixture).as_str()));
    assert_eq!(
        env(&launch, "PINGU_LAUNCHER"),
        Some(fixture.sys.exe.to_str().unwrap())
    );
    assert_eq!(launch.env.len(), 2);
    // The library was installed into the data directory.
    assert!(fixture.home.hook().is_file());
}

#[test]
fn artifact_mode_without_restriction_also_runs_directly() {
    let mut fixture = Fixture::healthy("launch-xcr0-7");
    fixture.sys.native_xcr0 = common::narrow_xcr0;
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(launch.program, "umu-run");
    assert_eq!(env(&launch, "LD_PRELOAD"), Some(library(&fixture).as_str()));
}

#[test]
fn lutris_commands_run_inside_the_companion_namespace() {
    let mut fixture = Fixture::healthy("launch-lutris");
    let original = proton(&mut fixture);
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);

    assert!(launch.program.ends_with("bin/bwrap"), "{}", launch.program);
    assert_eq!(
        launch.args[launch.args.len() - 3..],
        ["--", "umu-run", "game.exe"]
    );
    assert!(
        launch
            .args
            .contains(&original.to_string_lossy().into_owned())
    );
    assert_eq!(env(&launch, "LD_PRELOAD"), Some(library(&fixture).as_str()));
    assert_eq!(env(&launch, "AVX2_GPU"), Some("nvidia"));
    // A generic host has no AVX-512 packages to replace.
    assert_eq!(env(&launch, "AVX2_RUNTIME"), Some("none"));
    assert_eq!(env(&launch, "AVX2_POLICY"), Some("xcr0-only"));
    let companion = PathBuf::from(env(&launch, "PROTONPATH").unwrap());
    assert!(companion.starts_with(fixture.home.companions()));
    assert!(companion.join("toolmanifest.vdf").is_file());
    assert!(
        launch
            .notes
            .iter()
            .any(|note| note.contains("restricting XCR0"))
    );
}

#[test]
fn overlay_wrappers_stay_in_front_of_umu_run_inside_the_namespace() {
    let mut fixture = Fixture::healthy("launch-overlay-wrappers");
    proton(&mut fixture);
    let launch = build(
        &fixture,
        GameMode::Artifact,
        &["gamemoderun", "mangohud", "umu-run", "game.exe"],
    );

    assert!(launch.program.ends_with("bin/bwrap"), "{}", launch.program);
    assert_eq!(
        launch.args[launch.args.len() - 5..],
        ["--", "gamemoderun", "mangohud", "umu-run", "game.exe"]
    );
    assert!(env(&launch, "PROTONPATH").is_some());
}

#[test]
fn steam_commands_replace_proton_in_place() {
    let mut fixture = Fixture::healthy("launch-steam");
    let original = proton(&mut fixture);
    fixture.sys.env.remove("AVX2_PROTON_PATH");
    let runtime = fixture.root.join("SteamLinuxRuntime");
    fs::create_dir_all(&runtime).unwrap();
    fs::write(runtime.join("_v2-entry-point"), "x").unwrap();
    fs::write(
        runtime.join("toolmanifest.vdf"),
        "\"manifest\" { \"compatmanager_layer_name\" \"container-runtime\" }",
    )
    .unwrap();
    let entry = runtime
        .join("_v2-entry-point")
        .to_string_lossy()
        .into_owned();
    let proton_path = original.join("proton").to_string_lossy().into_owned();
    let command = [
        "reaper",
        "SteamLaunch",
        "--",
        &entry,
        "--verb=run",
        "--",
        &proton_path,
        "run",
        "game.exe",
    ];
    let launch = build(&fixture, GameMode::Artifact, &command);

    let companion = PathBuf::from(env(&launch, "PROTONPATH").unwrap());
    let start = launch
        .args
        .iter()
        .position(|word| word == "reaper")
        .unwrap();
    assert_eq!(launch.args[start - 1], "--");
    assert_eq!(
        launch.args[start..],
        [
            "reaper",
            "SteamLaunch",
            "--",
            entry.as_str(),
            "--verb=run",
            "--",
            companion.join("proton").to_str().unwrap(),
            companion.join("original-proton").to_str().unwrap(),
            companion.join("original/proton").to_str().unwrap(),
            "run",
            "game.exe",
        ]
    );
}

#[test]
fn avx512_hosts_keep_the_private_runtime() {
    let mut fixture = Fixture::healthy("launch-runtime");
    proton(&mut fixture);
    avx512_host(&fixture);
    let libraries = generation(&fixture);
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(env(&launch, "AVX2_RUNTIME"), None);
    assert_eq!(
        env(&launch, "VK_DRIVER_FILES"),
        Some("/usr/share/vulkan/icd.d/nvidia_icd.json")
    );
    assert!(launch.args.contains(&"--ro-overlay".to_string()));
    assert!(
        env(&launch, "PRESSURE_VESSEL_FILESYSTEMS_RO")
            .unwrap()
            .split(':')
            .any(|mount| mount == fs::canonicalize(&libraries).unwrap().to_str().unwrap())
    );

    // The user's own settings are never overwritten.
    fixture.set_env("AVX2_GPU", "amd");
    fixture.set_env("AVX2_RUNTIME", "none");
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(
        launch
            .env
            .iter()
            .filter(|(name, _)| name == "AVX2_RUNTIME")
            .count(),
        0
    );
    assert!(!launch.args.contains(&"--ro-overlay".to_string()));
}

#[test]
fn a_missing_runtime_stops_the_launch() {
    let mut fixture = Fixture::healthy("launch-no-runtime");
    proton(&mut fixture);
    avx512_host(&fixture);
    let report = fixture.report();
    let error = launch::build(
        &fixture.sys,
        &fixture.home,
        &report,
        &words(&["umu-run", "game.exe"]),
    );
    assert!(error.unwrap_err().contains("No selected runtime"));
}

#[test]
fn the_kernel_must_accept_the_restriction() {
    let mut fixture = Fixture::healthy("launch-arm");
    proton(&mut fixture);
    fixture.sys.arm_check = |_, _| Err("Operation not supported".into());
    let report = fixture.report();
    let error = launch::build(
        &fixture.sys,
        &fixture.home,
        &report,
        &words(&["umu-run", "game.exe"]),
    );
    assert!(error.unwrap_err().contains("Operation not supported"));
}

#[test]
fn existing_preload_entries_follow_the_library() {
    let mut fixture = Fixture::healthy("launch-preload");
    fixture.set_env("LD_PRELOAD", "/steam/gameoverlayrenderer.so:/other.so");
    let launch = build(&fixture, GameMode::Legacy, &["gamescope", "--", "game"]);
    let library = library(&fixture);
    assert_eq!(
        env(&launch, "LD_PRELOAD"),
        Some(format!("{library}:/other.so").as_str())
    );
    let launch = build(&fixture, GameMode::Legacy, &["umu-run", "game"]);
    assert_eq!(
        env(&launch, "LD_PRELOAD"),
        Some(format!("{library}:/steam/gameoverlayrenderer.so:/other.so").as_str())
    );
}

#[test]
fn a_missing_variant_warns_and_an_unwritable_data_directory_fails() {
    let mut fixture = Fixture::healthy("launch-variant");
    fixture.set_env("PINGU_HOOK_VARIANT", "gone");
    let launch = build(&fixture, GameMode::Legacy, &["umu-run"]);
    assert_eq!(launch.notes.len(), 1);
    assert!(launch.notes[0].contains("variant not found"));

    fixture.break_hook();
    let report = fixture.report_in(GameMode::Legacy);
    let error = launch::build(&fixture.sys, &fixture.home, &report, &words(&["umu-run"]));
    assert!(error.unwrap_err().contains("could not be installed"));
}

const HOOK_PATH: &str = "PINGU_HOOK_PATH";

#[test]
fn artifact_mode_selects_the_artifact_path() {
    let mut fixture = Fixture::healthy("launch-artifact-protocol");
    proton(&mut fixture);
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(env(&launch, HOOK_PATH), Some("artifact"));
    assert!(
        fixture
            .report()
            .plan
            .describe()
            .contains("Artifact support active")
    );

    let legacy = build(&fixture, GameMode::Legacy, &["umu-run", "game.exe"]);
    assert_eq!(env(&legacy, HOOK_PATH), None);
}

#[test]
fn the_artifact_path_is_only_selected_when_xcr0_will_be_7() {
    let mut fixture = Fixture::healthy("launch-v2-xcr0");
    proton(&mut fixture);
    fixture.sys.native_xcr0 = common::narrow_xcr0;
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(env(&launch, HOOK_PATH), Some("artifact"));

    // Without the restriction the real XCR0 stays wide.
    fixture.sys.native_xcr0 = common::wide_xcr0;
    fixture.set_env("AVX2_POLICY", "0");
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(env(&launch, HOOK_PATH), None);
}

#[test]
fn the_artifact_path_is_vendor_independent_and_never_overrides_the_user() {
    let mut fixture = Fixture::healthy("launch-v2-vendor");
    proton(&mut fixture);
    fixture.set_env(HOOK_PATH, "0");
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(
        launch
            .env
            .iter()
            .filter(|(name, _)| name == HOOK_PATH)
            .count(),
        0
    );

    fixture.sys.env.remove(HOOK_PATH);
    fixture.write(
        "proc/cpuinfo",
        "vendor_id\t: GenuineIntel\nflags\t\t: fpu\n",
    );
    let launch = build(&fixture, GameMode::Artifact, &["umu-run", "game.exe"]);
    assert_eq!(env(&launch, HOOK_PATH), Some("artifact"));
}
