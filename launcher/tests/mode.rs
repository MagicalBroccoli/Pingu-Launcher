mod common;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use pingu_launcher::mode::{self, GameMode, ModeSetting};

use common::Fixture;

fn game_dir(fixture: &Fixture, name: &str) -> PathBuf {
    let dir = fixture.root.join("games").join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn detect(fixture: &Fixture, command: &[&str]) -> mode::Detection {
    let command: Vec<String> = command.iter().map(|part| part.to_string()).collect();
    mode::detect(&fixture.sys, &command, ModeSetting::Auto)
}

#[test]
fn artifact_dll_anywhere_below_the_game_dir_selects_artifact_mode() {
    let mut fixture = Fixture::healthy("mode-found");
    let dir = game_dir(&fixture, "found");
    fs::create_dir_all(dir.join("Binaries/Win64")).unwrap();
    fs::write(dir.join("Binaries/Win64/Artifact.DLL"), "").unwrap();
    fixture.set_env("STEAM_COMPAT_INSTALL_PATH", &dir.to_string_lossy());

    let detection = detect(&fixture, &["reaper"]);
    assert_eq!(detection.mode, GameMode::Artifact);
    assert!(
        detection.note.contains("Artifact.DLL"),
        "{}",
        detection.note
    );
}

#[test]
fn no_artifact_dll_means_legacy_mode() {
    let mut fixture = Fixture::healthy("mode-missing");
    let dir = game_dir(&fixture, "plain");
    fs::write(dir.join("game.exe"), "").unwrap();
    fixture.set_env("GAMEDIR", &dir.to_string_lossy());

    let detection = detect(&fixture, &["umu-run"]);
    assert_eq!(detection.mode, GameMode::Legacy);
    assert!(
        detection.note.contains("no artifact.dll in"),
        "{}",
        detection.note
    );
}

#[test]
fn without_any_game_directory_the_mode_is_legacy() {
    let mut fixture = Fixture::healthy("mode-unknown");
    // Started from the home directory, which says nothing about the game.
    let home = fixture.root.join("home/user");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("artifact.dll"), "").unwrap();
    fixture.set_env("HOME", &home.to_string_lossy());

    let detection = detect(&fixture, &["umu-run"]);
    assert_eq!(detection.mode, GameMode::Legacy);
    assert!(
        detection.note.contains("no game directory"),
        "{}",
        detection.note
    );
}

#[test]
fn the_window_without_a_command_assumes_artifact_mode() {
    let fixture = Fixture::healthy("mode-no-command");
    let detection = detect(&fixture, &[]);
    assert_eq!(detection.mode, GameMode::Artifact);
    assert!(detection.note.contains("no command"), "{}", detection.note);
}

#[test]
fn executable_argument_and_working_directory_are_searched() {
    let mut fixture = Fixture::healthy("mode-sources");
    let exe_dir = game_dir(&fixture, "by-exe");
    fs::write(exe_dir.join("artifact.dll"), "").unwrap();
    fs::write(exe_dir.join("Game.EXE"), "").unwrap();
    let exe = exe_dir.join("Game.EXE").to_string_lossy().into_owned();
    assert_eq!(
        detect(&fixture, &["umu-run", &exe]).mode,
        GameMode::Artifact
    );

    let cwd = game_dir(&fixture, "by-cwd");
    fs::write(cwd.join("artifact.dll"), "").unwrap();
    fixture.sys.cwd = cwd;
    assert_eq!(detect(&fixture, &["umu-run"]).mode, GameMode::Artifact);
}

#[test]
fn working_directory_is_only_a_fallback() {
    let mut fixture = Fixture::healthy("mode-cwd");
    let cwd = game_dir(&fixture, "unrelated-cwd");
    fs::write(cwd.join("artifact.dll"), "").unwrap();
    fixture.sys.cwd = cwd;
    let plain = game_dir(&fixture, "plain-game");
    fixture.set_env("STEAM_COMPAT_INSTALL_PATH", &plain.to_string_lossy());
    assert_eq!(detect(&fixture, &["reaper"]).mode, GameMode::Legacy);
}

#[test]
fn every_explicit_directory_is_searched() {
    let mut fixture = Fixture::healthy("mode-order");
    let install = game_dir(&fixture, "install");
    let other = game_dir(&fixture, "other");
    fs::write(other.join("artifact.dll"), "").unwrap();
    fixture.set_env("STEAM_COMPAT_INSTALL_PATH", &install.to_string_lossy());
    fixture.set_env("GAMEDIR", &other.to_string_lossy());
    assert_eq!(detect(&fixture, &["reaper"]).mode, GameMode::Artifact);
}

#[test]
fn explicit_mode_skips_the_scan() {
    let mut fixture = Fixture::healthy("mode-forced");
    let dir = game_dir(&fixture, "forced");
    fs::write(dir.join("artifact.dll"), "").unwrap();
    fixture.set_env("GAMEDIR", &dir.to_string_lossy());
    let forced = mode::detect(&fixture.sys, &[], ModeSetting::Legacy);
    assert_eq!(forced.mode, GameMode::Legacy);
    assert!(forced.note.contains("--mode legacy"));
    assert_eq!(
        mode::detect(&fixture.sys, &[], ModeSetting::Artifact).mode,
        GameMode::Artifact
    );
}

#[test]
fn the_scan_is_bounded_and_ignores_symlinked_directories() {
    let mut fixture = Fixture::healthy("mode-limits");
    let dir = game_dir(&fixture, "deep");
    let mut deep = dir.clone();
    for _ in 0..9 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("artifact.dll"), "").unwrap();
    fixture.set_env("GAMEDIR", &dir.to_string_lossy());
    assert_eq!(detect(&fixture, &["x"]).mode, GameMode::Legacy);

    let shallow = game_dir(&fixture, "shallow");
    let mut near = shallow.clone();
    for _ in 0..8 {
        near.push("d");
    }
    fs::create_dir_all(&near).unwrap();
    fs::write(near.join("artifact.dll"), "").unwrap();
    fixture.set_env("GAMEDIR", &shallow.to_string_lossy());
    assert_eq!(detect(&fixture, &["x"]).mode, GameMode::Artifact);

    let outside = game_dir(&fixture, "outside");
    fs::write(outside.join("artifact.dll"), "").unwrap();
    let linked = game_dir(&fixture, "linked");
    symlink(&outside, linked.join("elsewhere")).unwrap();
    fixture.set_env("GAMEDIR", &linked.to_string_lossy());
    assert_eq!(detect(&fixture, &["x"]).mode, GameMode::Legacy);
}
