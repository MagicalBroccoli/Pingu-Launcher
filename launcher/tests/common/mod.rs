#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pingu_launcher::checks::{self, Report};
use pingu_launcher::home::Home;
use pingu_launcher::mode::{Detection, GameMode};
use pingu_launcher::runtime::RuntimeMode;
use pingu_launcher::sys::Sys;

pub fn faulting() -> bool {
    true
}

pub fn no_faulting() -> bool {
    false
}

pub fn wide_xcr0() -> Option<u64> {
    Some(0x2e7)
}

pub fn narrow_xcr0() -> Option<u64> {
    Some(7)
}

pub fn arm_ok(_: &Path, _: &str) -> Result<(), String> {
    Ok(())
}

pub struct Fixture {
    pub root: PathBuf,
    pub sys: Sys,
    pub home: Home,
}

impl Fixture {
    /// A machine that passes every check in artifact mode with a wide native XCR0.
    pub fn healthy(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = fs::remove_dir_all(&root);
        let bin = root.join("bin");
        let fixture = Self {
            sys: Sys {
                root: root.clone(),
                env: HashMap::from([
                    ("HOME".to_string(), "/home/user".to_string()),
                    ("PATH".to_string(), bin.to_string_lossy().into_owned()),
                ]),
                cwd: root.join("home/user"),
                exe: PathBuf::from("/opt/pingu-launcher"),
                cpuid_faulting: faulting,
                native_xcr0: wide_xcr0,
                arm_check: arm_ok,
                steamos_modules: &[],
            },
            home: Home {
                root: root.join("data"),
            },
            root,
        };
        fixture.write(
            "proc/cpuinfo",
            "processor\t: 0\nvendor_id\t: AuthenticAMD\nflags\t\t: fpu avx2 avx512f svm\n",
        );
        fixture.write(
            "proc/cmdline",
            "initrd=\\initramfs.img root=/dev/sda1 clearcpuid=umip\n",
        );
        fixture.write("proc/sys/kernel/osrelease", "7.3.3-test\n");
        fixture.write("sys/module/pingu_policy/parameters/ready", "Y\n");
        fixture.write(
            "var/lib/pacman/local/glibc-2.44-1/desc",
            "%NAME%\nglibc\n\n%VERSION%\n2.44-1\n\n%ARCH%\nx86_64\n",
        );
        fixture
    }

    pub fn write(&self, relative: &str, content: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    /// Writes below the data directory.
    pub fn write_data(&self, relative: &str, content: &str) {
        let path = self.home.file(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    /// Puts the data directory below a regular file, so nothing can be installed there.
    pub fn break_hook(&mut self) {
        let blocker = self.root.join("blocker");
        fs::write(&blocker, "x").unwrap();
        self.home.root = blocker.join("below");
    }

    pub fn executable(&self, relative: &str) {
        self.write(relative, "#!/bin/sh\n");
        let path = self.root.join(relative);
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    pub fn remove(&self, relative: &str) {
        let path = self.root.join(relative);
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }

    pub fn set_env(&mut self, key: &str, value: &str) {
        self.sys.env.insert(key.to_string(), value.to_string());
    }

    pub fn detection(mode: GameMode) -> Detection {
        Detection {
            mode,
            note: "test fixture.".into(),
        }
    }

    pub fn report_in(&self, mode: GameMode) -> Report {
        checks::run_all(
            &self.sys,
            &self.home,
            RuntimeMode::Auto,
            &Self::detection(mode),
        )
    }

    pub fn report(&self) -> Report {
        self.report_in(GameMode::Artifact)
    }
}

pub fn titles(report: &Report) -> Vec<&'static str> {
    report.checks.iter().map(|check| check.title).collect()
}
