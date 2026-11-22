//! The command line tools: runtime maintenance, module sources, the native self test.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::assets;
use crate::builder::{self, Builder, inspect_libraries};
use crate::cli::Tool;
use crate::cmd::{self, Cancel};
use crate::home::Home;
use crate::install::{self, Module};
use crate::runtime::{self, Provision, load_lock};
use crate::sys::Sys;
use crate::wrapper;

fn host_glibc(sys: &Sys) -> Result<String, String> {
    runtime::installed_glibc(sys)
        .map(|(version, _)| version)
        .ok_or_else(|| {
            "The installed glibc version could not be read from the pacman database.".into()
        })
}

fn gpu_or_detected(sys: &Sys, gpu: Option<String>) -> Result<String, String> {
    let gpu = gpu.unwrap_or_else(|| runtime::detect_gpu(sys));
    if runtime::GPUS.contains(&gpu.as_str()) {
        Ok(gpu)
    } else {
        Err(format!("--gpu must be nvidia, amd or intel, not {gpu}"))
    }
}

fn progress(line: &str) {
    eprintln!("{line}");
}

pub fn run(sys: &Sys, home: &Home, tool: Tool) -> Result<(), String> {
    let cancel = Cancel::default();
    match tool {
        Tool::Provision { gpu } => {
            let gpu = gpu_or_detected(sys, gpu)?;
            let glibc = host_glibc(sys)?;
            Provision::new().run(home, &gpu, &glibc, &progress)?;
            println!("The {gpu} runtime is selected.");
            Ok(())
        }
        Tool::Build { gpu, offline, work } => {
            let gpu = gpu_or_detected(sys, gpu)?;
            let lock = load_lock(home, &gpu)?;
            let builder = Builder::new(
                work.unwrap_or_else(|| home.builder_work()),
                home.generations(),
                &cancel,
                &progress,
            );
            let generation = builder
                .build_runtime(&lock, offline)
                .map_err(|failure| failure.to_string())?;
            println!("{}", generation.display());
            Ok(())
        }
        Tool::Update {
            gpu,
            mirror,
            add,
            work,
        } => {
            let gpu = gpu_or_detected(sys, gpu)?;
            let builder = Builder::new(
                work.unwrap_or_else(|| home.builder_work()),
                home.generations(),
                &cancel,
                &progress,
            );
            let mirror = mirror.unwrap_or_else(|| builder::DEFAULT_MIRROR.to_string());
            let generation = builder.update(&gpu, &mirror, &add, &home.lock_override(&gpu))?;
            println!("{}", generation.display());
            Ok(())
        }
        Tool::Select { generation } => {
            let glibc = host_glibc(sys)?;
            let builder = Builder::new(home.builder_work(), home.generations(), &cancel, &progress);
            println!("{}", builder.select(&generation, &glibc)?.display());
            Ok(())
        }
        Tool::Audit { path } => {
            let root = std::fs::canonicalize(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let audit = inspect_libraries(&root).map_err(|failure| failure.to_string())?;
            println!(
                "Audited {} ELF libraries; all DT_NEEDED names have matching-architecture providers",
                audit.elf_libraries.len()
            );
            Ok(())
        }
        Tool::ExportModule { destination } => {
            let written = assets::export_module(&destination)?;
            println!(
                "Wrote {} files of pingu-policy {} to {}",
                written.len(),
                assets::module_version(),
                destination.display()
            );
            Ok(())
        }
        Tool::InstallModule => {
            // Root's own helper directory, so a sudo run does not leave root-owned files in a user's home.
            let home = Home {
                root: sys.path("/var/lib/pingu-runtime"),
            };
            install::run(sys, &home, Module::Policy)
        }
        Tool::RebuildModule => install::rebuild(sys, Module::Policy),
        Tool::UninstallModules => install::uninstall(sys),
        Tool::Prepare { proton } => {
            let helper = home.bin().join("avx2-run");
            assets::install(&helper, assets::AVX2_RUN, 0o755)
                .map_err(|error| format!("{}: {error}", helper.display()))?;
            let companion = wrapper::prepare_tool(&proton, &helper, &home.companions())?;
            println!("{}", companion.display());
            Ok(())
        }
        Tool::Notify { title, text } => crate::ui::notify(&title, &text),
        Tool::Selftest => selftest(sys, home),
    }
}

fn step(name: &str, command: &mut Command) -> Result<(), String> {
    let output = cmd::run(command, Duration::from_secs(120), None)?;
    if output.success() {
        println!("PASS {name}");
        return Ok(());
    }
    println!("FAIL {name}");
    print!("{}{}", output.stdout, output.stderr);
    Err(format!("{name} failed ({})", output.status))
}

/// The native checks of the loaded module: unrestricted before, XCR0 exactly 7 under the policy.
pub(crate) fn selftest(sys: &Sys, home: &Home) -> Result<(), String> {
    let ready = sys
        .read("/sys/module/pingu_policy/parameters/ready")
        .is_some_and(|text| text.trim() == "Y");
    if !ready {
        return Err("The pingu_policy module is not loaded and ready.".into());
    }
    let bin = home.bin();
    let run = bin.join("avx2-run");
    let probe = bin.join("xstate-probe");
    let policy = bin.join("policy-test");
    for (path, data) in [
        (&run, assets::AVX2_RUN),
        (&probe, assets::XSTATE_PROBE),
        (&policy, assets::POLICY_TEST),
    ] {
        assets::install(path, data, 0o755)
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    let restricted = |program: &Path| {
        let mut command = Command::new(&run);
        command.env("AVX2_POLICY", "xcr0-only").arg(program);
        command
    };
    step(
        "unrestricted XCR0",
        Command::new(&probe).arg("--expect=avx512"),
    )?;
    step(
        "restricted XCR0",
        restricted(&probe).arg("--expect=xcr0-only"),
    )?;
    step(
        "restricted XCR0 under the module test",
        restricted(&policy)
            .env("AVX2_MODULE_PROBE", "1")
            .arg("--restricted-xcr0-native")
            .arg(&probe),
    )?;
    step(
        "unrestricted XCR0 afterwards",
        Command::new(&probe).arg("--expect=avx512"),
    )?;
    println!("The module passes the native self test.");
    Ok(())
}
