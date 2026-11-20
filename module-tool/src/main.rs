//! Static helper for the pingu-policy DKMS build: plans the kernel patches and runs the VM gate.
mod decode;
mod image;
mod profile;
mod vm;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Flags that stand alone instead of taking a value.
const BOOLEAN_FLAGS: [&str; 1] = ["optional"];

struct Args {
    values: Vec<(String, String)>,
}

impl Args {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut iterator = arguments.iter();
        while let Some(argument) = iterator.next() {
            let Some(flag) = argument.strip_prefix("--") else {
                return Err(format!("unexpected argument {argument}"));
            };
            if let Some((name, value)) = flag.split_once('=') {
                values.push((name.to_string(), value.to_string()));
            } else if BOOLEAN_FLAGS.contains(&flag) {
                values.push((flag.to_string(), "true".to_string()));
            } else {
                let value = iterator
                    .next()
                    .ok_or_else(|| format!("--{flag} needs a value"))?;
                values.push((flag.to_string(), value.clone()));
            }
        }
        Ok(Self { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        self.get(name).map(PathBuf::from)
    }

    fn required(&self, name: &str) -> Result<PathBuf, String> {
        self.path(name)
            .ok_or_else(|| format!("--{name} is required"))
    }
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn run_profile(args: &Args) -> ExitCode {
    let output = args.path("output");
    let metadata = args.path("metadata");
    let result = (|| {
        let headers = absolute(&args.required("headers")?);
        let package = args.required("package")?;
        let output = output.clone().ok_or("--output is required")?;
        let metadata = metadata.clone().ok_or("--metadata is required")?;
        let image = args.path("image");
        let system_map = args.path("system-map");
        let kernel_source = args.path("kernel-source");
        let approvals = args.path("approvals");
        let source = args.get("source").unwrap_or("auto");
        if !["auto", "vmlinux", "image"].contains(&source) {
            return Err("--source must be auto, vmlinux or image".to_string());
        }
        profile::generate(
            &profile::Inputs {
                headers: &headers,
                image: image.as_deref(),
                system_map: system_map.as_deref(),
                source,
                kernel_source: kernel_source.as_deref(),
            },
            &package,
            approvals.as_deref(),
            &profile::Outputs {
                output: &output,
                metadata: &metadata,
            },
        )
    })();
    match result {
        Ok(profile) => {
            let state = if profile.vm_validated == Some(true) {
                "VM-validated"
            } else {
                "static compatibility checks passed"
            };
            println!(
                "Profile generated: {} {} ({state})",
                profile.release, profile.build_id
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            for path in [&output, &metadata].into_iter().flatten() {
                let _ = std::fs::remove_file(path);
            }
            eprintln!("Profile rejected: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_validate(args: &Args) -> ExitCode {
    let result = (|| {
        let package = absolute(&args.required("package")?);
        let headers = absolute(&args.required("headers")?);
        let release = args
            .get("kernel-release")
            .ok_or("--kernel-release is required")?;
        vm::validate(&package, &headers, release, args.get("optional").is_some())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("DKMS VM VALIDATION FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_prepare(args: &Args) -> ExitCode {
    let result = (|| {
        vm::prepare(
            &absolute(&args.required("package")?),
            &absolute(&args.required("fixtures")?),
        )
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("DKMS VM VALIDATION FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = arguments.split_first() else {
        eprintln!("usage: pingu-module-tool profile|validate|prepare ...");
        return ExitCode::from(2);
    };
    let args = match Args::parse(rest) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    match command.as_str() {
        "profile" => run_profile(&args),
        "validate" => run_validate(&args),
        "prepare" => run_prepare(&args),
        other => {
            eprintln!("unknown command {other}");
            ExitCode::from(2)
        }
    }
}
