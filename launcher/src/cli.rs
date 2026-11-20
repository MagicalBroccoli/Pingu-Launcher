use std::path::PathBuf;

use crate::mode::ModeSetting;
use crate::runtime::RuntimeMode;

pub const USAGE: &str = "\
Usage: pingu-launcher [OPTIONS] [--] COMMAND [ARGS...]
       pingu-launcher [OPTIONS] TOOL ...

Checks that the machine is ready for the game, sets up the pingu-hook preload and
runs COMMAND. If something is missing, a window explains what to fix.

The game directory is scanned for artifact.dll. Found means Artifact mode,
otherwise Legacy mode. Without a COMMAND nothing is scanned and Artifact mode is
assumed. Legacy mode needs UMIP off, CPUID faulting and the hook.
Artifact mode needs the same and, when the native XCR0 is not 7, also FRED and
IBT off, the pingu_policy module and (on AVX-512 optimized hosts) the private
runtime. The restriction is applied by wrapping COMMAND (Lutris's umu-run or
Steam's expanded %command%) in a companion Proton.

Options:
  --check              Print the check results and exit (0 when everything is ready)
  --ui                 Show the window even when everything is ready (the default
                       when no COMMAND is given)
  --mode MODE          auto (default), artifact or legacy: skip the artifact.dll scan
  --data-dir DIR       Data directory (default: $PINGU_RUNTIME_DIR, then
                       $XDG_DATA_HOME/pingu-runtime, then ~/.local/share/pingu-runtime)
  --runtime MODE       auto (default), always or never: whether the private runtime is required
  -h, --help           Show this help

Tools:
  runtime provision [--gpu GPU]
                       Generate or upgrade the private runtime and select it
  runtime build [--gpu GPU] [--offline] [--work DIR]
                       Rebuild exactly the locked package set
  runtime update [--gpu GPU] [--mirror URL] [--add PACKAGE]... [--work DIR]
                       Resolve current packages, build and record the new lock
  runtime select GENERATION
                       Select a generation through its <gpu>-current link
  runtime audit PATH   Recheck the library closure of a generation
  module export DIR    Write the pingu-policy DKMS sources to DIR
  module export-cpuid DIR
                       Write the cpuid_fault_emulation DKMS sources to DIR
  module install       Install, test and load pingu-policy through DKMS (needs root)
  module install-cpuid Install and load cpuid_fault_emulation through DKMS (needs root)
  module uninstall     Remove the installed modules and their loading at boot (needs root)
  selftest             Run the native module test (needs the loaded module)
  prepare PROTON_DIR   Print the companion Proton the wrapper would use

Use it as a command prefix, for example in Lutris:
  pingu-launcher

Setting AVX2_POLICY=0 turns the XCR0 restriction off.";

#[derive(Debug, Default)]
pub struct Options {
    pub check: bool,
    pub force_ui: bool,
    pub mode: ModeSetting,
    pub data_dir: Option<PathBuf>,
    pub runtime: RuntimeMode,
    pub command: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Tool {
    Provision {
        gpu: Option<String>,
    },
    Build {
        gpu: Option<String>,
        offline: bool,
        work: Option<PathBuf>,
    },
    Update {
        gpu: Option<String>,
        mirror: Option<String>,
        add: Vec<String>,
        work: Option<PathBuf>,
    },
    Select {
        generation: PathBuf,
    },
    Audit {
        path: PathBuf,
    },
    ExportModule {
        destination: PathBuf,
    },
    ExportCpuidModule {
        destination: PathBuf,
    },
    InstallModule {
        cpuid: bool,
    },
    UninstallModules,
    Selftest,
    Prepare {
        proton: PathBuf,
    },
}

#[derive(Debug)]
pub enum Parsed {
    Run(Options),
    Tool {
        data_dir: Option<PathBuf>,
        tool: Tool,
    },
    Help,
    Error(String),
}

fn parse_tool(name: &str, args: Vec<String>) -> Result<Tool, String> {
    let mut args = args.into_iter();
    let mut gpu = None;
    let mut work = None;
    let mut mirror = None;
    let mut offline = false;
    let mut add = Vec::new();
    let mut positional = Vec::new();
    let subcommand = match name {
        "runtime" => args
            .next()
            .ok_or("runtime needs provision, build, update, select or audit")?,
        "module" => args.next().ok_or("module needs export")?,
        other => other.to_string(),
    };
    while let Some(arg) = args.next() {
        let mut value = |what: &str| args.next().ok_or_else(|| format!("{what} needs a value"));
        match arg.as_str() {
            "--gpu" => gpu = Some(value("--gpu")?),
            "--work" => work = Some(PathBuf::from(value("--work")?)),
            "--mirror" => mirror = Some(value("--mirror")?),
            "--add" => add.push(value("--add")?),
            "--offline" => offline = true,
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            _ => positional.push(arg),
        }
    }
    let one = |what: &str, positional: Vec<String>| -> Result<PathBuf, String> {
        match <[String; 1]>::try_from(positional) {
            Ok([value]) => Ok(PathBuf::from(value)),
            Err(_) => Err(format!("{what} needs exactly one argument")),
        }
    };
    let none = |positional: &[String]| {
        if positional.is_empty() {
            Ok(())
        } else {
            Err(format!("{subcommand} takes no arguments"))
        }
    };
    match (name, subcommand.as_str()) {
        ("runtime", "provision") => {
            none(&positional)?;
            Ok(Tool::Provision { gpu })
        }
        ("runtime", "build") => {
            none(&positional)?;
            Ok(Tool::Build { gpu, offline, work })
        }
        ("runtime", "update") => {
            none(&positional)?;
            Ok(Tool::Update {
                gpu,
                mirror,
                add,
                work,
            })
        }
        ("runtime", "select") => Ok(Tool::Select {
            generation: one("runtime select", positional)?,
        }),
        ("runtime", "audit") => Ok(Tool::Audit {
            path: one("runtime audit", positional)?,
        }),
        ("module", "export") => Ok(Tool::ExportModule {
            destination: one("module export", positional)?,
        }),
        ("module", "export-cpuid") => Ok(Tool::ExportCpuidModule {
            destination: one("module export-cpuid", positional)?,
        }),
        ("module", "install") => {
            none(&positional)?;
            Ok(Tool::InstallModule { cpuid: false })
        }
        ("module", "install-cpuid") => {
            none(&positional)?;
            Ok(Tool::InstallModule { cpuid: true })
        }
        ("module", "uninstall") => {
            none(&positional)?;
            Ok(Tool::UninstallModules)
        }
        ("selftest", _) => {
            none(&positional)?;
            Ok(Tool::Selftest)
        }
        ("prepare", _) => Ok(Tool::Prepare {
            proton: one("prepare", positional)?,
        }),
        ("runtime", other) => Err(format!("unknown runtime tool {other}")),
        ("module", other) => Err(format!("unknown module tool {other}")),
        (other, _) => Err(format!("unknown tool {other}")),
    }
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Parsed {
    let mut args = args.into_iter();
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--check" => options.check = true,
            "--ui" => options.force_ui = true,
            "-h" | "--help" => return Parsed::Help,
            "--data-dir" => match args.next() {
                Some(value) => options.data_dir = Some(PathBuf::from(value)),
                None => return Parsed::Error("--data-dir needs a value".into()),
            },
            "--runtime" => match args.next().map(|value| value.parse()) {
                Some(Ok(mode)) => options.runtime = mode,
                Some(Err(error)) => return Parsed::Error(error),
                None => return Parsed::Error("--runtime needs a value".into()),
            },
            "--mode" => match args.next().map(|value| value.parse()) {
                Some(Ok(mode)) => options.mode = mode,
                Some(Err(error)) => return Parsed::Error(error),
                None => return Parsed::Error("--mode needs a value".into()),
            },
            "--" => {
                options.command.extend(args);
                break;
            }
            other if other.starts_with("--data-dir=") => {
                options.data_dir = Some(PathBuf::from(&other["--data-dir=".len()..]));
            }
            other if other.starts_with("--runtime=") => match other["--runtime=".len()..].parse() {
                Ok(mode) => options.runtime = mode,
                Err(error) => return Parsed::Error(error),
            },
            other if other.starts_with("--mode=") => match other["--mode=".len()..].parse() {
                Ok(mode) => options.mode = mode,
                Err(error) => return Parsed::Error(error),
            },
            other if other.starts_with('-') && other.len() > 1 => {
                return Parsed::Error(format!("unknown option {other}"));
            }
            "runtime" | "module" | "selftest" | "prepare" => {
                return match parse_tool(&arg, args.collect()) {
                    Ok(tool) => Parsed::Tool {
                        data_dir: options.data_dir,
                        tool,
                    },
                    Err(error) => Parsed::Error(error),
                };
            }
            _ => {
                options.command.push(arg);
                options.command.extend(args);
                break;
            }
        }
    }
    Parsed::Run(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    fn run(args: &[&str]) -> Options {
        match parse(words(args)) {
            Parsed::Run(options) => options,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn tool(args: &[&str]) -> Tool {
        match parse(words(args)) {
            Parsed::Tool { tool, .. } => tool,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn command_starts_at_first_positional_and_keeps_its_flags() {
        let options = run(&["--ui", "umu-run", "--steam", "--", "%command%"]);
        assert!(options.force_ui);
        assert_eq!(options.command, ["umu-run", "--steam", "--", "%command%"]);
    }

    #[test]
    fn double_dash_ends_options() {
        let options = run(&["--check", "--", "--odd-program"]);
        assert!(options.check);
        assert_eq!(options.command, ["--odd-program"]);
        let options = run(&["--", "runtime", "x"]);
        assert_eq!(options.command, ["runtime", "x"]);
    }

    #[test]
    fn value_options_accept_both_forms() {
        let options = run(&["--data-dir=/a", "--runtime", "never"]);
        assert_eq!(options.data_dir, Some(PathBuf::from("/a")));
        assert_eq!(options.runtime, RuntimeMode::Never);
    }

    #[test]
    fn rejects_unknown_options_and_bad_modes() {
        assert!(matches!(parse(words(&["--nope"])), Parsed::Error(_)));
        assert!(matches!(
            parse(words(&["--runtime=maybe"])),
            Parsed::Error(_)
        ));
        assert!(matches!(parse(words(&["--runtime"])), Parsed::Error(_)));
        assert!(matches!(
            parse(words(&["--project-dir", "x"])),
            Parsed::Error(_)
        ));
    }

    #[test]
    fn runtime_tools_are_parsed() {
        assert_eq!(
            tool(&["runtime", "provision", "--gpu", "amd"]),
            Tool::Provision {
                gpu: Some("amd".into())
            }
        );
        assert_eq!(
            tool(&["runtime", "build", "--offline", "--work", "/w"]),
            Tool::Build {
                gpu: None,
                offline: true,
                work: Some("/w".into())
            }
        );
        assert_eq!(
            tool(&[
                "runtime",
                "update",
                "--add",
                "libpulse",
                "--add",
                "lib32-libpulse",
                "--mirror",
                "https://m"
            ]),
            Tool::Update {
                gpu: None,
                mirror: Some("https://m".into()),
                add: words(&["libpulse", "lib32-libpulse"]),
                work: None,
            }
        );
        assert_eq!(
            tool(&["runtime", "select", "/g"]),
            Tool::Select {
                generation: "/g".into()
            }
        );
        assert_eq!(
            tool(&["runtime", "audit", "/g"]),
            Tool::Audit { path: "/g".into() }
        );
    }

    #[test]
    fn other_tools_and_their_errors() {
        assert_eq!(
            tool(&["module", "export", "/d"]),
            Tool::ExportModule {
                destination: "/d".into()
            }
        );
        assert_eq!(
            tool(&["module", "export-cpuid", "/d"]),
            Tool::ExportCpuidModule {
                destination: "/d".into()
            }
        );
        assert_eq!(
            tool(&["module", "install"]),
            Tool::InstallModule { cpuid: false }
        );
        assert_eq!(tool(&["module", "uninstall"]), Tool::UninstallModules);
        assert_eq!(
            tool(&["module", "install-cpuid"]),
            Tool::InstallModule { cpuid: true }
        );
        assert_eq!(tool(&["selftest"]), Tool::Selftest);
        assert_eq!(
            tool(&["prepare", "/p"]),
            Tool::Prepare {
                proton: "/p".into()
            }
        );
        for bad in [
            &["runtime"][..],
            &["runtime", "nope"],
            &["runtime", "select"],
            &["runtime", "provision", "extra"],
            &["module", "import", "/d"],
            &["selftest", "x"],
            &["prepare"],
            &["runtime", "update", "--gpu"],
        ] {
            assert!(matches!(parse(words(bad)), Parsed::Error(_)), "{bad:?}");
        }
    }

    #[test]
    fn the_data_directory_flag_applies_to_tools() {
        match parse(words(&["--data-dir", "/x", "selftest"])) {
            Parsed::Tool { data_dir, .. } => assert_eq!(data_dir, Some(PathBuf::from("/x"))),
            other => panic!("unexpected {other:?}"),
        }
    }
}
