use std::path::Path;

use crate::checks::Report;
use crate::home::Home;
use crate::hook;
use crate::runtime::RuntimeState;
use crate::sys::Sys;
use crate::wrapper;

/// Launch options written for the old wrappers start with these.
const OLD_WRAPPERS: [&str; 4] = ["linuwux", "avx-runtime", "lutris-avx2", "lutris_avx2.py"];

/// The program to run with its environment, ready for exec.
#[derive(Debug)]
pub struct Launch {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Remarks for the user, printed before the program starts.
    pub notes: Vec<String>,
}

fn base_name(argument: &str) -> &str {
    Path::new(argument)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(argument)
}

/// Drops the old wrappers (`linuwux avx-runtime [--steam] [--]`) from the front, because this program now does their jobs.
pub fn normalize_command(command: &[String]) -> Vec<String> {
    let mut rest = command;
    let mut stripped = false;
    while let Some(first) = rest.first() {
        let name = base_name(first);
        if OLD_WRAPPERS.contains(&name) {
            stripped = true;
        } else if !(stripped && (first == "--steam" || first == "--")) {
            break;
        }
        rest = &rest[1..];
    }
    rest.to_vec()
}

/// Lutris starts the game through umu-run; anything else is Steam's expanded %command%.
/// Words in front of umu-run (Faugus's `gamemoderun` and `mangohud`) stay in the command, so they
/// still wrap it inside the namespace.
pub fn is_lutris(command: &[String]) -> bool {
    command.iter().any(|word| base_name(word) == "umu-run")
}

pub fn build(
    sys: &Sys,
    home: &Home,
    report: &Report,
    command: &[String],
) -> Result<Launch, String> {
    let library = hook::resolve(sys, home).map_err(|missing| missing.detail)?;
    let preload =
        hook::compose_preload(sys.env("LD_PRELOAD"), &library.path, base_name(&command[0]));
    let mut env = vec![("LD_PRELOAD".to_string(), preload)];
    if report.plan.artifact_path && sys.env("PINGU_HOOK_PATH").is_none() {
        env.push(("PINGU_HOOK_PATH".into(), "artifact".into()));
    }
    let mut notes: Vec<String> = library.warning.into_iter().collect();

    if !report.plan.policy {
        return Ok(Launch {
            program: command[0].clone(),
            args: command[1..].to_vec(),
            env,
            notes,
        });
    }

    if let Some(runtime) = &report.runtime {
        if sys.env("AVX2_GPU").is_none() {
            env.push(("AVX2_GPU".into(), runtime.gpu.clone()));
        }
        if matches!(runtime.state, RuntimeState::NotRequired(_))
            && sys.env("AVX2_RUNTIME").is_none()
        {
            env.push(("AVX2_RUNTIME".into(), "none".into()));
        }
        if let RuntimeState::Outdated { reason, .. } = &runtime.state {
            notes.push(format!(
                "The private runtime is outdated: {reason} Run the launcher without a command to upgrade it."
            ));
        }
    }
    let prepared = wrapper::plan(sys, home, report.runtime.as_ref(), command)?;
    env.extend(prepared.env);
    if !prepared.note.is_empty() {
        notes.push(prepared.note);
    }
    Ok(Launch {
        program: prepared.program,
        args: prepared.args,
        env,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn old_launch_options_lose_their_wrapper_prefix() {
        assert_eq!(
            normalize_command(&words(&[
                "linuwux",
                "/p/build/avx-runtime",
                "--steam",
                "--",
                "reaper",
                "--",
                "x"
            ])),
            words(&["reaper", "--", "x"])
        );
        assert_eq!(
            normalize_command(&words(&["/home/u/.local/bin/linuwux", "umu-run", "g.exe"])),
            words(&["umu-run", "g.exe"])
        );
    }

    #[test]
    fn plain_commands_are_left_alone() {
        let command = words(&["--steam-like-game", "--", "x"]);
        assert_eq!(normalize_command(&command), command);
        assert!(normalize_command(&[]).is_empty());
    }

    #[test]
    fn umu_run_means_lutris() {
        assert!(is_lutris(&words(&["/usr/bin/umu-run", "g.exe"])));
        assert!(is_lutris(&words(&[
            "gamemoderun",
            "/usr/bin/mangohud",
            "umu-run",
            "g.exe"
        ])));
        assert!(!is_lutris(&words(&["mangohud", "reaper", "SteamLaunch"])));
        assert!(!is_lutris(&words(&["gamemoderun"])));
        assert!(!is_lutris(&words(&["reaper", "SteamLaunch"])));
    }
}
