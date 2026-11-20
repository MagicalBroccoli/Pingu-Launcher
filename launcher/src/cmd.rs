//! Running helper programs with a timeout that a second thread can cut short.

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Lets another thread stop the program that is currently running.
#[derive(Default)]
pub struct Cancel {
    cancelled: AtomicBool,
    pid: AtomicI32,
}

impl Cancel {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let pid = self.pid.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: the child leads its own process group, so this only signals it and its helpers.
            unsafe { libc::kill(-pid, libc::SIGTERM) };
        }
    }
}

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }
}

fn read_all(source: Option<impl Read>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(mut source) = source {
        let _ = source.read_to_end(&mut bytes);
    }
    bytes
}

fn terminate(pid: i32) {
    // SAFETY: signals the process group the child leads.
    unsafe { libc::kill(-pid, libc::SIGTERM) };
}

fn kill(pid: i32) {
    // SAFETY: signals the process group the child leads.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
}

/// Runs `command` to completion; stdin is closed and both output streams are captured.
pub fn run(
    command: &mut Command,
    timeout: Duration,
    cancel: Option<&Cancel>,
) -> Result<Output, String> {
    if cancel.is_some_and(Cancel::is_cancelled) {
        return Err("Cancelled".into());
    }
    let program = command.get_program().to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| format!("Cannot start {program}: {error}"))?;
    let pid = child.id() as i32;
    if let Some(cancel) = cancel {
        cancel.pid.store(pid, Ordering::SeqCst);
        // A cancel that arrived between the check and the spawn.
        if cancel.is_cancelled() {
            terminate(pid);
        }
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let started = Instant::now();

    let (status, out, err, timed_out) = std::thread::scope(|scope| {
        let out = scope.spawn(|| read_all(stdout));
        let err = scope.spawn(|| read_all(stderr));
        let mut timed_out = false;
        let mut signalled_at: Option<Instant> = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(_) => break None,
            }
            let stop = cancel.is_some_and(Cancel::is_cancelled) || started.elapsed() > timeout;
            if stop && signalled_at.is_none() {
                timed_out = !cancel.is_some_and(Cancel::is_cancelled);
                terminate(pid);
                signalled_at = Some(Instant::now());
            }
            if signalled_at.is_some_and(|at| at.elapsed() > Duration::from_secs(2)) {
                kill(pid);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // Helpers that outlive a stopped program would keep the pipes open.
        if signalled_at.is_some() {
            kill(pid);
        }
        (
            status,
            out.join().unwrap_or_default(),
            err.join().unwrap_or_default(),
            timed_out,
        )
    });
    if let Some(cancel) = cancel {
        cancel.pid.store(0, Ordering::SeqCst);
        if cancel.is_cancelled() {
            return Err("Cancelled".into());
        }
    }
    if timed_out {
        return Err(format!("{program} timed out after {}s", timeout.as_secs()));
    }
    let status = status.ok_or_else(|| format!("Cannot wait for {program}"))?;
    Ok(Output {
        status,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    })
}

/// Like [`run`], but a non-zero exit becomes an error carrying the program's stderr.
pub fn run_checked(
    command: &mut Command,
    timeout: Duration,
    cancel: Option<&Cancel>,
) -> Result<Output, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let output = run(command, timeout, cancel)?;
    if output.success() {
        return Ok(output);
    }
    let detail = output.stderr.trim();
    Err(if detail.is_empty() {
        format!("{program} failed ({})", output.status)
    } else {
        format!("{program} failed ({}): {detail}", output.status)
    })
}

fn pump(source: Option<impl Read>, on_line: &(dyn Fn(&str) + Sync)) {
    let Some(source) = source else { return };
    for line in BufReader::new(source).split(b'\n') {
        let Ok(bytes) = line else { break };
        on_line(String::from_utf8_lossy(&bytes).trim_end_matches('\r'));
    }
}

/// Runs `command` with stdin closed and hands every line of stdout and stderr to `on_line` as it appears.
pub fn stream(
    command: &mut Command,
    on_line: &(dyn Fn(&str) + Sync),
) -> Result<ExitStatus, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Cannot start {program}: {error}"))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    std::thread::scope(|scope| {
        scope.spawn(|| pump(stdout, on_line));
        scope.spawn(|| pump(stderr, on_line));
        child
            .wait()
            .map_err(|error| format!("Cannot wait for {program}: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn streamed_lines_arrive_from_both_streams() {
        let lines = std::sync::Mutex::new(Vec::new());
        let status = stream(
            Command::new("sh").args(["-c", "echo out; echo err >&2; printf 'last\\r\\n'; exit 4"]),
            &|line| lines.lock().unwrap().push(line.to_string()),
        )
        .unwrap();
        assert_eq!(status.code(), Some(4));
        let mut lines = lines.into_inner().unwrap();
        lines.sort();
        assert_eq!(lines, ["err", "last", "out"]);
        assert!(stream(&mut Command::new("/nonexistent/program"), &|_| {}).is_err());
    }

    #[test]
    fn captures_output_and_status() {
        let output = run(
            Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
            Duration::from_secs(10),
            None,
        )
        .unwrap();
        assert_eq!(output.stdout, "out\n");
        assert_eq!(output.stderr, "err\n");
        assert_eq!(output.status.code(), Some(3));
        let error = run_checked(
            Command::new("sh").args(["-c", "echo bad >&2; exit 1"]),
            Duration::from_secs(10),
            None,
        )
        .unwrap_err();
        assert!(error.contains("bad"), "{error}");
    }

    #[test]
    fn timeout_stops_the_program() {
        let started = Instant::now();
        let error = run(
            Command::new("sh").args(["-c", "sleep 30"]),
            Duration::from_millis(200),
            None,
        )
        .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn cancel_stops_the_program() {
        let cancel = Arc::new(Cancel::default());
        let worker = {
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                run(
                    Command::new("sh").args(["-c", "sleep 30"]),
                    Duration::from_secs(60),
                    Some(&cancel),
                )
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        cancel.cancel();
        assert_eq!(worker.join().unwrap().err(), Some("Cancelled".to_string()));
    }

    #[test]
    fn a_missing_program_is_reported() {
        let error = run(
            &mut Command::new("/nonexistent/program"),
            Duration::from_secs(1),
            None,
        )
        .unwrap_err();
        assert!(error.contains("Cannot start"), "{error}");
    }
}
