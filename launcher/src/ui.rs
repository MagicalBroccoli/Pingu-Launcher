use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use slint::{ComponentHandle, ModelRc, VecModel};

use crate::checks::{self, Action, Check, Report, Status};
use crate::home::Home;
use crate::install;
use crate::mode::Detection;
use crate::runtime::{Provision, RuntimeMode};
use crate::sys::Sys;

slint::include_modules!();

const LOG_LINES: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Launch,
    Quit { ok: bool },
}

fn level(status: Status) -> CheckLevel {
    match status {
        Status::Ok => CheckLevel::Ok,
        Status::Problem => CheckLevel::Problem,
    }
}

fn item(check: &Check) -> CheckItem {
    CheckItem {
        title: check.title.into(),
        level: level(check.status),
        detail: check.detail.as_str().into(),
        fix: check.fix.as_str().into(),
        warning: check.warning.as_str().into(),
        action: check.action_label.into(),
        action_id: check.action.map_or("", Action::id).into(),
    }
}

/// Copies a report into the window's properties.
pub fn apply_report(ui: &MainWindow, report: &Report) {
    let items: Vec<CheckItem> = report.checks.iter().map(item).collect();
    ui.set_checks(ModelRc::new(VecModel::from(items)));
    ui.set_mode_text(report.plan.describe().into());
    ui.set_report_text(checks::render_text(report).into());

    ui.set_has_runtime(report.runtime.is_some());
    ui.set_has_installation(report.installed);
    if let Some(info) = &report.runtime {
        let runtime = info.as_check();
        let action = info.action();
        ui.set_runtime_level(level(runtime.status));
        let detail = if runtime.warning.is_empty() {
            runtime.detail
        } else {
            format!("{}\n{}", runtime.detail, runtime.warning)
        };
        ui.set_runtime_detail(detail.into());
        // Manual steps are only shown when the window cannot do the work itself.
        let manual = if action.is_none() && runtime.status == Status::Problem {
            runtime.fix
        } else {
            String::new()
        };
        ui.set_runtime_fix(manual.into());
        ui.set_runtime_action(action.map(|action| action.label()).unwrap_or("").into());
        ui.set_runtime_can_regenerate(info.can_regenerate());
        ui.set_runtime_gpu(info.gpu.as_str().into());
        ui.set_host_glibc(info.host_glibc.clone().unwrap_or_default().into());
    }

    let problems = report.problem_count();
    ui.set_all_ok(problems == 0);
    if problems == 0 {
        ui.set_headline("Ready to play".into());
        ui.set_subline("Every requirement for this game is met.".into());
    } else {
        let noun = if problems == 1 {
            "requirement needs"
        } else {
            "requirements need"
        };
        ui.set_headline(format!("{problems} {noun} attention").into());
        ui.set_subline(
            "Follow the steps below, then check again. Kernel and boot changes need a reboot."
                .into(),
        );
    }
}

/// A sink for output lines that shows the last few in the window's action log.
fn action_log(weak: &slint::Weak<MainWindow>) -> impl Fn(&str) + Sync + use<> {
    let tail = Mutex::new((VecDeque::new(), weak.clone()));
    move |line: &str| {
        let Ok(mut guard) = tail.lock() else { return };
        if guard.0.len() == LOG_LINES {
            guard.0.pop_front();
        }
        guard.0.push_back(line.to_string());
        let text = guard.0.iter().cloned().collect::<Vec<_>>().join("\n");
        let _ = guard
            .1
            .upgrade_in_event_loop(move |ui| ui.set_action_log(text.into()));
    }
}

pub fn run(
    sys: Sys,
    home: Home,
    mode: RuntimeMode,
    detection: Detection,
    has_command: bool,
) -> Result<Outcome, String> {
    let ui = MainWindow::new().map_err(|error| error.to_string())?;
    ui.set_has_command(has_command);
    apply_report(&ui, &checks::run_all(&sys, &home, mode, &detection));

    let provision = Provision::new();
    let launched = Arc::new(Mutex::new(false));

    ui.on_recheck({
        let weak = ui.as_weak();
        let (sys, home, detection) = (sys.clone(), home.clone(), detection.clone());
        move || {
            if let Some(ui) = weak.upgrade() {
                apply_report(&ui, &checks::run_all(&sys, &home, mode, &detection));
            }
        }
    });

    for replace in [false, true] {
        let weak = ui.as_weak();
        let provision = provision.clone();
        let (sys, home, detection) = (sys.clone(), home.clone(), detection.clone());
        let handler = move || {
            let Some(ui) = weak.upgrade() else { return };
            if ui.get_busy() {
                return;
            }
            let gpu = ui.get_runtime_gpu().to_string();
            let host = ui.get_host_glibc().to_string();
            ui.set_busy(true);
            ui.set_provisioning(true);
            ui.set_log_failed(false);
            ui.set_log("Starting...".into());

            let (weak, provision) = (weak.clone(), provision.clone());
            let (sys, home, detection) = (sys.clone(), home.clone(), detection.clone());
            std::thread::spawn(move || {
                let tail = Mutex::new((VecDeque::new(), weak.clone()));
                let log = |line: &str| {
                    let Ok(mut guard) = tail.lock() else { return };
                    if guard.0.len() == LOG_LINES {
                        guard.0.pop_front();
                    }
                    guard.0.push_back(line.to_string());
                    let text = guard.0.iter().cloned().collect::<Vec<_>>().join("\n");
                    let _ = guard
                        .1
                        .upgrade_in_event_loop(move |ui| ui.set_log(text.into()));
                };
                let result = if replace {
                    provision.regenerate(&home, &gpu, &host, &log)
                } else {
                    provision.run(&home, &gpu, &host, &log)
                };
                let report = checks::run_all(&sys, &home, mode, &detection);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    ui.set_provisioning(false);
                    match result {
                        Ok(()) => ui.set_log("Runtime ready.".into()),
                        Err(message) => {
                            ui.set_log_failed(true);
                            ui.set_log(message.into());
                        }
                    }
                    apply_report(&ui, &report);
                });
            });
        };
        if replace {
            ui.on_regenerate(handler);
        } else {
            ui.on_provision(handler);
        }
    }

    ui.on_check_action({
        let weak = ui.as_weak();
        let (sys, home, detection) = (sys.clone(), home.clone(), detection.clone());
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let Some(action) = Action::from_id(id.as_str()) else {
                return;
            };
            if ui.get_busy() {
                return;
            }
            ui.set_busy(true);
            ui.set_running_action(action.id().into());
            ui.set_action_failed(false);
            ui.set_action_log("Waiting for the password prompt...".into());

            let (weak, sys, home, detection) =
                (weak.clone(), sys.clone(), home.clone(), detection.clone());
            std::thread::spawn(move || {
                let log = action_log(&weak);
                let result = install::run_elevated(&sys, action.module(), &log);
                let report = checks::run_all(&sys, &home, mode, &detection);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    ui.set_running_action("".into());
                    if let Err(message) = result {
                        ui.set_action_failed(true);
                        let shown = ui.get_action_log();
                        ui.set_action_log(format!("{shown}\n{message}").into());
                    }
                    apply_report(&ui, &report);
                });
            });
        }
    });

    ui.on_uninstall({
        let weak = ui.as_weak();
        let (sys, home, detection) = (sys.clone(), home.clone(), detection.clone());
        move || {
            let Some(ui) = weak.upgrade() else { return };
            if ui.get_busy() {
                return;
            }
            ui.set_busy(true);
            ui.set_running_action("uninstall".into());
            ui.set_action_failed(false);
            ui.set_action_log("Waiting for the password prompt...".into());

            let (weak, sys, home, detection) =
                (weak.clone(), sys.clone(), home.clone(), detection.clone());
            std::thread::spawn(move || {
                let log = action_log(&weak);
                let result = install::run_elevated_uninstall(&sys, &log);
                let report = checks::run_all(&sys, &home, mode, &detection);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    ui.set_running_action("".into());
                    if let Err(message) = result {
                        ui.set_action_failed(true);
                        let shown = ui.get_action_log();
                        ui.set_action_log(format!("{shown}\n{message}").into());
                    }
                    apply_report(&ui, &report);
                });
            });
        }
    });

    ui.on_launch({
        let weak = ui.as_weak();
        let launched = launched.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                if let Ok(mut flag) = launched.lock() {
                    *flag = true;
                }
                let _ = ui.hide();
            }
        }
    });

    ui.on_quit({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        }
    });

    ui.run().map_err(|error| error.to_string())?;
    provision.cancel();
    if launched.lock().map(|flag| *flag).unwrap_or(false) {
        Ok(Outcome::Launch)
    } else {
        Ok(Outcome::Quit {
            ok: ui.get_all_ok(),
        })
    }
}

/// Splits a message into blocks; indented lines form a command block.
fn notice_blocks(body: &str) -> Vec<NoticeBlock> {
    let mut blocks: Vec<(bool, Vec<&str>)> = Vec::new();
    let mut fresh = true;
    for line in body.lines() {
        if line.trim().is_empty() {
            fresh = true;
            continue;
        }
        let code = line.starts_with("    ");
        match blocks.last_mut() {
            Some((last, lines)) if !fresh && *last == code => lines.push(line.trim()),
            _ => blocks.push((code, vec![line.trim()])),
        }
        fresh = false;
    }
    blocks
        .into_iter()
        .map(|(code, lines)| NoticeBlock {
            text: lines.join(if code { "\n" } else { " " }).into(),
            code,
        })
        .collect()
}

/// A standalone message box (the `notify` tool, spawned by pingu-hook when a
/// game loads artifact.dll without Artifact mode). Returns once dismissed.
pub fn notify(headline: &str, body: &str) -> Result<(), String> {
    let ui = NotifyWindow::new().map_err(|error| error.to_string())?;
    ui.set_headline(headline.into());
    ui.set_blocks(ModelRc::new(VecModel::from(notice_blocks(body))));
    ui.on_ok({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
        }
    });
    ui.run().map_err(|error| error.to_string())
}
