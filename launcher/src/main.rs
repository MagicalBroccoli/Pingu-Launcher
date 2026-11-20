use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use pingu_launcher::checks::{self, Report};
use pingu_launcher::cli::{self, Parsed, USAGE};
use pingu_launcher::home::Home;
use pingu_launcher::launch;
use pingu_launcher::mode;
use pingu_launcher::sys::Sys;
use pingu_launcher::tools;
use pingu_launcher::ui::{self, Outcome};

fn main() -> ExitCode {
    let options = match cli::parse(std::env::args().skip(1)) {
        Parsed::Run(options) => options,
        Parsed::Tool { data_dir, tool } => {
            let sys = Sys::real();
            let home = Home::locate(&sys, data_dir);
            return match tools::run(&sys, &home, tool) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("pingu-launcher: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        Parsed::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Parsed::Error(message) => {
            eprintln!("pingu-launcher: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let command = launch::normalize_command(&options.command);
    let sys = Sys::real();
    let home = Home::locate(&sys, options.data_dir.clone());
    let detection = mode::detect(&sys, &command, options.mode);
    let report = checks::run_all(&sys, &home, options.runtime, &detection);

    if options.check {
        print!("{}", checks::render_text(&report));
        return exit_code(report.ok());
    }
    // With nothing to launch, the window is the whole point.
    if report.ok() && !options.force_ui && !command.is_empty() {
        return proceed(&sys, &home, &report, &command);
    }

    let window = ui::run(
        sys.clone(),
        home.clone(),
        options.runtime,
        detection.clone(),
        !command.is_empty(),
    );
    match window {
        Ok(Outcome::Launch) => {
            // The window may have generated the runtime, so look again.
            let report = checks::run_all(&sys, &home, options.runtime, &detection);
            proceed(&sys, &home, &report, &command)
        }
        Ok(Outcome::Quit { ok }) => exit_code(ok && command.is_empty()),
        Err(error) => {
            report_without_window(&report, &error);
            exit_code(report.ok() && command.is_empty())
        }
    }
}

fn proceed(sys: &Sys, home: &Home, report: &Report, command: &[String]) -> ExitCode {
    let launch = match launch::build(sys, home, report, command) {
        Ok(launch) => launch,
        Err(error) => {
            eprintln!("pingu-launcher: {error}");
            return ExitCode::FAILURE;
        }
    };
    for note in &launch.notes {
        eprintln!("pingu-launcher: {note}");
    }
    let error = Command::new(&launch.program)
        .args(&launch.args)
        .envs(launch.env)
        .exec();
    eprintln!("pingu-launcher: {}: {error}", launch.program);
    ExitCode::from(if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

fn report_without_window(report: &Report, error: &str) {
    eprintln!("pingu-launcher: cannot open a window ({error}). Check results:\n");
    eprint!("{}", checks::render_text(report));
}

fn exit_code(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
