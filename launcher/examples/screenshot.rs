//! Renders the window of a machine that meets every requirement into a PNG, without a display.
//! `make launcher-screenshot` runs it and updates docs/images/launcher.png.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use flate2::write::ZlibEncoder;
use flate2::{Compression, Crc};
use pingu_launcher::assets;
use pingu_launcher::checks;
use pingu_launcher::home::Home;
use pingu_launcher::mode::{Detection, GameMode};
use pingu_launcher::runtime::RuntimeMode;
use pingu_launcher::sys::Sys;
use pingu_launcher::ui::{MainWindow, apply_report};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize, PlatformError, Rgb8Pixel};

const WIDTH: u32 = 760;
const HEIGHT: u32 = 640;

struct Headless(Rc<MinimalSoftwareWindow>);

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.0.clone())
    }
}

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// A fake root of an AVX-512 CachyOS machine with everything installed and loaded.
fn machine(root: &Path) -> (Sys, Home) {
    let _ = fs::remove_dir_all(root);
    let version = assets::module_version();
    write(
        root,
        "proc/cpuinfo",
        "processor\t: 0\nvendor_id\t: AuthenticAMD\nflags\t\t: fpu umip avx2 avx512f svm\n",
    );
    write(root, "proc/cmdline", "root=/dev/nvme0n1p2 rw quiet\n");
    write(root, "proc/sys/kernel/osrelease", "7.3.5-1-cachyos\n");
    let module = "sys/module/pingu_policy";
    write(root, &format!("{module}/version"), &format!("{version}\n"));
    write(root, &format!("{module}/parameters/ready"), "Y\n");
    write(root, &format!("{module}/parameters/umip_fixup"), "Y\n");
    write(
        root,
        &format!("{module}/parameters/cpuid_fault"),
        "native\n",
    );
    write(
        root,
        "var/lib/pacman/local/glibc-2.44-1/desc",
        "%NAME%\nglibc\n\n%VERSION%\n2.44-1\n\n%ARCH%\nx86_64_v4\n",
    );
    write(
        root,
        &format!("usr/src/pingu-policy-{version}/dkms.conf"),
        "",
    );
    let home = root.join("home/user/.local/share/pingu-runtime");
    write(
        &home,
        "runtime-generations/nvidia-current/runtime.json",
        "{\"schema\": 2, \"gpu\": \"nvidia\", \"glibc\": \"2.44-1\"}\n",
    );
    let sys = Sys {
        root: root.to_path_buf(),
        env: HashMap::from([("HOME".to_string(), "/home/user".to_string())]),
        cwd: root.join("home/user"),
        exe: PathBuf::from("/usr/local/bin/pingu-launcher"),
        cpuid_faulting: || true,
        native_xcr0: || Some(0x2e7),
        arm_check: |_, _| Ok(()),
        steamos_modules: &[],
    };
    (sys, Home { root: home })
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let mut crc = Crc::new();
    crc.update(kind);
    crc.update(data);
    out.extend((data.len() as u32).to_be_bytes());
    out.extend(kind);
    out.extend(data);
    out.extend(crc.sum().to_be_bytes());
}

fn png(pixels: &[Rgb8Pixel]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((WIDTH as usize * 3 + 1) * HEIGHT as usize);
    for row in pixels.chunks(WIDTH as usize) {
        raw.push(0);
        raw.extend(row.iter().flat_map(|pixel| [pixel.r, pixel.g, pixel.b]));
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&raw).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut header = Vec::new();
    header.extend(WIDTH.to_be_bytes());
    header.extend(HEIGHT.to_be_bytes());
    header.extend([8, 2, 0, 0, 0]);
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    chunk(&mut out, b"IHDR", &header);
    chunk(&mut out, b"IDAT", &compressed);
    chunk(&mut out, b"IEND", &[]);
    out
}

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../docs/images/launcher.png"));

    let root = manifest.join("target/tmp/screenshot");
    let (sys, home) = machine(&root);
    let detection = Detection {
        mode: GameMode::Artifact,
        note: String::new(),
    };
    let mut report = checks::run_all(&sys, &home, RuntimeMode::Auto, &detection);
    // The fake root only exists below the target directory; show the paths as on a real machine.
    let prefix = root.to_string_lossy().into_owned();
    for check in &mut report.checks {
        for text in [&mut check.detail, &mut check.fix, &mut check.warning] {
            *text = text.replace(&prefix, "");
        }
    }
    assert!(
        report.ok(),
        "the fake machine has problems:\n{}",
        checks::render_text(&report)
    );

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    window.set_size(PhysicalSize::new(WIDTH, HEIGHT));
    slint::platform::set_platform(Box::new(Headless(window.clone()))).unwrap();
    let ui = MainWindow::new().unwrap();
    ui.set_has_command(true);
    apply_report(&ui, &report);
    ui.show().unwrap();

    slint::platform::update_timers_and_animations();
    let mut buffer = vec![Rgb8Pixel::default(); (WIDTH * HEIGHT) as usize];
    let drawn = window.draw_if_needed(|renderer| {
        renderer.render(&mut buffer, WIDTH as usize);
    });
    assert!(drawn, "the window did not draw");

    fs::write(&output, png(&buffer)).unwrap();
    let _ = fs::remove_dir_all(&root);
    println!("wrote {}", output.display());
}
