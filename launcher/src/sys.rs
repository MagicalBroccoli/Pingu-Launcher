use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const ARCH_SET_CPUID: libc::c_long = 0x1012;

/// Runs the policy launcher in its check mode with the given `AVX2_POLICY` value.
pub type ArmCheck = fn(&Path, &str) -> Result<(), String>;

/// Machine view with an injectable root so tests can use fixture trees.
#[derive(Clone)]
pub struct Sys {
    pub root: PathBuf,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    pub exe: PathBuf,
    pub cpuid_faulting: fn() -> bool,
    pub native_xcr0: fn() -> Option<u64>,
    pub arm_check: ArmCheck,
    /// The prebuilt SteamOS modules, as `<kernel build ID>/<file>` assets.
    pub steamos_modules: &'static [crate::assets::Asset],
}

impl Sys {
    pub fn real() -> Self {
        Self {
            root: PathBuf::from("/"),
            env: std::env::vars_os()
                .filter_map(|(key, value)| {
                    Some((key.into_string().ok()?, value.into_string().ok()?))
                })
                .collect(),
            cwd: std::env::current_dir().unwrap_or_default(),
            exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("pingu-launcher")),
            cpuid_faulting: native_cpuid_faulting,
            native_xcr0,
            arm_check: run_arm_check,
            steamos_modules: crate::assets::STEAMOS_MODULES,
        }
    }

    /// A variable's value, treating an empty one as unset.
    pub fn env(&self, key: &str) -> Option<&str> {
        self.env
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub fn env_path(&self, key: &str) -> Option<PathBuf> {
        self.env(key)
            .map(|value| match (value.strip_prefix("~/"), self.env("HOME")) {
                (Some(rest), Some(home)) => Path::new(home).join(rest),
                _ => PathBuf::from(value),
            })
    }

    pub fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    pub fn read(&self, absolute: &str) -> Option<String> {
        fs::read_to_string(self.path(absolute)).ok()
    }

    pub fn read_bytes(&self, absolute: &str) -> Option<Vec<u8>> {
        fs::read(self.path(absolute)).ok()
    }

    pub fn exists(&self, absolute: &str) -> bool {
        self.path(absolute).exists()
    }

    pub fn readable(&self, absolute: &str) -> bool {
        fs::File::open(self.path(absolute)).is_ok()
    }

    /// The first executable called `name` on `$PATH`.
    pub fn which(&self, name: &str) -> Option<PathBuf> {
        std::env::split_paths(self.env("PATH")?)
            .map(|directory| directory.join(name))
            .find(|candidate| {
                fs::metadata(candidate)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
    }

    pub fn kernel_release(&self) -> String {
        self.read("/proc/sys/kernel/osrelease")
            .map(|text| text.trim().to_string())
            .unwrap_or_default()
    }

    pub fn kernel_params(&self) -> Vec<String> {
        self.read("/proc/cmdline")
            .map(|text| text.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// The running kernel's GNU build ID as hex, from the notes the kernel exports.
    pub fn is_steamos(&self) -> bool {
        self.read("/etc/os-release")
            .is_some_and(|text| text.lines().any(|line| line.trim() == "ID=steamos"))
    }

    /// An ostree image (Bazzite, Silverblue): /usr is read-only and DKMS cannot install modules.
    pub fn is_ostree(&self) -> bool {
        self.exists("/run/ostree-booted")
    }

    /// Whether the kernel loads only modules signed with a trusted key (Secure Boot lockdown or `module.sig_enforce`).
    pub fn module_signature_required(&self) -> bool {
        let enforced = self
            .read("/sys/module/module/parameters/sig_enforce")
            .is_some_and(|text| text.trim() == "Y");
        let locked = self
            .read("/sys/kernel/security/lockdown")
            .is_some_and(|text| text.contains("[integrity]") || text.contains("[confidentiality]"));
        enforced || locked
    }

    /// The embedded asset of a prebuilt module for the running kernel build.
    pub fn steamos_module(&self, file: &str) -> Option<&'static crate::assets::Asset> {
        let path = format!("{}/{file}", self.kernel_build_id()?);
        self.steamos_modules.iter().find(|asset| asset.path == path)
    }

    pub fn kernel_build_id(&self) -> Option<String> {
        let notes = fs::read(self.path("/sys/kernel/notes")).ok()?;
        let mut rest = notes.as_slice();
        while rest.len() >= 12 {
            let word = |at: usize| {
                u32::from_ne_bytes([rest[at], rest[at + 1], rest[at + 2], rest[at + 3]]) as usize
            };
            let (name, desc, kind) = (word(0), word(4), word(8));
            let desc_at = 12 + name.next_multiple_of(4);
            let end = desc_at + desc.next_multiple_of(4);
            if end > rest.len() {
                return None;
            }
            if kind == 3 && rest[12..12 + name] == *b"GNU\0" {
                return Some(
                    rest[desc_at..desc_at + desc]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                );
            }
            rest = &rest[end..];
        }
        None
    }

    /// True when `name` appears in the installed module index of the running kernel.
    pub fn module_installed(&self, name: &str) -> bool {
        let index = format!("/lib/modules/{}/modules.dep", self.kernel_release());
        let Some(text) = self.read(&index) else {
            return false;
        };
        let wanted = name.replace('-', "_");
        text.lines().any(|line| {
            let path = line.split(':').next().unwrap_or("");
            let file = path.rsplit('/').next().unwrap_or("");
            let stem = file.split(".ko").next().unwrap_or("");
            file.contains(".ko") && stem.replace('-', "_") == wanted
        })
    }

    pub fn module_loaded(&self, name: &str) -> bool {
        self.exists(&format!("/sys/module/{name}"))
    }
}

/// Enabling is the default CPUID mode, so this only reports whether the kernel can fault CPUID.
pub fn native_cpuid_faulting() -> bool {
    // SAFETY: arch_prctl with ARCH_SET_CPUID takes a single integer argument and touches no memory.
    unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, 1 as libc::c_ulong) == 0 }
}

/// Asks the kernel, through the static policy launcher, to arm the restriction for a child.
pub fn run_arm_check(helper: &Path, policy: &str) -> Result<(), String> {
    let output = crate::cmd::run(
        std::process::Command::new(helper)
            .arg("--check")
            .env("AVX2_POLICY", policy),
        std::time::Duration::from_secs(30),
        None,
    )?;
    if output.success() {
        return Ok(());
    }
    let detail = output.stderr.trim();
    Err(if detail.is_empty() {
        format!("The policy launcher failed ({})", output.status)
    } else {
        detail.to_string()
    })
}

/// XCR0 as the running kernel set it; None when XGETBV is unavailable.
#[cfg(target_arch = "x86_64")]
pub fn native_xcr0() -> Option<u64> {
    use std::arch::x86_64::{__cpuid, _xgetbv};
    // CPUID.1:ECX bit 27 (OSXSAVE) must be set before XGETBV is allowed.
    if __cpuid(1).ecx & (1 << 27) == 0 {
        return None;
    }
    // SAFETY: OSXSAVE guarantees XGETBV exists and XCR0 is readable.
    Some(unsafe { _xgetbv(0) })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn native_xcr0() -> Option<u64> {
    None
}

pub struct CpuInfo {
    pub vendor: String,
    pub flags: HashSet<String>,
}

impl CpuInfo {
    pub fn read(sys: &Sys) -> Self {
        Self::parse(&sys.read("/proc/cpuinfo").unwrap_or_default())
    }

    pub fn parse(text: &str) -> Self {
        let mut vendor = String::new();
        let mut flags = HashSet::new();
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim() {
                "vendor_id" if vendor.is_empty() => vendor = value.trim().to_string(),
                "flags" if flags.is_empty() => {
                    flags = value.split_whitespace().map(str::to_string).collect();
                }
                _ => {}
            }
        }
        Self { vendor, flags }
    }

    pub fn has(&self, flag: &str) -> bool {
        self.flags.contains(flag)
    }
}

pub fn shell_quote(path: &Path) -> String {
    crate::shlex::quote(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_first_cpu_only() {
        let text = "processor\t: 0\nvendor_id\t: AuthenticAMD\nflags\t\t: fpu avx2 umip\n\nprocessor\t: 1\nvendor_id\t: Other\nflags\t\t: fpu\n";
        let cpu = CpuInfo::parse(text);
        assert_eq!(cpu.vendor, "AuthenticAMD");
        assert!(cpu.has("umip") && cpu.has("avx2") && !cpu.has("fred"));
    }

    #[test]
    fn quotes_only_when_needed() {
        assert_eq!(shell_quote(Path::new("/opt/a-b/c.zip")), "/opt/a-b/c.zip");
        assert_eq!(
            shell_quote(Path::new("/opt/my dir/it's")),
            "'/opt/my dir/it'\"'\"'s'"
        );
    }
}
