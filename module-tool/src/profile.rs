//! Plans the kernel entry patches: reads the kernel's symbols and code, picks the whole
//! instructions each hook overwrites and records how to replay them from the trampolines.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use object::read::ReadRef;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader, Sym};
use object::{Endianness, SectionIndex, elf};
use regex_lite::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::decode::{self, Decoder, Instruction, Operand};
use crate::image::{Res, extract_kernel_elf};

pub const SCHEMA: u64 = 2;
const SOURCE_FILES: [&str; 12] = [
    "Makefile",
    "dkms.conf",
    "probe.c",
    "policy.c",
    "policy.h",
    "trampoline.S",
    "umip.c",
    "cpuid_fault.c",
    "svm_capture_context.S",
    "svm_run_vm.S",
    "inc/host_state.h",
    "inc/vmcb_layout.h",
];
const ENDBR: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
pub const MAX_WINDOW: usize = 16;
const MINIMUM_KERNEL: (u32, u32) = (6, 6);
const SCRATCH: &str = "r11";
const SCRATCH_ALIASES: [&str; 4] = ["r11", "r11d", "r11w", "r11b"];
/// (role, entry symbols in order of preference, window includes the function entry)
const HOOKS: [(&str, &[&str], bool); 10] = [
    ("irqentry_enter", &["irqentry_enter"], false),
    ("do_syscall_64", &["do_syscall_64"], false),
    ("irqentry_exit", &["irqentry_exit"], false),
    ("irqentry_nmi_enter", &["irqentry_nmi_enter"], false),
    ("irqentry_nmi_exit", &["irqentry_nmi_exit"], false),
    ("noist_exc_debug", &["noist_exc_debug"], false),
    ("exc_int3", &["exc_int3"], true),
    (
        "do_int80_emulation",
        &[
            "do_int80_emulation",
            "int80_emulation",
            "do_int80_syscall_32",
        ],
        false,
    ),
    ("do_fast_syscall_32", &["do_fast_syscall_32"], false),
    (
        "noist_exc_machine_check",
        &["noist_exc_machine_check"],
        false,
    ),
];
/// FRED entry points that replace the IDT-only debug, int 0x80 and machine check hooks.
/// They follow HOOKS in the tables; kernels without FRED code get empty slots.
const FRED_HOOKS: [(&str, &str, bool); 3] = [
    ("fred_exc_debug", "fred_exc_debug", false),
    ("fred_int80_emulation", "fred_int80_emulation", false),
    ("fred_exc_machine_check", "fred_exc_machine_check", false),
];
const FIXED_SYMBOLS: [&str; 9] = [
    "kallsyms_lookup_name",
    "vmlinux_build_id",
    "text_mutex",
    "__x64_sys_arch_prctl",
    "__ia32_sys_arch_prctl",
    "copy_thread",
    "free_task",
    "ret_from_fork",
    "__tracepoint_sched_process_exec",
];
// Kernel functions are renamed over time; the first defined candidate wins.
const TEXT_POKE_SINGLE: [&str; 2] = ["smp_text_poke_single", "text_poke_bp"];
const TEXT_POKE_SYNC: [&str; 2] = ["smp_text_poke_sync_each_cpu", "text_poke_sync"];
const TEXT_POKE_ATOMIC: [&str; 2] = ["__text_poke", "text_poke"];
const FORBIDDEN_CALL_TARGETS: [&str; 8] = [
    "__fentry__",
    "__x86_",
    "__SCT__",
    "__SCK__",
    "__sanitizer",
    "__asan",
    "__kasan",
    "__kcsan",
];
const REQUIRED_OPTIONS: [&str; 5] = [
    "CONFIG_X86_64",
    "CONFIG_MODULES",
    "CONFIG_KPROBES",
    "CONFIG_KALLSYMS_ALL",
    "CONFIG_IA32_EMULATION",
];
const REFUSED_OPTIONS: [&str; 4] = [
    "CONFIG_CFI",
    "CONFIG_CFI_CLANG",
    "CONFIG_RANDSTRUCT_FULL",
    "CONFIG_RANDSTRUCT_PERFORMANCE",
];

fn is_gpr64(name: &str) -> bool {
    matches!(name, "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp")
        || name
            .strip_prefix('r')
            .is_some_and(|rest| matches!(rest, "8" | "9" | "10" | "11" | "12" | "13" | "14" | "15"))
}

fn is_gpr32(name: &str) -> bool {
    matches!(name, "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp")
        || name
            .strip_prefix('r')
            .and_then(|rest| rest.strip_suffix('d'))
            .is_some_and(|rest| matches!(rest, "8" | "9" | "10" | "11" | "12" | "13" | "14" | "15"))
}

fn is_gpr(name: &str) -> bool {
    is_gpr64(name) || is_gpr32(name)
}

pub fn digest(path: &Path) -> Res<String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

fn source_digest(directory: &Path) -> Res<String> {
    let mut hasher = Sha256::new();
    for name in SOURCE_FILES {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(from_hex(&digest(&directory.join(name))?));
    }
    Ok(hex(&hasher.finalize()))
}

/// Defined kernel symbols with address-to-name resolution.
#[derive(Default)]
pub struct Symbols {
    by_name: HashMap<String, Vec<(u64, u64)>>,
    entries: Vec<(u64, u64, String, bool)>,
    keys: Vec<u64>,
}

impl Symbols {
    pub fn add(&mut self, name: &str, value: u64, size: u64, is_global: bool) {
        self.by_name
            .entry(name.to_string())
            .or_default()
            .push((value, size));
        self.entries
            .push((value, size, name.to_string(), is_global));
    }

    pub fn finish(&mut self) {
        self.entries.sort();
        self.keys = self.entries.iter().map(|entry| entry.0).collect();
    }

    pub fn defined(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    pub fn address(&self, name: &str) -> Res<u64> {
        match self.by_name.get(name).map(Vec::as_slice) {
            Some([(value, _)]) => Ok(*value),
            Some([]) | None => Err(format!("Symbol {name} is missing")),
            Some(_) => Err(format!("Symbol {name} is ambiguous")),
        }
    }

    pub fn choose<'a>(&self, names: &[&'a str]) -> Option<&'a str> {
        names.iter().copied().find(|name| self.defined(name))
    }

    /// Names a symbol that kallsyms finds uniquely, plus the offset of `target` inside it.
    pub fn resolve(&self, target: u64) -> Res<(String, u64)> {
        let position = self.keys.partition_point(|key| *key <= target);
        let mut best: Option<u64> = None;
        let mut candidates: Vec<(u64, &str, bool)> = Vec::new();
        let lowest = position.saturating_sub(63);
        for index in (lowest..position).rev() {
            let (value, size, name, is_global) = &self.entries[index];
            if best.is_some_and(|best| *value < best) {
                break;
            }
            if *value == target || value + size > target {
                best = Some(*value);
                candidates.push((*value, name, *is_global));
            }
        }
        // Prefer a real variable over a linker-script alias such as const_current_task.
        let usable = candidates
            .into_iter()
            .filter(|(_, name, _)| self.by_name[*name].len() == 1 && !name.contains('.'))
            .min_by_key(|(_, name, is_global)| (name.starts_with("const_"), !is_global, *name));
        match usable {
            Some((value, name, _)) => Ok((name.to_string(), target - value)),
            None => Err(format!("No unique kernel symbol covers {target:#x}")),
        }
    }
}

/// Parses System.map; sizes are not recorded there, so a symbol extends to the next address.
pub fn load_system_map(text: &str) -> Res<Symbols> {
    let mut rows: Vec<(u64, String, bool)> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 3 && !"UuwWNn".contains(fields[1]) {
            let address = u64::from_str_radix(fields[0], 16)
                .map_err(|_| format!("invalid literal for int() with base 16: '{}'", fields[0]))?;
            let kind = fields[1];
            let upper =
                kind.chars().any(|c| c.is_alphabetic()) && kind.chars().all(|c| !c.is_lowercase());
            rows.push((address, fields[2].to_string(), upper));
        }
    }
    rows.sort();
    let mut symbols = Symbols::default();
    let mut following = 0;
    for index in (0..rows.len()).rev() {
        let (address, name, is_global) = &rows[index];
        if index + 1 < rows.len() && rows[index + 1].0 != *address {
            following = rows[index + 1].0;
        } else if index + 1 == rows.len() {
            following = *address;
        }
        symbols.add(name, *address, following - address, *is_global);
    }
    symbols.finish();
    if rows.len() < 1000 {
        return Err(
            "System.map has no real symbol list (Debian ships a stub); install the kernel's -dbg package"
                .into(),
        );
    }
    Ok(symbols)
}

pub struct Segment {
    vaddr: u64,
    filesz: u64,
    offset: u64,
}

enum Source {
    Memory(Vec<u8>),
    File(File),
}

/// The loadable contents of the kernel ELF, read on demand.
pub struct Kernel {
    segments: Vec<Segment>,
    source: Source,
}

impl Kernel {
    pub fn read(&self, address: u64, size: usize) -> Res<Vec<u8>> {
        for segment in &self.segments {
            if segment.vaddr <= address && address + size as u64 <= segment.vaddr + segment.filesz {
                let offset = segment.offset + address - segment.vaddr;
                let mut data = vec![0u8; size];
                let complete = match &self.source {
                    Source::Memory(bytes) => {
                        let start = offset as usize;
                        bytes.get(start..start + size).is_some_and(|slice| {
                            data.copy_from_slice(slice);
                            true
                        })
                    }
                    Source::File(file) => file.read_exact_at(&mut data, offset).is_ok(),
                };
                if complete {
                    return Ok(data);
                }
            }
        }
        Err(format!(
            "No file-backed load segment for {address:#x}+{size}"
        ))
    }
}

struct ElfInfo {
    little_endian_x86_64: bool,
    segments: Vec<Segment>,
    build_ids: BTreeSet<String>,
    symbols: Option<Symbols>,
}

fn is_symbol_table(kind: elf::SectionType) -> bool {
    kind == elf::SHT_SYMTAB || kind == elf::SHT_DYNSYM
}

fn parse_elf<'a, R: ReadRef<'a>>(data: R, want_symbols: bool) -> Res<ElfInfo> {
    let unsupported = || "Only little-endian x86-64 kernels are supported".to_string();
    let header = elf::FileHeader64::<Endianness>::parse(data).map_err(|_| unsupported())?;
    let endian = header.endian().map_err(|_| unsupported())?;
    let mut info = ElfInfo {
        little_endian_x86_64: header.is_little_endian()
            && header.e_machine(endian) == elf::EM_X86_64,
        segments: Vec::new(),
        build_ids: BTreeSet::new(),
        symbols: None,
    };
    if !info.little_endian_x86_64 {
        return Ok(info);
    }
    let corrupt = |error: object::Error| format!("Corrupt kernel ELF: {error}");
    for program in header.program_headers(endian, data).map_err(corrupt)? {
        if program.p_type(endian) == elf::PT_LOAD {
            info.segments.push(Segment {
                vaddr: program.p_vaddr(endian),
                filesz: program.p_filesz(endian),
                offset: program.p_offset(endian),
            });
        }
    }
    let sections = header.sections(endian, data).map_err(corrupt)?;
    let mut symbols = Symbols::default();
    for (index, section) in sections.iter().enumerate() {
        let kind = section.sh_type(endian);
        if kind == elf::SHT_NOTE {
            if let Some(mut notes) = section.notes(endian, data).map_err(corrupt)? {
                while let Some(note) = notes.next().map_err(corrupt)? {
                    if note.name().strip_suffix(b"\0").unwrap_or(note.name()) == b"GNU"
                        && note.n_type(endian) == elf::NT_GNU_BUILD_ID
                    {
                        info.build_ids.insert(hex(note.desc()));
                    }
                }
            }
        } else if want_symbols && is_symbol_table(kind) {
            let table = object::read::elf::SymbolTable::<elf::FileHeader64<Endianness>, R>::parse(
                endian,
                data,
                &sections,
                SectionIndex(index),
                section,
            )
            .map_err(corrupt)?;
            for symbol in table.iter() {
                let name = symbol.name(endian, table.strings()).map_err(corrupt)?;
                let kind = symbol.st_type();
                if name.is_empty()
                    || symbol.st_shndx(endian) == elf::SHN_UNDEF
                    || !matches!(kind, elf::STT_FUNC | elf::STT_OBJECT | elf::STT_NOTYPE)
                {
                    continue;
                }
                symbols.add(
                    &String::from_utf8_lossy(name),
                    symbol.st_value(endian),
                    symbol.st_size(endian),
                    symbol.st_bind() == elf::STB_GLOBAL,
                );
            }
        }
    }
    if want_symbols {
        symbols.finish();
        info.symbols = Some(symbols);
    }
    Ok(info)
}

/// Whether this is a vmlinux that still names kernel functions (some header packages ship a stub).
fn has_symbol_table(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let cache = object::read::ReadCache::new(file);
    let data = &cache;
    let Ok(header) = elf::FileHeader64::<Endianness>::parse(data) else {
        return false;
    };
    let Ok(endian) = header.endian() else {
        return false;
    };
    let Ok(sections) = header.sections(endian, data) else {
        return false;
    };
    sections.iter().any(|section| {
        is_symbol_table(section.sh_type(endian))
            && sections
                .section(SectionIndex(section.sh_link(endian) as usize))
                .ok()
                .and_then(|strings| strings.data(endian, data).ok())
                .is_some_and(|strings| {
                    strings
                        .windows(b"kallsyms_lookup_name\0".len())
                        .any(|window| window == b"kallsyms_lookup_name\0")
                })
    })
}

pub type Reloc = (usize, usize, String, u64);

pub struct Window {
    pub skip: u64,
    pub data: Vec<u8>,
    pub assembly: Vec<String>,
    pub instructions: Vec<String>,
    pub relocs: Vec<Reloc>,
}

/// Assigns stable indexes to the (symbol, addend) pairs that relocations reference.
#[derive(Default)]
pub struct Interner {
    pub targets: Vec<(String, u64)>,
}

impl Interner {
    fn index(&mut self, name: &str, addend: u64) -> usize {
        let pair = (name.to_string(), addend);
        match self.targets.iter().position(|item| *item == pair) {
            Some(position) => position,
            None => {
                self.targets.push(pair);
                self.targets.len() - 1
            }
        }
    }
}

fn register_names(instruction: &Instruction) -> BTreeSet<&str> {
    let mut names = BTreeSet::new();
    for operand in &instruction.operands {
        match operand {
            Operand::Reg { name, .. } => {
                names.insert(name.as_str());
            }
            Operand::Mem { base, index, .. } => {
                names.extend(base.as_deref());
                names.extend(index.as_deref());
            }
            Operand::Imm { .. } => {}
        }
    }
    names
}

struct Replay {
    lines: Vec<String>,
    reloc: Option<Reloc>,
    scratch: bool,
}

fn plain(lines: Vec<String>) -> Res<Replay> {
    Ok(Replay {
        lines,
        reloc: None,
        scratch: false,
    })
}

/// Translates one instruction into position-independent assembly. Only side-effect-free,
/// relocatable forms are accepted; anything else needs review.
fn replay_instruction(
    instruction: &Instruction,
    window_start: u64,
    symbols: &Symbols,
    interner: &mut Interner,
) -> Res<Replay> {
    let text = instruction.text();
    let message = format!("unsupported instruction `{text}`; manual review required");
    let reject = || message.clone();
    let operands = &instruction.operands;
    if instruction.prefix[0] != 0 || instruction.prefix[2] != 0 || instruction.prefix[3] != 0 {
        return Err(reject());
    }

    let plain_memory = |operand: &Operand| {
        matches!(operand, Operand::Mem { base: Some(base), index: None, segment: None, .. }
            if is_gpr64(base) || base == "rsp")
    };
    let stack_memory = |operand: &Operand| {
        matches!(operand, Operand::Mem { base: Some(base), index: None, segment: None, .. }
            if base == "rsp" || base == "rbp")
    };
    let absolute_gs = |operand: &Operand| {
        matches!(operand, Operand::Mem { base: None, index: None, segment: Some(segment), .. }
            if segment == "gs")
    };
    let rip_relative = |operand: &Operand| {
        matches!(operand, Operand::Mem { base: Some(base), index: None, segment, .. }
            if base == "rip" && segment.as_deref().is_none_or(|segment| segment == "gs"))
    };
    let mut through_pointer = |operand: &Operand| -> Res<Replay> {
        let Operand::Mem { disp, .. } = operand else {
            return Err(reject());
        };
        if instruction.disp_size != 4 {
            return Err(reject());
        }
        let target = instruction
            .address
            .wrapping_add(instruction.size as u64)
            .wrapping_add(*disp as u64);
        let (name, addend) = symbols.resolve(target)?;
        let index = interner.index(&name, addend);
        let offset = (instruction.address - window_start) as usize;
        let rewritten =
            rip_operand().replace_all(&instruction.op_str, format!("${{1}}(%{SCRATCH})"));
        Ok(Replay {
            lines: vec![
                format!("movq xcr0_probe_targets+8*{index}(%rip), %{SCRATCH}"),
                format!("{} {rewritten}", instruction.mnemonic),
            ],
            reloc: Some((
                offset + instruction.disp_offset,
                offset + instruction.size,
                name,
                addend,
            )),
            scratch: true,
        })
    };

    let id = instruction.id;
    match (id, operands.as_slice()) {
        (decode::INS_PUSH, [first @ Operand::Reg { name, .. }]) => {
            if is_gpr64(name) && first.size() == 8 {
                return plain(vec![text]);
            }
        }
        (decode::INS_MOV, [first, second]) => match (first, second) {
            (Operand::Reg { name: a, size: sa }, Operand::Reg { name: b, size: sb }) => {
                if (is_gpr(a) || a == "rsp") && is_gpr(b) && sa == sb {
                    return plain(vec![text]);
                }
            }
            (Operand::Reg { name: a, size }, Operand::Mem { .. }) => {
                if is_gpr(a) && matches!(size, 4 | 8) && stack_memory(second) {
                    return plain(vec![text]);
                }
            }
            (Operand::Mem { .. }, Operand::Reg { name: b, size }) => {
                if is_gpr(b) && matches!(size, 4 | 8) {
                    if plain_memory(first) || absolute_gs(first) {
                        return plain(vec![text]);
                    }
                    if rip_relative(first) {
                        return through_pointer(first);
                    }
                }
            }
            (Operand::Imm { .. }, Operand::Reg { name: b, .. }) if is_gpr(b) => {
                return plain(vec![text]);
            }
            _ => {}
        },
        (
            decode::INS_SUB | decode::INS_ADD,
            [Operand::Imm { .. }, second @ Operand::Reg { .. }],
        ) => {
            if matches!(second, Operand::Reg { name, .. } if name == "rsp") {
                return plain(vec![text]);
            }
        }
        (
            decode::INS_SUB | decode::INS_ADD,
            [Operand::Imm { .. }, second @ Operand::Mem { .. }],
        ) => {
            if rip_relative(second) {
                return through_pointer(second);
            }
        }
        (decode::INS_INC | decode::INS_DEC, [first @ Operand::Mem { .. }]) => {
            if rip_relative(first) {
                return through_pointer(first);
            }
        }
        (
            decode::INS_TEST | decode::INS_CMP,
            [Operand::Imm { .. }, second @ Operand::Mem { .. }],
        ) => {
            if plain_memory(second) {
                return plain(vec![text]);
            }
            if rip_relative(second) {
                return through_pointer(second);
            }
        }
        (
            decode::INS_TEST | decode::INS_CMP,
            [
                Operand::Reg { name: a, size: sa },
                Operand::Reg { name: b, size: sb },
            ],
        ) => {
            if sa == sb && is_gpr(a) && is_gpr(b) {
                return plain(vec![text]);
            }
        }
        (decode::INS_CALL, [Operand::Imm { value, .. }]) if instruction.size == 5 => {
            let (name, addend) = symbols.resolve(*value as u64)?;
            if addend != 0
                || FORBIDDEN_CALL_TARGETS
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            {
                return Err(reject());
            }
            let index = interner.index(&name, addend);
            let offset = (instruction.address - window_start) as usize;
            return Ok(Replay {
                lines: vec![
                    "ANNOTATE_RETPOLINE_SAFE".to_string(),
                    format!("call *xcr0_probe_targets+8*{index}(%rip)"),
                ],
                reloc: Some((offset + 1, offset + instruction.size, name, addend)),
                scratch: false,
            });
        }
        _ => {}
    }
    Err(reject())
}

fn rip_operand() -> &'static Regex {
    use std::sync::OnceLock;
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| Regex::new(r"((?:%[a-z]s:)?)-?(?:0x[0-9a-fA-F]+|[0-9]+)\(%rip\)").unwrap())
}

/// Rejects a window that other code in the function branches into.
fn check_interior_entries(
    kernel: &Kernel,
    symbols: &Symbols,
    name: &str,
    start: u64,
    length: u64,
) -> Res<()> {
    let decoder = Decoder::new().skipdata();
    for candidate in [name.to_string(), format!("{name}.cold")] {
        for (value, size) in symbols.by_name.get(&candidate).into_iter().flatten() {
            let code = kernel.read(*value, if *size == 0 { 1 } else { *size as usize })?;
            for instruction in decoder.disassemble(&code, *value) {
                if instruction.id == 0 {
                    continue;
                }
                if !(instruction.in_group(decode::GRP_JUMP)
                    || instruction.in_group(decode::GRP_CALL)
                    || instruction.in_group(decode::GRP_BRANCH_RELATIVE))
                {
                    continue;
                }
                if let Some(Operand::Imm { value: target, .. }) = instruction.operands.first() {
                    let target = *target as u64;
                    if start < target && target < start + length {
                        return Err(format!(
                            "{name}: branch at {:#x} enters the patch window; manual review required",
                            instruction.address
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Chooses the whole instructions that a patch at this hook overwrites and how to replay them.
pub fn plan_window(
    kernel: &Kernel,
    symbols: &Symbols,
    interner: &mut Interner,
    name: &str,
    atomic: bool,
) -> Res<Window> {
    let address = symbols.address(name)?;
    let has_endbr = kernel.read(address, 4)? == ENDBR;
    let skip = if atomic || !has_endbr { 0 } else { 4 };
    let minimum = if atomic { 8 } else { 5 };
    let start = address + skip;
    let decoder = Decoder::new();
    let mut assembly = Vec::new();
    let mut instructions = Vec::new();
    let mut relocs = Vec::new();
    let mut uses_scratch = false;
    let mut scratch_conflict = false;
    let mut consumed = if atomic && has_endbr { ENDBR.len() } else { 0 };
    if consumed != 0 {
        instructions.push("endbr64".to_string());
    }
    let code = kernel.read(start + consumed as u64, 40)?;
    let mut complete = false;
    for instruction in decoder.disassemble(&code, start + consumed as u64) {
        let replay = replay_instruction(&instruction, start, symbols, interner)?;
        scratch_conflict |= register_names(&instruction)
            .iter()
            .any(|register| SCRATCH_ALIASES.contains(register));
        uses_scratch |= replay.scratch;
        assembly.extend(replay.lines);
        instructions.push(instruction.text());
        relocs.extend(replay.reloc);
        consumed += instruction.size;
        if consumed >= minimum {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(format!("{name}: incomplete patch window"));
    }
    if consumed > MAX_WINDOW {
        return Err(format!(
            "{name}: patch window of {consumed} bytes is too long; manual review required"
        ));
    }
    if uses_scratch && scratch_conflict {
        return Err(format!(
            "{name}: window already uses the scratch register; manual review required"
        ));
    }
    check_interior_entries(kernel, symbols, name, start, consumed as u64)?;
    Ok(Window {
        skip,
        data: kernel.read(start, consumed)?,
        assembly,
        instructions,
        relocs,
    })
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Features {
    pub lass: bool,
    pub task_fpu: bool,
    /// Kernels from 7.x register a `struct syscore` instead of `struct syscore_ops`.
    pub syscore_struct: bool,
    /// The kernel has FRED entry code and every FRED hook could be planned.
    pub fred: bool,
    pub text_poke_single: String,
    pub text_poke_sync: String,
    pub text_poke_atomic: String,
}

#[derive(Serialize, Clone)]
pub struct Target {
    pub symbol: String,
    pub addend: u64,
}

#[derive(Serialize, Clone)]
pub struct RelocationEntry {
    pub disp: usize,
    pub end: usize,
    pub symbol: String,
    pub addend: u64,
}

#[derive(Serialize, Clone)]
pub struct Entry {
    pub role: String,
    pub name: String,
    pub address: String,
    pub skip: u64,
    pub bytes: String,
    pub instructions: Vec<String>,
    pub assembly: Vec<String>,
    pub relocations: Vec<RelocationEntry>,
}

#[derive(Serialize, Clone)]
pub struct Profile {
    pub schema: u64,
    pub release: String,
    pub build_id: String,
    pub inputs: BTreeMap<String, String>,
    pub boot_image: Option<String>,
    pub features: Features,
    pub targets: Vec<Target>,
    pub entries: Vec<Entry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_validated: Option<bool>,
}

fn first_file(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    candidates.into_iter().find(|path| path.is_file())
}

fn boot_image_candidates(headers: &Path, release: &str) -> Vec<PathBuf> {
    vec![
        headers.parent().unwrap_or(headers).join("vmlinuz"),
        Path::new("/lib/modules").join(release).join("vmlinuz"),
        Path::new("/usr/lib/modules").join(release).join("vmlinuz"),
        Path::new("/boot").join(format!("vmlinuz-{release}")),
        Path::new("/boot").join(format!("vmlinuz-{release}.efi")),
    ]
}

fn vmlinux_candidates(headers: &Path, release: &str) -> Vec<PathBuf> {
    vec![
        headers.join("vmlinux"),
        Path::new("/usr/lib/debug/boot").join(format!("vmlinux-{release}")),
        Path::new("/usr/lib/debug").join(format!("vmlinux-{release}")),
        Path::new("/usr/lib/debug/lib/modules")
            .join(release)
            .join("vmlinux"),
        Path::new("/usr/lib/debug/usr/lib/modules")
            .join(release)
            .join("vmlinux"),
    ]
}

fn system_map_candidates(headers: &Path, release: &str) -> Vec<PathBuf> {
    vec![
        headers.join("System.map"),
        headers.parent().unwrap_or(headers).join("System.map"),
        Path::new("/lib/modules").join(release).join("System.map"),
        Path::new("/usr/lib/modules")
            .join(release)
            .join("System.map"),
        Path::new("/boot").join(format!("System.map-{release}")),
        Path::new("/usr/lib/debug/boot").join(format!("System.map-{release}")),
    ]
}

fn read_text(path: &Path) -> Res<String> {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Picks the kernel API variants present in these headers and this kernel.
pub fn detect_features(headers: &Path, symbols: &Symbols, extra: &[PathBuf]) -> Res<Features> {
    // Distributions with separate source and build trees keep arch headers only in the source tree.
    let mut roots = vec![headers.to_path_buf()];
    roots.extend(extra.iter().cloned());
    roots.push(headers.join("source"));
    let smap = roots
        .iter()
        .map(|root| root.join("arch/x86/include/asm/smap.h"))
        .find(|path| path.is_file());
    let mut fpu_headers = Vec::new();
    for root in &roots {
        if let Ok(listing) = fs::read_dir(root.join("arch/x86/include/asm/fpu")) {
            let mut files: Vec<PathBuf> = listing
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().is_some_and(|extension| extension == "h"))
                .collect();
            files.sort();
            fpu_headers.extend(files);
        }
    }
    let mut missing: BTreeSet<&str> = FIXED_SYMBOLS
        .iter()
        .copied()
        .filter(|name| !symbols.defined(name))
        .collect();
    let single = symbols.choose(&TEXT_POKE_SINGLE);
    let sync = symbols.choose(&TEXT_POKE_SYNC);
    let atomic = symbols.choose(&TEXT_POKE_ATOMIC);
    for (found, names) in [
        (single, &TEXT_POKE_SINGLE),
        (sync, &TEXT_POKE_SYNC),
        (atomic, &TEXT_POKE_ATOMIC),
    ] {
        if found.is_none() {
            missing.insert(names[0]);
        }
    }
    if !missing.is_empty() {
        let list: Vec<&str> = missing.into_iter().collect();
        return Err(format!(
            "Required kernel symbols are missing: {}",
            list.join(", ")
        ));
    }
    let lass = match smap {
        Some(path) => read_text(&path)?.contains("lass_stac"),
        None => false,
    };
    let mut task_fpu = false;
    for header in &fpu_headers {
        if read_text(header)?.contains("x86_task_fpu") {
            task_fpu = true;
            break;
        }
    }
    let syscore_struct = match roots
        .iter()
        .map(|root| root.join("include/linux/syscore_ops.h"))
        .find(|path| path.is_file())
    {
        Some(path) => read_text(&path)?.contains("struct syscore {"),
        None => false,
    };
    Ok(Features {
        lass,
        task_fpu,
        syscore_struct,
        fred: false,
        text_poke_single: single.unwrap().to_string(),
        text_poke_sync: sync.unwrap().to_string(),
        text_poke_atomic: atomic.unwrap().to_string(),
    })
}

pub struct Inputs<'a> {
    pub headers: &'a Path,
    pub image: Option<&'a Path>,
    pub system_map: Option<&'a Path>,
    pub source: &'a str,
    pub kernel_source: Option<&'a Path>,
}

fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let major_end = release.find(|c: char| !c.is_ascii_digit())?;
    let major: u32 = release[..major_end].parse().ok()?;
    let rest = release[major_end..].strip_prefix('.')?;
    let minor_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let minor: u32 = rest[..minor_end].parse().ok()?;
    Some((major, minor))
}

fn valid_release(release: &str) -> bool {
    let mut chars = release.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

pub fn inspect_kernel(inputs: &Inputs) -> Res<Profile> {
    let headers = inputs.headers;
    let release = read_text(&headers.join("include/config/kernel.release"))?
        .trim()
        .to_string();
    if !valid_release(&release) {
        return Err("Invalid kernel release string".into());
    }
    match kernel_version(&release) {
        Some(version) if version >= MINIMUM_KERNEL => {}
        _ => {
            return Err(
                "Kernels older than 6.6 have different entry code and are not supported".into(),
            );
        }
    }
    let config = read_text(&headers.join(".config"))?;
    let lines: Vec<&str> = config.lines().collect();
    let has = |option: &str| lines.contains(&format!("{option}=y").as_str());
    for option in REQUIRED_OPTIONS {
        if !has(option) {
            return Err(format!("Required kernel option is absent: {option}=y"));
        }
    }
    if !has("CONFIG_DYNAMIC_FTRACE_WITH_REGS") && !has("CONFIG_DYNAMIC_FTRACE_WITH_ARGS") {
        return Err("Required kernel option is absent: CONFIG_DYNAMIC_FTRACE_WITH_REGS=y".into());
    }
    for option in REFUSED_OPTIONS {
        if has(option) {
            return Err(format!("Unsupported kernel option is enabled: {option}=y"));
        }
    }
    let vmlinux = if inputs.source != "image" {
        vmlinux_candidates(headers, &release)
            .into_iter()
            .find(|path| path.is_file() && has_symbol_table(path))
    } else {
        None
    };
    if inputs.source == "vmlinux" && vmlinux.is_none() {
        return Err("No vmlinux with symbols was found".into());
    }
    let boot_image = inputs
        .image
        .map(Path::to_path_buf)
        .or_else(|| first_file(boot_image_candidates(headers, &release)));
    let mut recorded = BTreeMap::new();
    recorded.insert(
        headers.join(".config").to_string_lossy().into_owned(),
        digest(&headers.join(".config"))?,
    );
    let (info, source) = if let Some(vmlinux) = &vmlinux {
        let file =
            File::open(vmlinux).map_err(|error| format!("{}: {error}", vmlinux.display()))?;
        let cache = object::read::ReadCache::new(
            file.try_clone()
                .map_err(|error| format!("{}: {error}", vmlinux.display()))?,
        );
        let parsed = parse_elf(&cache, true)?;
        recorded.insert(vmlinux.to_string_lossy().into_owned(), digest(vmlinux)?);
        (parsed, Source::File(file))
    } else {
        let system_map = inputs
            .system_map
            .map(Path::to_path_buf)
            .or_else(|| first_file(system_map_candidates(headers, &release)));
        let (Some(boot_image), Some(system_map)) = (boot_image.as_ref(), system_map) else {
            return Err(
                "Neither a vmlinux with symbols nor a boot image plus System.map was found; \
                install your kernel's debug package or pass XCR0_IMAGE and XCR0_SYSTEM_MAP"
                    .into(),
            );
        };
        let bytes = fs::read(boot_image).map_err(|e| format!("{}: {e}", boot_image.display()))?;
        let elf = extract_kernel_elf(&bytes)?;
        let mut parsed = parse_elf(elf.as_slice(), false)?;
        parsed.symbols = Some(load_system_map(&read_text(&system_map)?)?);
        recorded.insert(
            boot_image.to_string_lossy().into_owned(),
            digest(boot_image)?,
        );
        recorded.insert(
            system_map.to_string_lossy().into_owned(),
            digest(&system_map)?,
        );
        (parsed, Source::Memory(elf))
    };
    let Some(symbols) = info.symbols.as_ref() else {
        return Err("Only little-endian x86-64 kernels are supported".into());
    };
    if symbols.defined("avx512_policy_prctl") {
        return Err("Kernel already contains the built-in policy; refusing double patching".into());
    }
    if !info.little_endian_x86_64 {
        return Err("Only little-endian x86-64 kernels are supported".into());
    }
    let extra: Vec<PathBuf> = inputs
        .kernel_source
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    let mut features = detect_features(headers, symbols, &extra)?;
    let build_id = match info.build_ids.iter().collect::<Vec<_>>().as_slice() {
        [id] if id.len() == 40 && id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) => {
            (*id).clone()
        }
        _ => return Err("A unique 20-byte GNU build ID is required".into()),
    };
    let kernel = Kernel {
        segments: info.segments,
        source,
    };
    let mut interner = Interner::default();
    let mut entries = Vec::new();
    for (role, candidates, atomic) in HOOKS {
        let Some(name) = symbols.choose(candidates) else {
            return Err(format!(
                "Required kernel symbols are missing: {}",
                candidates[0]
            ));
        };
        let window = plan_window(&kernel, symbols, &mut interner, name, atomic)?;
        entries.push(hook_entry(role, name, symbols.address(name)?, window));
    }
    // FRED support is all or nothing; a kernel without it simply keeps the IDT hooks.
    let known_targets = interner.targets.len();
    let mut fred_entries = Vec::new();
    let mut fred_problem = None;
    for (role, name, atomic) in FRED_HOOKS {
        if !symbols.defined(name) {
            fred_problem = Some(format!("{name} is missing"));
            break;
        }
        match plan_window(&kernel, symbols, &mut interner, name, atomic) {
            Ok(window) => fred_entries.push(hook_entry(role, name, symbols.address(name)?, window)),
            Err(error) => {
                fred_problem = Some(error);
                break;
            }
        }
    }
    if let Some(problem) = fred_problem {
        if symbols.defined("fred_entry_from_user") {
            eprintln!("warning: FRED entry points are not usable by the module: {problem}");
        }
        interner.targets.truncate(known_targets);
        fred_entries = FRED_HOOKS
            .iter()
            .map(|(role, _, _)| absent_entry(role))
            .collect();
    } else {
        features.fred = true;
    }
    entries.extend(fred_entries);
    Ok(Profile {
        schema: SCHEMA,
        release,
        build_id,
        inputs: recorded,
        boot_image: boot_image.map(|path| path.to_string_lossy().into_owned()),
        features,
        targets: interner
            .targets
            .into_iter()
            .map(|(symbol, addend)| Target { symbol, addend })
            .collect(),
        entries,
        source_sha256: None,
        profile_sha256: None,
        vm_validated: None,
    })
}

fn hook_entry(role: &str, name: &str, address: u64, window: Window) -> Entry {
    Entry {
        role: role.to_string(),
        name: name.to_string(),
        address: format!("{:#x}", address + window.skip),
        skip: window.skip,
        bytes: hex(&window.data),
        instructions: window.instructions,
        assembly: window.assembly,
        relocations: window
            .relocs
            .into_iter()
            .map(|(disp, end, symbol, addend)| RelocationEntry {
                disp,
                end,
                symbol,
                addend,
            })
            .collect(),
    }
}

/// An unused slot keeps the tables aligned with the hook numbering.
fn absent_entry(role: &str) -> Entry {
    Entry {
        role: role.to_string(),
        name: String::new(),
        address: "0x0".to_string(),
        skip: 0,
        bytes: String::new(),
        instructions: Vec::new(),
        assembly: Vec::new(),
        relocations: Vec::new(),
    }
}

fn c_string(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

pub fn header_text(profile: &Profile) -> String {
    let build_id = from_hex(&profile.build_id)
        .iter()
        .map(|value| format!("0x{value:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let validated = i32::from(profile.vm_validated.unwrap_or(false));
    let features = &profile.features;
    let prologues: String = profile
        .entries
        .iter()
        .map(|entry| {
            format!(
                "#define XCR0_PROLOGUE_{} {}\n",
                entry.role.to_uppercase(),
                entry.assembly.join("; ")
            )
        })
        .collect();
    let entries = profile
        .entries
        .iter()
        .map(|entry| {
            let bytes = from_hex(&entry.bytes)
                .iter()
                .map(|value| format!("0x{value:02x}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("\t{{ {} }}", if bytes.is_empty() { "0" } else { &bytes })
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let names = profile
        .entries
        .iter()
        .map(|entry| c_string(&entry.name))
        .collect::<Vec<_>>()
        .join(", ");
    let lengths = profile
        .entries
        .iter()
        .map(|entry| (entry.bytes.len() / 2).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let skips = profile
        .entries
        .iter()
        .map(|entry| entry.skip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let relocs: Vec<(usize, &RelocationEntry)> = profile
        .entries
        .iter()
        .enumerate()
        .flat_map(|(index, entry)| entry.relocations.iter().map(move |item| (index, item)))
        .collect();
    let target_index: HashMap<(&str, u64), usize> = profile
        .targets
        .iter()
        .enumerate()
        .map(|(number, target)| ((target.symbol.as_str(), target.addend), number))
        .collect();
    let reloc_rows = if relocs.is_empty() {
        "\t{ 0, 0, 0, 0 }".to_string()
    } else {
        relocs
            .iter()
            .map(|(index, item)| {
                format!(
                    "\t{{ {index}, {}, {}, {} }}",
                    item.disp,
                    item.end,
                    target_index[&(item.symbol.as_str(), item.addend)]
                )
            })
            .collect::<Vec<_>>()
            .join(",\n")
    };
    let target_names = if profile.targets.is_empty() {
        "\"\"".to_string()
    } else {
        profile
            .targets
            .iter()
            .map(|target| c_string(&target.symbol))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let target_addends = if profile.targets.is_empty() {
        "0".to_string()
    } else {
        profile
            .targets
            .iter()
            .map(|target| target.addend.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "#ifndef XCR0_GENERATED_PROFILE_H\n#define XCR0_GENERATED_PROFILE_H\n\
         #ifdef __ASSEMBLER__\n{prologues}#else\n\
         #define XCR0_PROFILE_RELEASE {release}\n\
         #define XCR0_PROFILE_BUILD_ID {id}\n\
         #define XCR0_PROFILE_VALIDATED {validated}\n\
         #define XCR0_PROFILE_VALIDATED_TEXT \"{validated}\"\n\
         #define XCR0_HAVE_LASS {lass}\n\
         #define XCR0_HAVE_TASK_FPU {task_fpu}\n\
         #define XCR0_PROFILE_FRED {fred}\n\
         #define XCR0_HAVE_SYSCORE_STRUCT {syscore_struct}\n\
         #define XCR0_SYM_TEXT_POKE_SINGLE {single}\n\
         #define XCR0_SYM_TEXT_POKE_SYNC {sync}\n\
         #define XCR0_SYM_TEXT_POKE_ATOMIC {atomic}\n\
         #define XCR0_TEXT_POKE_ATOMIC_CUSTOM {custom}\n\
         #define XCR0_PROFILE_WINDOW {MAX_WINDOW}\n\
         #define XCR0_PROFILE_TARGET_COUNT {target_count}\n\
         #define XCR0_PROFILE_RELOC_COUNT {reloc_count}\n\
         #ifndef XCR0_PROFILE_FEATURES_ONLY\n\
         static const unsigned char xcr0_profile_build_id[] = {{ {build_id} }};\n\
         static const unsigned char xcr0_profile_entries[][XCR0_PROFILE_WINDOW] = {{\n{entries}\n}};\n\
         static const char * const xcr0_profile_names[] = {{ {names} }};\n\
         static const unsigned char xcr0_profile_lengths[] = {{ {lengths} }};\n\
         static const unsigned char xcr0_profile_skips[] = {{ {skips} }};\n\
         struct xcr0_profile_reloc {{ unsigned char hook, disp, end, target; }};\n\
         static const struct xcr0_profile_reloc xcr0_profile_relocs[] = {{\n{reloc_rows}\n}};\n\
         static const char * const xcr0_profile_target_names[] = {{ {target_names} }};\n\
         static const long xcr0_profile_target_addends[] = {{ {target_addends} }};\n\
         #endif\n#endif\n#endif\n",
        release = c_string(&profile.release),
        id = c_string(&profile.build_id),
        lass = i32::from(features.lass),
        task_fpu = i32::from(features.task_fpu),
        fred = i32::from(features.fred),
        syscore_struct = i32::from(features.syscore_struct),
        single = c_string(&features.text_poke_single),
        sync = c_string(&features.text_poke_sync),
        atomic = c_string(&features.text_poke_atomic),
        custom = i32::from(features.text_poke_atomic == "__text_poke"),
        target_count = profile.targets.len().max(1),
        reloc_count = relocs.len(),
    )
}

fn profile_digest(profile: &Profile) -> String {
    let mut identity = profile.clone();
    identity.vm_validated = None;
    identity.profile_sha256 = None;
    let value = serde_json::to_value(&identity).unwrap();
    hex(&Sha256::digest(
        serde_json::to_string(&value).unwrap().as_bytes(),
    ))
}

/// Records the profile identity and, when a matching VM receipt exists, that it was validated.
pub fn apply_approval(profile: &mut Profile, approvals: Option<&Path>) -> Res<()> {
    profile.profile_sha256 = Some(profile_digest(profile));
    profile.vm_validated = Some(false);
    let Some(approvals) = approvals else {
        return Ok(());
    };
    let receipt = approvals.join(format!("{}.json", profile.build_id));
    if !receipt.exists() {
        return Ok(());
    }
    let validation: serde_json::Value = serde_json::from_str(&read_text(&receipt)?)
        .map_err(|error| format!("Invalid validation receipt: {}; {error}", receipt.display()))?;
    let Some(object) = validation.as_object() else {
        return Err(format!(
            "Invalid validation receipt: {}; expected an object",
            receipt.display()
        ));
    };
    let log_digest = object.get("vm_log_sha256").and_then(|v| v.as_str());
    let good_log = log_digest.is_some_and(|text| {
        text.len() == 64 && text.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    });
    if object.get("schema").and_then(|v| v.as_u64()) != Some(SCHEMA)
        || object.get("profile_sha256").and_then(|v| v.as_str())
            != profile.profile_sha256.as_deref()
        || object.get("install_stress").and_then(|v| v.as_str()) != Some("PASS")
        || !good_log
    {
        return Err(format!(
            "Stale or invalid validation receipt: {}; rerun module-refresh",
            receipt.display()
        ));
    }
    profile.vm_validated = Some(true);
    Ok(())
}

/// Writes through a temporary file, and not at all when the content is unchanged.
pub fn write_atomic(path: &Path, content: &str) -> Res<()> {
    let io = |error: std::io::Error| format!("{}: {error}", path.display());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io)?;
    }
    if fs::read_to_string(path).is_ok_and(|existing| existing == content) {
        return Ok(());
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{}.tmp", std::process::id()));
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, content).map_err(io)?;
    let renamed = fs::rename(&temporary, path);
    if renamed.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    renamed.map_err(io)
}

pub struct Outputs<'a> {
    pub output: &'a Path,
    pub metadata: &'a Path,
}

/// The whole `profile` command: plan, record and write the header and the metadata.
pub fn generate(
    inputs: &Inputs,
    package: &Path,
    approvals: Option<&Path>,
    outputs: &Outputs,
) -> Res<Profile> {
    let mut profile = inspect_kernel(inputs)?;
    profile.source_sha256 = Some(source_digest(package)?);
    apply_approval(&mut profile, approvals)?;
    write_atomic(outputs.output, &header_text(&profile))?;
    let mut metadata =
        serde_json::to_string_pretty(&serde_json::to_value(&profile).unwrap()).unwrap();
    metadata.push('\n');
    write_atomic(outputs.metadata, &metadata)?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xFFFF_FFFF_8100_0000;
    const ENDBR_HEX: &str = "f30f1efa";

    fn code(parts: &[&str]) -> Vec<u8> {
        from_hex(&parts.concat())
    }

    /// Code placed at the given addresses, padded so look-ahead reads never run short.
    fn kernel_at(regions: &[(u64, Vec<u8>)]) -> Kernel {
        let mut memory = Vec::new();
        let mut segments = Vec::new();
        for (address, bytes) in regions {
            let offset = memory.len() as u64;
            memory.extend(bytes);
            memory.extend([0xcc; 64]);
            segments.push(Segment {
                vaddr: *address,
                filesz: bytes.len() as u64 + 64,
                offset,
            });
        }
        Kernel {
            segments,
            source: Source::Memory(memory),
        }
    }

    fn symbols_with(code_size: usize, others: &[(&str, u64, u64)]) -> Symbols {
        let mut symbols = Symbols::default();
        symbols.add("hook", BASE, code_size as u64, true);
        for (name, address, size) in others {
            symbols.add(name, *address, *size, true);
        }
        symbols.finish();
        symbols
    }

    fn plan(bytes: &[u8], atomic: bool, others: &[(&str, u64, u64)]) -> Res<(Window, Interner)> {
        let symbols = symbols_with(bytes.len(), others);
        let kernel = kernel_at(&[(BASE, bytes.to_vec())]);
        let mut interner = Interner::default();
        plan_window(&kernel, &symbols, &mut interner, "hook", atomic)
            .map(|window| (window, interner))
    }

    fn relative(target: u64, instruction_end: u64) -> String {
        hex(&((target as i64 - instruction_end as i64) as i32).to_le_bytes())
    }

    fn nops(count: usize) -> String {
        "90".repeat(count)
    }

    fn assembly(window: &Window) -> Vec<&str> {
        window.assembly.iter().map(String::as_str).collect()
    }

    #[test]
    fn register_saves_and_frame_setup_are_replayed() {
        let (window, _) = plan(&code(&[ENDBR_HEX, "554889e54157"]), false, &[]).unwrap();
        assert_eq!(window.skip, 4);
        assert_eq!(hex(&window.data), "554889e54157");
        assert_eq!(
            assembly(&window),
            ["pushq %rbp", "movq %rsp, %rbp", "pushq %r15"]
        );
    }

    #[test]
    fn stack_adjustment_and_spill_are_replayed() {
        let (window, _) = plan(
            &code(&[ENDBR_HEX, "4883ec204c896c2418", &nops(8)]),
            false,
            &[],
        )
        .unwrap();
        assert_eq!(
            assembly(&window),
            ["subq $0x20, %rsp", "movq %r13, 0x18(%rsp)"]
        );
    }

    #[test]
    fn single_long_instruction_is_enough() {
        let (window, _) =
            plan(&code(&[ENDBR_HEX, "f6878800000003", &nops(8)]), false, &[]).unwrap();
        assert_eq!(assembly(&window), ["testb $3, 0x88(%rdi)"]);
    }

    #[test]
    fn register_moves_are_replayed_in_att_operand_order() {
        let (window, _) = plan(&code(&[ENDBR_HEX, "4156534889fb"]), false, &[]).unwrap();
        assert_eq!(
            assembly(&window),
            ["pushq %r14", "pushq %rbx", "movq %rdi, %rbx"]
        );
    }

    #[test]
    fn function_without_endbr_starts_at_its_entry() {
        let (window, _) = plan(&code(&["554889e54157"]), false, &[]).unwrap();
        assert_eq!(window.skip, 0);
        assert_eq!(hex(&window.data), "554889e54157");
    }

    #[test]
    fn rip_relative_operand_is_reached_through_a_scratch_pointer() {
        let counter = BASE + 0x2000;
        let bytes = code(&[
            ENDBR_HEX,
            "658b05",
            &relative(counter, BASE + 4 + 7),
            &nops(8),
        ]);
        let (window, interner) = plan(&bytes, false, &[("counter", counter, 4)]).unwrap();
        assert_eq!(
            assembly(&window),
            [
                "movq xcr0_probe_targets+8*0(%rip), %r11",
                "movl %gs:(%r11), %eax"
            ]
        );
        assert_eq!(window.relocs, [(3, 7, "counter".to_string(), 0)]);
        assert_eq!(interner.targets, [("counter".to_string(), 0)]);
    }

    #[test]
    fn rip_relative_operand_with_immediate_keeps_the_displacement_base() {
        let flag = BASE + 0x3000;
        let bytes = code(&[
            ENDBR_HEX,
            "803d",
            &relative(flag, BASE + 4 + 7),
            "00",
            &nops(8),
        ]);
        let (window, _) = plan(&bytes, false, &[("flag", flag, 1)]).unwrap();
        assert_eq!(
            assembly(&window),
            ["movq xcr0_probe_targets+8*0(%rip), %r11", "cmpb $0, (%r11)"]
        );
        assert_eq!(window.relocs, [(2, 7, "flag".to_string(), 0)]);
    }

    #[test]
    fn member_of_a_larger_object_resolves_to_symbol_plus_offset() {
        let table = BASE + 0x4000;
        let bytes = code(&[
            ENDBR_HEX,
            "488b05",
            &relative(table + 8, BASE + 4 + 7),
            &nops(8),
        ]);
        let (window, interner) = plan(&bytes, false, &[("table", table, 64)]).unwrap();
        assert_eq!(window.relocs, [(3, 7, "table".to_string(), 8)]);
        assert_eq!(interner.targets, [("table".to_string(), 8)]);
    }

    #[test]
    fn targets_are_shared_between_windows() {
        let shared = BASE + 0x2000;
        let second_base = BASE + 0x100;
        let first = code(&[
            ENDBR_HEX,
            "488b05",
            &relative(shared, BASE + 4 + 7),
            &nops(8),
        ]);
        let second = code(&[
            ENDBR_HEX,
            "488b05",
            &relative(shared, second_base + 4 + 7),
            &nops(8),
        ]);
        let mut symbols = Symbols::default();
        symbols.add("first", BASE, first.len() as u64, true);
        symbols.add("second", second_base, second.len() as u64, true);
        symbols.add("shared", shared, 8, true);
        symbols.finish();
        let kernel = kernel_at(&[(BASE, first), (second_base, second)]);
        let mut interner = Interner::default();
        plan_window(&kernel, &symbols, &mut interner, "first", false).unwrap();
        plan_window(&kernel, &symbols, &mut interner, "second", false).unwrap();
        assert_eq!(interner.targets, [("shared".to_string(), 0)]);
    }

    #[test]
    fn direct_call_is_replayed_as_an_indirect_call() {
        let helper = BASE + 0x500;
        let bytes = code(&[ENDBR_HEX, "e8", &relative(helper, BASE + 4 + 5), &nops(8)]);
        let (window, _) = plan(&bytes, false, &[("helper", helper, 32)]).unwrap();
        assert_eq!(
            assembly(&window),
            [
                "ANNOTATE_RETPOLINE_SAFE",
                "call *xcr0_probe_targets+8*0(%rip)"
            ]
        );
        assert_eq!(window.relocs, [(1, 5, "helper".to_string(), 0)]);
    }

    #[test]
    fn call_into_the_middle_of_a_function_is_rejected() {
        let helper = BASE + 0x500;
        let bytes = code(&[
            ENDBR_HEX,
            "e8",
            &relative(helper + 4, BASE + 4 + 5),
            &nops(8),
        ]);
        let error = plan(&bytes, false, &[("helper", helper, 32)])
            .err()
            .unwrap();
        assert!(error.contains("manual review"), "{error}");
    }

    #[test]
    fn call_to_instrumentation_stubs_is_rejected() {
        let stub = BASE + 0x500;
        let bytes = code(&[ENDBR_HEX, "e8", &relative(stub, BASE + 4 + 5), &nops(8)]);
        let error = plan(&bytes, false, &[("__fentry__", stub, 16)])
            .err()
            .unwrap();
        assert!(error.contains("manual review"), "{error}");
    }

    #[test]
    fn patchable_nops_are_rejected() {
        for encoded in ["0f1f440000", "6690", "eb00", "7500", "e900000000"] {
            let error = plan(&code(&[ENDBR_HEX, encoded, &nops(8)]), false, &[])
                .err()
                .unwrap();
            assert!(error.contains("manual review"), "{encoded}: {error}");
        }
    }

    #[test]
    fn prefixed_and_privileged_instructions_are_rejected() {
        for encoded in ["f0ff0500000000", "0f01d0", "c3", "ffd0"] {
            let error = plan(&code(&[ENDBR_HEX, encoded, &nops(8)]), false, &[])
                .err()
                .unwrap();
            assert!(error.contains("manual review"), "{encoded}: {error}");
        }
    }

    #[test]
    fn window_using_the_scratch_register_with_a_pointer_load_is_rejected() {
        let flag = BASE + 0x3000;
        let bytes = code(&[ENDBR_HEX, "4c8b1d", &relative(flag, BASE + 4 + 7), &nops(8)]);
        let error = plan(&bytes, false, &[("flag", flag, 8)]).err().unwrap();
        assert!(error.contains("scratch register"), "{error}");
    }

    #[test]
    fn atomic_window_includes_the_endbr_and_spans_eight_bytes() {
        let (window, _) = plan(&code(&[ENDBR_HEX, "4883ec18", &nops(8)]), true, &[]).unwrap();
        assert_eq!(window.skip, 0);
        assert_eq!(hex(&window.data), "f30f1efa4883ec18");
        assert_eq!(window.instructions[0], "endbr64");
        assert_eq!(assembly(&window), ["subq $0x18, %rsp"]);
    }

    #[test]
    fn atomic_window_never_ends_inside_an_instruction() {
        let (window, _) = plan(&code(&[ENDBR_HEX, "5541574156", &nops(8)]), true, &[]).unwrap();
        assert_eq!(hex(&window.data), "f30f1efa5541574156");
    }

    #[test]
    fn atomic_window_without_endbr_still_spans_eight_bytes() {
        let (window, _) = plan(&code(&["554889e541574156", &nops(8)]), true, &[]).unwrap();
        assert_eq!(hex(&window.data), "554889e541574156");
    }

    fn body_with_branch(target_offset: i64) -> Vec<u8> {
        let mut body = code(&[ENDBR_HEX, "554889e54157", &nops(10)]);
        let displacement = (BASE as i64 + target_offset) - (BASE as i64 + body.len() as i64 + 2);
        body.push(0xeb);
        body.push(displacement as i8 as u8);
        body
    }

    #[test]
    fn branch_into_the_window_is_rejected() {
        let error = plan(&body_with_branch(5), false, &[]).err().unwrap();
        assert!(error.contains("enters the patch window"), "{error}");
    }

    #[test]
    fn branch_to_the_window_start_is_allowed() {
        let (window, _) = plan(&body_with_branch(4), false, &[]).unwrap();
        assert_eq!(hex(&window.data), "554889e54157");
    }

    #[test]
    fn exact_symbol_wins_over_containing_object() {
        let mut symbols = Symbols::default();
        symbols.add("table", 0x1000, 64, true);
        symbols.add("entry", 0x1008, 8, true);
        symbols.finish();
        assert_eq!(symbols.resolve(0x1008).unwrap(), ("entry".to_string(), 0));
        assert_eq!(
            symbols.resolve(0x1010).unwrap(),
            ("table".to_string(), 0x10)
        );
    }

    #[test]
    fn alias_that_is_a_real_variable_is_preferred() {
        let mut symbols = Symbols::default();
        symbols.add("const_current_task", 0x2000, 8, true);
        symbols.add("current_task", 0x2000, 8, true);
        symbols.finish();
        assert_eq!(
            symbols.resolve(0x2000).unwrap(),
            ("current_task".to_string(), 0)
        );
    }

    #[test]
    fn ambiguous_and_compiler_renamed_symbols_are_not_used() {
        let mut symbols = Symbols::default();
        symbols.add("dup", 0x3000, 8, true);
        symbols.add("dup", 0x9000, 8, true);
        symbols.add("helper.constprop.0", 0x4000, 8, true);
        symbols.finish();
        for target in [0x3000, 0x4000] {
            assert!(symbols.resolve(target).is_err(), "{target:#x}");
        }
        assert!(symbols.address("dup").unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn first_defined_alternative_is_chosen() {
        let mut symbols = Symbols::default();
        symbols.add("text_poke_bp", 0x10, 4, true);
        symbols.finish();
        assert_eq!(symbols.choose(&TEXT_POKE_SINGLE), Some("text_poke_bp"));
        assert_eq!(symbols.choose(&TEXT_POKE_SYNC), None);
    }

    #[test]
    fn system_map_sizes_extend_to_the_next_address() {
        let mut text: String = (0..1200)
            .map(|index| format!("{:016x} t sym{index}\n", 0x1000 + 0x10 * index))
            .collect();
        text.push_str(&format!(
            "{:016x} T alias\n{:016x} U undefined\n",
            0x1000, 0
        ));
        let symbols = load_system_map(&text).unwrap();
        assert_eq!(symbols.by_name["sym0"], [(0x1000, 0x10)]);
        assert_eq!(symbols.by_name["alias"], [(0x1000, 0x10)]);
        assert!(!symbols.defined("undefined"));
    }

    #[test]
    fn stub_system_map_is_rejected() {
        let error = load_system_map(
            "ffffffffffffffff B The real System.map is in the linux-image-<version>-dbg package\n",
        )
        .err()
        .unwrap();
        assert!(error.contains("-dbg"), "{error}");
    }

    #[test]
    fn inputs_are_searched_in_distribution_locations() {
        let headers = Path::new("/lib/modules/6.12.1/build");
        let has = |list: Vec<PathBuf>, wanted: &str| list.contains(&PathBuf::from(wanted));
        assert!(has(
            boot_image_candidates(headers, "6.12.1"),
            "/lib/modules/6.12.1/vmlinuz"
        ));
        assert!(has(
            boot_image_candidates(headers, "6.12.1"),
            "/boot/vmlinuz-6.12.1"
        ));
        assert!(has(
            system_map_candidates(headers, "6.12.1"),
            "/boot/System.map-6.12.1"
        ));
        assert!(has(
            vmlinux_candidates(headers, "6.12.1"),
            "/usr/lib/debug/boot/vmlinux-6.12.1"
        ));
    }

    fn sample() -> Profile {
        let entry =
            |role: &str, bytes: &str, assembly: &[&str], relocations: Vec<RelocationEntry>| Entry {
                role: role.to_string(),
                name: role.to_string(),
                address: "0x0".into(),
                skip: 4,
                bytes: bytes.to_string(),
                instructions: Vec::new(),
                assembly: assembly.iter().map(|line| line.to_string()).collect(),
                relocations,
            };
        Profile {
            schema: SCHEMA,
            release: "test-kernel".into(),
            build_id: "a".repeat(40),
            inputs: BTreeMap::new(),
            boot_image: None,
            features: Features {
                lass: false,
                task_fpu: true,
                syscore_struct: false,
                fred: false,
                text_poke_single: "text_poke_bp".into(),
                text_poke_sync: "text_poke_sync".into(),
                text_poke_atomic: "text_poke".into(),
            },
            targets: vec![Target {
                symbol: "pcpu_hot".into(),
                addend: 8,
            }],
            entries: vec![
                entry(
                    "irqentry_enter",
                    "f6878800000003",
                    &["testb $3, 0x88(%rdi)"],
                    Vec::new(),
                ),
                entry(
                    "irqentry_nmi_enter",
                    "658b05650ff501",
                    &[
                        "movq xcr0_probe_targets+8*0(%rip), %r11",
                        "movl %gs:(%r11), %eax",
                    ],
                    vec![RelocationEntry {
                        disp: 3,
                        end: 7,
                        symbol: "pcpu_hot".into(),
                        addend: 8,
                    }],
                ),
            ],
            source_sha256: None,
            profile_sha256: None,
            vm_validated: Some(false),
        }
    }

    #[test]
    fn assembler_macros_replay_each_window() {
        let header = header_text(&sample());
        assert!(header.contains("#ifdef __ASSEMBLER__"));
        assert!(header.contains("#define XCR0_PROLOGUE_IRQENTRY_ENTER testb $3, 0x88(%rdi)"));
        assert!(header.contains(
            "#define XCR0_PROLOGUE_IRQENTRY_NMI_ENTER movq xcr0_probe_targets+8*0(%rip), %r11; movl %gs:(%r11), %eax"
        ));
    }

    #[test]
    fn tables_describe_windows_and_relocations() {
        let header = header_text(&sample());
        assert!(header.contains("xcr0_profile_lengths[] = { 7, 7 }"));
        assert!(header.contains("xcr0_profile_skips[] = { 4, 4 }"));
        assert!(header.contains("{ 1, 3, 7, 0 }"));
        assert!(header.contains("xcr0_profile_target_names[] = { \"pcpu_hot\" }"));
        assert!(header.contains("xcr0_profile_target_addends[] = { 8 }"));
        assert!(header.contains("#define XCR0_PROFILE_RELOC_COUNT 1"));
    }

    #[test]
    fn kernel_api_variants_are_exported_as_macros() {
        let header = header_text(&sample());
        assert!(header.contains("#define XCR0_HAVE_LASS 0"));
        assert!(header.contains("#define XCR0_HAVE_TASK_FPU 1"));
        assert!(header.contains("#define XCR0_SYM_TEXT_POKE_SINGLE \"text_poke_bp\""));
        assert!(header.contains("#define XCR0_TEXT_POKE_ATOMIC_CUSTOM 0"));
        assert!(header.contains("#ifndef XCR0_PROFILE_FEATURES_ONLY"));
    }

    #[test]
    fn missing_fred_hooks_leave_empty_slots() {
        let mut profile = sample();
        profile.entries.push(absent_entry("fred_exc_debug"));
        let header = header_text(&profile);
        assert!(header.contains("#define XCR0_PROFILE_FRED 0"));
        assert!(header.contains("#define XCR0_PROLOGUE_FRED_EXC_DEBUG \n"));
        assert!(header.contains("xcr0_profile_lengths[] = { 7, 7, 0 }"));
        assert!(header.contains(
            "xcr0_profile_names[] = { \"irqentry_enter\", \"irqentry_nmi_enter\", \"\" }"
        ));
        assert!(header.contains("\t{ 0 }\n"));
    }

    #[test]
    fn usable_fred_hooks_are_flagged() {
        let mut profile = sample();
        profile.features.fred = true;
        assert!(header_text(&profile).contains("#define XCR0_PROFILE_FRED 1"));
    }

    #[test]
    fn empty_relocation_and_target_tables_stay_well_formed() {
        let mut profile = sample();
        profile.targets.clear();
        profile.entries.truncate(1);
        let header = header_text(&profile);
        assert!(header.contains("#define XCR0_PROFILE_TARGET_COUNT 1"));
        assert!(header.contains("#define XCR0_PROFILE_RELOC_COUNT 0"));
        assert!(header.contains("{ 0, 0, 0, 0 }"));
    }

    fn scratch(name: &str) -> PathBuf {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-tmp")
            .join(name);
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn release_tree(name: &str, release: &str) -> PathBuf {
        let headers = scratch(name);
        fs::create_dir_all(headers.join("include/config")).unwrap();
        fs::write(
            headers.join("include/config/kernel.release"),
            format!("{release}\n"),
        )
        .unwrap();
        headers
    }

    fn inspect(headers: &Path) -> Res<Profile> {
        inspect_kernel(&Inputs {
            headers,
            image: None,
            system_map: None,
            source: "auto",
            kernel_source: None,
        })
    }

    #[test]
    fn kernels_before_6_6_are_rejected_with_a_clear_message() {
        for (index, release) in ["6.1.71-1-lts", "5.15.0-100-generic", "4.19.1"]
            .iter()
            .enumerate()
        {
            let error = inspect(&release_tree(&format!("old-{index}"), release))
                .err()
                .unwrap();
            assert!(error.contains("older than 6.6"), "{release}: {error}");
        }
    }

    #[test]
    fn supported_generations_pass_the_version_gate() {
        for (index, release) in [
            "6.6.72-1-lts",
            "6.12.107+deb13-amd64",
            "7.3.3-300.fc45.x86_64",
        ]
        .iter()
        .enumerate()
        {
            // Passing the gate reaches the missing .config.
            let error = inspect(&release_tree(&format!("new-{index}"), release))
                .err()
                .unwrap();
            assert!(error.contains(".config"), "{release}: {error}");
        }
    }

    fn approval_case() -> Profile {
        let mut profile = sample();
        profile.entries.clear();
        profile.targets.clear();
        profile.vm_validated = None;
        profile.source_sha256 = Some("b".repeat(64));
        profile
    }

    fn receipt(candidate: &Profile, result: &str) -> String {
        serde_json::json!({
            "schema": SCHEMA,
            "profile_sha256": profile_digest(candidate),
            "install_stress": result,
            "vm_log_sha256": "c".repeat(64),
        })
        .to_string()
    }

    fn receipts(name: &str, candidate: &Profile, content: &str) -> PathBuf {
        let directory = scratch(name);
        fs::write(
            directory.join(format!("{}.json", candidate.build_id)),
            content,
        )
        .unwrap();
        directory
    }

    #[test]
    fn default_build_does_not_require_receipts() {
        let mut candidate = approval_case();
        apply_approval(&mut candidate, None).unwrap();
        assert_eq!(candidate.vm_validated, Some(false));
        assert_eq!(candidate.profile_sha256, Some(profile_digest(&candidate)));
    }

    #[test]
    fn missing_optional_receipt_is_not_vm_validated() {
        let mut candidate = approval_case();
        apply_approval(&mut candidate, Some(&scratch("no-receipt"))).unwrap();
        assert_eq!(candidate.vm_validated, Some(false));
    }

    #[test]
    fn matching_receipt_is_accepted() {
        let mut candidate = approval_case();
        let directory = receipts("matching", &candidate, &receipt(&candidate, "PASS"));
        apply_approval(&mut candidate, Some(&directory)).unwrap();
        assert_eq!(candidate.vm_validated, Some(true));
    }

    #[test]
    fn changed_sources_invalidate_receipt() {
        let mut candidate = approval_case();
        let directory = receipts("changed", &candidate, &receipt(&candidate, "PASS"));
        candidate.source_sha256 = Some("d".repeat(64));
        let error = apply_approval(&mut candidate, Some(&directory)).unwrap_err();
        assert!(error.contains("Stale or invalid"), "{error}");
    }

    #[test]
    fn failed_validation_is_rejected() {
        let mut candidate = approval_case();
        let directory = receipts("failed", &candidate, &receipt(&candidate, "FAIL"));
        assert!(apply_approval(&mut candidate, Some(&directory)).is_err());
    }

    #[test]
    fn malformed_optional_receipt_is_rejected() {
        for (index, value) in ["null", "[]", "{\"schema\": 2, \"vm_log_sha256\": 123}"]
            .iter()
            .enumerate()
        {
            let mut candidate = approval_case();
            let directory = receipts(&format!("malformed-{index}"), &candidate, value);
            assert!(
                apply_approval(&mut candidate, Some(&directory)).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn unchanged_output_keeps_timestamp() {
        let output = scratch("atomic").join("profile.h");
        write_atomic(&output, "first\n").unwrap();
        let before = fs::metadata(&output).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_atomic(&output, "first\n").unwrap();
        assert_eq!(fs::metadata(&output).unwrap().modified().unwrap(), before);
        write_atomic(&output, "second\n").unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), "second\n");
    }
}
