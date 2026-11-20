//! A small ELF reader for the runtime audit: dynamic dependencies and the ISA requirement note.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;
const X86_ISA_NEEDED_V4: u32 = 8;
/// Larger tables would only come from a corrupt header.
const MAX_TABLE: u64 = 256 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Info {
    pub bits: u32,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub needs_x86_64_v4: bool,
}

struct Segment {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

fn read_at(file: &File, offset: u64, length: u64) -> Result<Vec<u8>, String> {
    if length > MAX_TABLE {
        return Err("ELF table is implausibly large".into());
    }
    let mut buffer = vec![0u8; length as usize];
    file.read_exact_at(&mut buffer, offset)
        .map_err(|error| format!("truncated ELF file: {error}"))?;
    Ok(buffer)
}

fn parse_segment(entry: &[u8], bits: u32) -> Option<Segment> {
    if bits == 64 {
        Some(Segment {
            kind: u32_at(entry, 0)?,
            offset: u64_at(entry, 8)?,
            vaddr: u64_at(entry, 16)?,
            filesz: u64_at(entry, 32)?,
        })
    } else {
        Some(Segment {
            kind: u32_at(entry, 0)?,
            offset: u64::from(u32_at(entry, 4)?),
            vaddr: u64::from(u32_at(entry, 8)?),
            filesz: u64::from(u32_at(entry, 16)?),
        })
    }
}

fn c_string(table: &[u8], start: usize) -> Result<String, String> {
    let tail = table
        .get(start..)
        .ok_or("string offset outside the string table")?;
    let end = tail
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn requires_v4(notes: &[u8], bits: u32) -> bool {
    let property_align = if bits == 64 { 8 } else { 4 };
    let mut at = 0usize;
    while let (Some(name_size), Some(desc_size), Some(kind)) = (
        u32_at(notes, at),
        u32_at(notes, at + 4),
        u32_at(notes, at + 8),
    ) {
        let name_start = at + 12;
        let desc_start = name_start + (name_size as usize).next_multiple_of(4);
        let Some(desc) = notes.get(desc_start..desc_start + desc_size as usize) else {
            return false;
        };
        let name = notes.get(name_start..name_start + name_size as usize);
        if kind == NT_GNU_PROPERTY_TYPE_0 && name.is_some_and(|name| name.starts_with(b"GNU")) {
            let mut property = 0usize;
            while let (Some(property_kind), Some(size)) =
                (u32_at(desc, property), u32_at(desc, property + 4))
            {
                let data = desc.get(property + 8..property + 8 + size as usize);
                if property_kind == GNU_PROPERTY_X86_ISA_1_NEEDED
                    && let Some(flags) = data.and_then(|data| u32_at(data, 0))
                    && flags & X86_ISA_NEEDED_V4 != 0
                {
                    return true;
                }
                property += 8 + (size as usize).next_multiple_of(property_align);
            }
        }
        at = desc_start + (desc_size as usize).next_multiple_of(4);
    }
    false
}

/// Reads the dynamic section and notes of `path`; `None` when it is not an ELF file.
pub fn inspect(path: &Path) -> Result<Option<Info>, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    inspect_file(&file).map_err(|error| format!("{}: {error}", path.display()))
}

fn inspect_file(file: &File) -> Result<Option<Info>, String> {
    let mut ident = [0u8; 16];
    if file.read_exact_at(&mut ident, 0).is_err() || &ident[..4] != b"\x7fELF" {
        return Ok(None);
    }
    let bits = match ident[4] {
        1 => 32,
        2 => 64,
        other => return Err(format!("invalid ELF class {other}")),
    };
    if ident[5] != 1 {
        return Err("only little-endian ELF files are supported".into());
    }
    let header = read_at(file, 0, if bits == 64 { 64 } else { 52 })?;
    let (table, size, count) = if bits == 64 {
        (
            u64_at(&header, 0x20),
            u16_at(&header, 0x36),
            u16_at(&header, 0x38),
        )
    } else {
        (
            u32_at(&header, 0x1c).map(u64::from),
            u16_at(&header, 0x2a),
            u16_at(&header, 0x2c),
        )
    };
    let (table, size, count) = (
        table.ok_or("truncated ELF header")?,
        u64::from(size.ok_or("truncated ELF header")?),
        u64::from(count.ok_or("truncated ELF header")?),
    );
    let mut segments = Vec::new();
    if count > 0 {
        let headers = read_at(file, table, size * count)?;
        for entry in headers.chunks(size as usize) {
            segments.push(parse_segment(entry, bits).ok_or("truncated program header")?);
        }
    }

    let mut info = Info {
        bits,
        needed: Vec::new(),
        soname: None,
        needs_x86_64_v4: false,
    };
    for segment in segments.iter().filter(|segment| segment.kind == PT_NOTE) {
        let notes = read_at(file, segment.offset, segment.filesz)?;
        info.needs_x86_64_v4 |= requires_v4(&notes, bits);
    }
    let Some(dynamic) = segments.iter().find(|segment| segment.kind == PT_DYNAMIC) else {
        return Ok(Some(info));
    };
    let entries = read_at(file, dynamic.offset, dynamic.filesz)?;
    let width = if bits == 64 { 8 } else { 4 };
    let (mut strtab, mut strsz) = (None, 0u64);
    let mut names = Vec::new();
    for entry in entries.chunks_exact(width * 2) {
        let (tag, value) = if bits == 64 {
            (u64_at(entry, 0), u64_at(entry, 8))
        } else {
            (
                u32_at(entry, 0).map(u64::from),
                u32_at(entry, 4).map(u64::from),
            )
        };
        let (Some(tag), Some(value)) = (tag, value) else {
            break;
        };
        match tag {
            DT_NULL => break,
            DT_NEEDED | DT_SONAME => names.push((tag, value)),
            DT_STRTAB => strtab = Some(value),
            DT_STRSZ => strsz = value,
            _ => {}
        }
    }
    if names.is_empty() {
        return Ok(Some(info));
    }
    let address = strtab.ok_or("dynamic section without a string table")?;
    let offset = segments
        .iter()
        .filter(|segment| segment.kind == PT_LOAD)
        .find(|segment| segment.vaddr <= address && address < segment.vaddr + segment.filesz)
        .map(|segment| address - segment.vaddr + segment.offset)
        .ok_or("string table outside every loadable segment")?;
    let strings = read_at(file, offset, strsz)?;
    for (tag, value) in names {
        let name = c_string(&strings, value as usize)?;
        if tag == DT_NEEDED {
            info.needed.push(name);
        } else {
            info.soname = Some(name);
        }
    }
    Ok(Some(info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// An ELF64 file with one loadable segment that spans the file, a dynamic section and a note.
    fn elf64(needed: &[&str], soname: Option<&str>, isa_needed: Option<u32>) -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut offsets = Vec::new();
        for name in needed.iter().copied().chain(soname) {
            offsets.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut note = Vec::new();
        if let Some(flags) = isa_needed {
            push_u32(&mut note, 4);
            push_u32(&mut note, 16);
            push_u32(&mut note, NT_GNU_PROPERTY_TYPE_0);
            note.extend_from_slice(b"GNU\0");
            push_u32(&mut note, GNU_PROPERTY_X86_ISA_1_NEEDED);
            push_u32(&mut note, 4);
            push_u32(&mut note, flags);
            push_u32(&mut note, 0);
        }
        let phdrs = 64u64;
        let strtab = phdrs + 3 * 56;
        let note_at = strtab + strings.len() as u64;
        let dynamic = note_at + note.len() as u64;
        let mut entries = Vec::new();
        for (index, _) in needed.iter().enumerate() {
            push_u64(&mut entries, DT_NEEDED);
            push_u64(&mut entries, offsets[index]);
        }
        if soname.is_some() {
            push_u64(&mut entries, DT_SONAME);
            push_u64(&mut entries, *offsets.last().unwrap());
        }
        push_u64(&mut entries, DT_STRTAB);
        push_u64(&mut entries, strtab);
        push_u64(&mut entries, DT_STRSZ);
        push_u64(&mut entries, strings.len() as u64);
        push_u64(&mut entries, DT_NULL);
        push_u64(&mut entries, 0);
        let total = dynamic + entries.len() as u64;

        let mut out = b"\x7fELF\x02\x01\x01".to_vec();
        out.resize(16, 0);
        push_u16(&mut out, 3);
        push_u16(&mut out, 62);
        push_u32(&mut out, 1);
        push_u64(&mut out, 0);
        push_u64(&mut out, phdrs);
        push_u64(&mut out, 0);
        push_u32(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 56);
        push_u16(&mut out, 3);
        push_u16(&mut out, 64);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        for (kind, offset, size) in [
            (PT_LOAD, 0, total),
            (PT_NOTE, note_at, note.len() as u64),
            (PT_DYNAMIC, dynamic, entries.len() as u64),
        ] {
            push_u32(&mut out, kind);
            push_u32(&mut out, 4);
            push_u64(&mut out, offset);
            push_u64(&mut out, offset);
            push_u64(&mut out, offset);
            push_u64(&mut out, size);
            push_u64(&mut out, size);
            push_u64(&mut out, 8);
        }
        out.extend_from_slice(&strings);
        out.extend_from_slice(&note);
        out.extend_from_slice(&entries);
        out
    }

    fn inspect_bytes(name: &str, bytes: &[u8]) -> Result<Option<Info>, String> {
        let path = crate::scratch(name).join("file");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        inspect(&path)
    }

    #[test]
    fn reads_needed_names_and_soname() {
        let info = inspect_bytes(
            "elf-deps",
            &elf64(&["libc.so.6", "libm.so.6"], Some("libfoo.so.1"), None),
        )
        .unwrap()
        .unwrap();
        assert_eq!(info.bits, 64);
        assert_eq!(info.needed, ["libc.so.6", "libm.so.6"]);
        assert_eq!(info.soname.as_deref(), Some("libfoo.so.1"));
        assert!(!info.needs_x86_64_v4);
    }

    #[test]
    fn explicit_x86_64_v4_requirement_is_detected() {
        let v4 = inspect_bytes("elf-v4", &elf64(&[], None, Some(8 | 1)))
            .unwrap()
            .unwrap();
        assert!(v4.needs_x86_64_v4);
        let v3 = inspect_bytes("elf-v3", &elf64(&[], None, Some(4 | 1)))
            .unwrap()
            .unwrap();
        assert!(!v3.needs_x86_64_v4);
    }

    #[test]
    fn other_files_are_not_elf() {
        assert_eq!(
            inspect_bytes("elf-text", b"GROUP ( libc.so.6 )").unwrap(),
            None
        );
        assert_eq!(inspect_bytes("elf-empty", b"").unwrap(), None);
    }

    #[test]
    fn corrupt_files_are_errors_not_panics() {
        let mut bytes = elf64(&["libc.so.6"], None, None);
        bytes.truncate(100);
        assert!(inspect_bytes("elf-truncated", &bytes).is_err());
        let mut bytes = elf64(&["libc.so.6"], None, None);
        bytes[4] = 9;
        assert!(inspect_bytes("elf-class", &bytes).is_err());
    }

    #[test]
    fn a_real_system_library_is_understood() {
        let Some(path) = ["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
        else {
            return;
        };
        let info = inspect(path).unwrap().unwrap();
        assert_eq!(info.bits, 64);
        assert_eq!(info.soname.as_deref(), Some("libc.so.6"));
    }
}
