//! A small safe wrapper around the parts of Capstone that the profile planner needs.
use std::ffi::CStr;

use capstone_sys as cs;

pub const GRP_JUMP: u8 = 1;
pub const GRP_CALL: u8 = 2;
pub const GRP_BRANCH_RELATIVE: u8 = 7;

pub const INS_ADD: u32 = cs::x86_insn::X86_INS_ADD as u32;
pub const INS_CALL: u32 = cs::x86_insn::X86_INS_CALL as u32;
pub const INS_CMP: u32 = cs::x86_insn::X86_INS_CMP as u32;
pub const INS_DEC: u32 = cs::x86_insn::X86_INS_DEC as u32;
pub const INS_INC: u32 = cs::x86_insn::X86_INS_INC as u32;
pub const INS_MOV: u32 = cs::x86_insn::X86_INS_MOV as u32;
pub const INS_PUSH: u32 = cs::x86_insn::X86_INS_PUSH as u32;
pub const INS_SUB: u32 = cs::x86_insn::X86_INS_SUB as u32;
pub const INS_TEST: u32 = cs::x86_insn::X86_INS_TEST as u32;

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Reg {
        name: String,
        size: u8,
    },
    Imm {
        value: i64,
        size: u8,
    },
    Mem {
        base: Option<String>,
        index: Option<String>,
        segment: Option<String>,
        disp: i64,
        size: u8,
    },
}

impl Operand {
    pub fn size(&self) -> u8 {
        match self {
            Self::Reg { size, .. } | Self::Imm { size, .. } | Self::Mem { size, .. } => *size,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub id: u32,
    pub address: u64,
    pub size: usize,
    pub mnemonic: String,
    pub op_str: String,
    pub prefix: [u8; 4],
    pub operands: Vec<Operand>,
    pub disp_offset: usize,
    pub disp_size: usize,
    pub groups: Vec<u8>,
}

impl Instruction {
    /// The instruction as the assembler wants it.
    pub fn text(&self) -> String {
        format!("{} {}", self.mnemonic, self.op_str)
            .trim()
            .to_string()
    }

    pub fn in_group(&self, group: u8) -> bool {
        self.groups.contains(&group)
    }
}

pub struct Decoder {
    handle: cs::csh,
}

fn text(raw: &[libc::c_char]) -> String {
    // SAFETY: Capstone terminates both text buffers.
    unsafe { CStr::from_ptr(raw.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

impl Decoder {
    /// An x86-64 decoder with AT&T syntax and operand details.
    pub fn new() -> Self {
        let mut handle: cs::csh = 0;
        // SAFETY: plain FFI calls on a handle this function owns.
        unsafe {
            let result = cs::cs_open(
                cs::cs_arch::CS_ARCH_X86,
                cs::cs_mode::CS_MODE_64,
                &mut handle,
            );
            assert_eq!(result, cs::cs_err::CS_ERR_OK, "cs_open failed");
            cs::cs_option(
                handle,
                cs::cs_opt_type::CS_OPT_SYNTAX,
                cs::cs_opt_value::CS_OPT_SYNTAX_ATT as usize,
            );
            cs::cs_option(
                handle,
                cs::cs_opt_type::CS_OPT_DETAIL,
                cs::cs_opt_value::CS_OPT_ON as usize,
            );
        }
        Self { handle }
    }

    /// Skip undecodable bytes instead of stopping at them.
    pub fn skipdata(self) -> Self {
        // SAFETY: plain FFI call.
        unsafe {
            cs::cs_option(
                self.handle,
                cs::cs_opt_type::CS_OPT_SKIPDATA,
                cs::cs_opt_value::CS_OPT_ON as usize,
            );
        }
        self
    }

    fn register(&self, register: u32) -> Option<String> {
        if register == 0 {
            return None;
        }
        // SAFETY: Capstone returns a static string or null.
        let name = unsafe { cs::cs_reg_name(self.handle, register) };
        (!name.is_null()).then(|| {
            unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Decodes `code` from `address` until it ends or a byte sequence is not an instruction.
    pub fn disassemble(&self, code: &[u8], address: u64) -> Vec<Instruction> {
        let mut result = Vec::new();
        // SAFETY: the instruction buffer is allocated and freed here; the iterator advances
        // `pointer`, `remaining` and `cursor` within `code`.
        unsafe {
            let insn = cs::cs_malloc(self.handle);
            let mut pointer = code.as_ptr();
            let mut remaining = code.len();
            let mut cursor = address;
            while remaining > 0
                && cs::cs_disasm_iter(self.handle, &mut pointer, &mut remaining, &mut cursor, insn)
            {
                let item = &*insn;
                let mut operands = Vec::new();
                let mut prefix = [0u8; 4];
                let mut disp_offset = 0;
                let mut disp_size = 0;
                let mut groups = Vec::new();
                if item.id != 0 && !item.detail.is_null() {
                    let detail = &*item.detail;
                    let x86 = &detail.__bindgen_anon_1.x86;
                    prefix = x86.prefix;
                    disp_offset = x86.encoding.disp_offset as usize;
                    disp_size = x86.encoding.disp_size as usize;
                    groups = detail.groups[..detail.groups_count as usize].to_vec();
                    for operand in &x86.operands[..x86.op_count as usize] {
                        let size = operand.size;
                        operands.push(match operand.type_ {
                            cs::x86_op_type::X86_OP_REG => Operand::Reg {
                                name: self
                                    .register(operand.__bindgen_anon_1.reg)
                                    .unwrap_or_default(),
                                size,
                            },
                            cs::x86_op_type::X86_OP_IMM => Operand::Imm {
                                value: operand.__bindgen_anon_1.imm,
                                size,
                            },
                            cs::x86_op_type::X86_OP_MEM => {
                                let mem = operand.__bindgen_anon_1.mem;
                                Operand::Mem {
                                    base: self.register(mem.base),
                                    index: self.register(mem.index),
                                    segment: self.register(mem.segment),
                                    disp: mem.disp,
                                    size,
                                }
                            }
                            _ => continue,
                        });
                    }
                }
                result.push(Instruction {
                    id: item.id,
                    address: item.address,
                    size: item.size as usize,
                    mnemonic: text(&item.mnemonic),
                    op_str: text(&item.op_str),
                    prefix,
                    operands,
                    disp_offset,
                    disp_size,
                    groups,
                });
            }
            cs::cs_free(insn, 1);
        }
        result
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: the handle was opened in `new` and is closed once.
        unsafe {
            cs::cs_close(&mut self.handle);
        }
    }
}
