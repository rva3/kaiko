use ahash::AHashSet;
use tracing::{debug, instrument, trace};
use yaxpeax_arm::armv7::{Opcode, Operand};

use crate::{
    Code,
    cpu_mode::CpuMode,
    phase1::{
        Metadata,
        disasm::{disassemble_arm_oneshot, disassemble_thumb_oneshot},
    },
    regext::{RegExt, RegListExt},
};

pub struct IndirectFnAnalysis {
    checked: AHashSet<u32>,
}

impl IndirectFnAnalysis {
    pub fn new() -> Self {
        Self {
            checked: AHashSet::new(),
        }
    }

    /// detect functions in the raw literals
    #[instrument(skip(self, metadata), level = "trace")]
    pub fn fns(&mut self, metadata: &Metadata) -> Vec<(u32, CpuMode)> {
        let mut out = Vec::new();

        for &raw_va in metadata.refs.values() {
            let is_thumb = raw_va & 1 != 0;
            let va = raw_va & !1;

            if !is_thumb && (va & 3) != 0 {
                continue;
            }

            if !self.checked.insert(va) {
                continue;
            }

            if metadata.blocks.contains_key(&va)
                || metadata.code_covering(va).is_some()
                || metadata.slots.contains(&va)
            {
                continue;
            }

            trace!("try {raw_va:#x}");
            let Some(off) = metadata.unmap_va(va) else {
                continue;
            };
            let Some(bytes) = metadata.data.get(off..off + 4) else {
                continue;
            };
            trace!("bounds check passed");

            let decoded = if is_thumb {
                trace!("T bit is set");
                disassemble_thumb_oneshot(bytes)
                    .ok()
                    .map(|c| (CpuMode::Thumb, c))
            } else {
                trace!("T bit is NOT set");
                disassemble_arm_oneshot(bytes)
                    .ok()
                    .map(|c| (CpuMode::Arm, c))
            };

            let Some((mode, code)) = decoded else {
                continue;
            };

            if Self::maybe_prologue(&code) && !Self::maybe_str(bytes) {
                debug!("data at {va:#x} is likely a fn");
                out.push((va, mode));
            } else {
                debug!("data at {va:#x} is not fn:");
                if !Self::maybe_prologue(&code) {
                    trace!("not prologue");
                }
                if Self::maybe_str(bytes) {
                    trace!("is a string");
                }
            }
        }

        out
    }

    /// prologue junk filter
    fn maybe_prologue(code: &Code) -> bool {
        match code.instruction.opcode {
            Opcode::PUSH => {
                if let Operand::Reg(r) = code.instruction.operands[0] {
                    r.is_lr()
                } else if let Operand::RegList(r) = code.instruction.operands[0] {
                    r.has_lr()
                } else {
                    false
                }
            }
            Opcode::MOV => true,
            // stack frame
            Opcode::SUB => {
                if let Operand::Reg(r_should_be_sp) = code.instruction.operands[0] {
                    r_should_be_sp.is_sp()
                } else {
                    false
                }
            }
            // calls & jumps
            Opcode::BL | Opcode::BLX => true,
            Opcode::B | Opcode::BX => true,
            Opcode::LDR => {
                if let Operand::Reg(r_should_be_pc) = code.instruction.operands[0]
                    && r_should_be_pc.is_pc()
                {
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// str literal junk filter
    fn maybe_str(b: &[u8]) -> bool {
        b.iter().all(|c| c.is_ascii_graphic() || *c == b' ')
    }
}
