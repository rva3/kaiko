use tracing::{debug, instrument, trace};
use yaxpeax_arm::armv7::{Opcode, Operand};

use crate::{
    Code,
    cpu_mode::CpuMode,
    phase1::{
        Metadata,
        disasm::{disassemble_arm_oneshot, disassemble_thumb_oneshot},
    },
    regext::RegExt,
};

pub struct IndirectFnAnalysis;
impl IndirectFnAnalysis {
    /// detect functions in the raw literals
    #[instrument(skip(metadata), level = "trace")]
    pub fn fns(metadata: &Metadata) -> Vec<(usize, CpuMode)> {
        metadata
            .refs
            .iter()
            // i. hate. references. for. primitives.
            .filter(|(_, va)| !metadata.bin.contains_key(&(*va & !1)))
            .filter_map(|(_, va)| -> Option<(usize, CpuMode)> {
                trace!("try {va}");
                // in binary range
                if *va >= metadata.base_address && *va < metadata.base_address + metadata.data.len()
                {
                    trace!("bounds check passed");

                    let is_thumb = va & 1 != 0;
                    let va = va & !1;

                    let off = va - metadata.base_address;
                    let value = &metadata.data[off..off + 4];

                    let (mode, code) = if is_thumb {
                        trace!("T bit is set");
                        (CpuMode::Thumb, disassemble_thumb_oneshot(value).ok()?)
                    } else {
                        trace!("T bit is NOT set");
                        (CpuMode::Arm, disassemble_arm_oneshot(value).ok()?)
                    };

                    if Self::maybe_prologue(&code) && !Self::maybe_str(value) {
                        debug!("data at {va:#x} is likely a fn");
                        Some((va, mode))
                    } else {
                        debug!("data at {va:#x} is not fn:");
                        if !Self::maybe_prologue(&code) {
                            trace!("not prologue");
                        }
                        if Self::maybe_str(value) {
                            trace!("is a string");
                        }
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// prologue junk filter
    fn maybe_prologue(code: &Code) -> bool {
        match code.instruction.opcode {
            // sometimes there's PUSH without LR
            Opcode::PUSH => true,
            // pretty common too
            Opcode::MOV => true,
            // stack frame
            Opcode::SUB => {
                if let Operand::Reg(r_should_be_sp) = code.instruction.operands[0]
                    && r_should_be_sp.is_sp()
                {
                    true
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
        b.iter().filter(|c| c.is_ascii()).count() >= 4
    }
}
