use tracing::{debug, trace};
use yaxpeax_arch::LengthedInstruction;
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

pub struct BlindAnalysis;
impl BlindAnalysis {
    pub fn find_fns(metadata: &Metadata) -> Vec<(usize, CpuMode)> {
        let code_blacklist = &metadata.blocks;
        let literal_blacklist = metadata.refs.values().map(|va| *va).collect::<Vec<_>>();

        let mut fns = Vec::new();
        // range is aligned by 2 because some thumb functions are not aligned to 4
        let mut va = metadata.base_address;
        while va < metadata.base_address + metadata.data.len() {
            trace!("try {va:#x}");

            if let Some(block) = code_blacklist
                .iter()
                .find(|code_blacklist| code_blacklist.range.contains(&va))
            {
                trace!(
                    "existing code at {va:#x}, blacklisted by {:#x}..={:#x}",
                    block.start_va(),
                    block.end_va()
                );
                va += if block.mode == CpuMode::Arm { 4 } else { 2 };
                continue;
            } else if literal_blacklist.contains(&va) {
                let size = if let Some(referenced_by) = metadata
                    .refs
                    .iter()
                    .find_map(|(&caller_va, &literal_va)| (literal_va == va).then_some(caller_va))
                    && let Some(code) = metadata.bin.get(&referenced_by)
                {
                    code.instruction.len().to_const() as usize
                } else {
                    4 // safe
                };
                trace!("literal at {va:#x} with {size:#x} size");
                va += size;
                continue;
            }

            let off = va - metadata.base_address;
            if off + 4 >= metadata.data.len() {
                debug!("end");
                break;
            }

            let data = &metadata.data[off..off + 4];
            if data.iter().all(|&i| i == 0 || i == 0xff) {
                debug!("likely a junk");
                va += 4;
                continue;
            }

            let (code, mode) = match disassemble_thumb_oneshot(data) {
                Ok(code) => (code, CpuMode::Thumb),
                Err(_) => match disassemble_arm_oneshot(data) {
                    Ok(code) => (code, CpuMode::Arm),
                    Err(_) => {
                        trace!("invalid code at {va:#x}");
                        va += 2; // thumb align
                        continue;
                    }
                },
            };

            if Self::strict_prologue(&code) && Self::dry_run(metadata, va, mode) {
                trace!("maybe fn at {va:#x}");
                fns.push((va, mode));
                va += code.instruction.len().to_const() as usize;
            } else {
                trace!("not a fn at {va:#x}");
                va += 2; // might be invalid opcode
            }
        }

        fns
    }

    fn strict_prologue(code: &Code) -> bool {
        match code.instruction.opcode {
            // saved LR
            Opcode::PUSH => {
                if let Operand::RegList(list) = code.instruction.operands[0] {
                    list.has_lr()
                } else {
                    false
                }
            }
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
            _ => false,
        }
    }

    /// test if it's actual fn
    fn dry_run(metadata: &Metadata, start_va: usize, mode: CpuMode) -> bool {
        let mut va = start_va;
        let mut decoded = 0;
        const MAX_DEPTH: usize = 15;

        while decoded < MAX_DEPTH {
            let offset = va.wrapping_sub(metadata.base_address);

            if offset + 4 > metadata.data.len() {
                return false;
            }

            let data = &metadata.data[offset..offset + 4];

            let code = match mode {
                CpuMode::Thumb => disassemble_thumb_oneshot(data).ok(),
                CpuMode::Arm => disassemble_arm_oneshot(data).ok(),
            };

            if let Some(mut code) = code {
                code.va = va;

                match code.instruction.opcode {
                    // epilogue is good
                    Opcode::POP => {
                        if let Operand::RegList(list) = code.instruction.operands[0] {
                            if list.has_pc() {
                                return true;
                            }
                        }
                    }
                    Opcode::BX => {
                        if let Operand::Reg(r) = code.instruction.operands[0] {
                            if r.is_lr() {
                                return true;
                            }
                        }
                    }
                    Opcode::B => {
                        if let Operand::BranchOffset(imm) | Operand::BranchThumbOffset(imm) =
                            code.instruction.operands[0]
                        {
                            let target = code.pc().wrapping_add_signed(imm as isize);

                            if target < metadata.base_address
                                || target >= metadata.base_address + metadata.data.len()
                            {
                                return false; // junk
                            }
                        }
                    }
                    _ => {}
                }

                va += code.instruction.len().to_const() as usize;
                decoded += 1;
            } else {
                return false;
            }
        }

        // likely a fn
        true
    }
}
