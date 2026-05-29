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
    pub fn find_fns(metadata: &Metadata) -> Vec<(u32, CpuMode)> {
        let code_blacklist = &metadata.blocks;
        let literal_blacklist = metadata.refs.values().map(|va| *va).collect::<Vec<_>>();

        let min_exec_va = metadata
            .blocks
            .iter()
            .map(|b| b.start_va())
            .min()
            .unwrap_or(metadata.base_address);
        let max_exec_va = metadata
            .blocks
            .iter()
            .map(|b| b.end_va())
            .max()
            .unwrap_or(metadata.base_address + metadata.data.len() as u32);

        debug!("allow range: {min_exec_va:#x}..={max_exec_va:#x}");

        let mut fns = Vec::new();
        let mut va = min_exec_va;

        while va < max_exec_va {
            trace!("try {va:#x}");

            if let Some(block) = code_blacklist
                .iter()
                .find(|code_blacklist| code_blacklist.range.contains(&va))
            {
                trace!("existing code at {va:#x}");
                va += if block.mode == CpuMode::Arm { 4 } else { 2 };
                continue;
            } else if literal_blacklist.contains(&va) {
                trace!("literal at {va:#x}");
                va += 4;
                continue;
            }

            let off = (va - metadata.base_address) as usize;
            let data = match metadata.data.get(off..off + 4) {
                Some(data) => {
                    if data.iter().all(|&i| i == 0 || i == 0xff) {
                        trace!("likely junk at {va:#x}");
                        va += 4;
                        continue;
                    } else {
                        data
                    }
                }
                None => {
                    trace!("out of bounds, stop");
                    break;
                }
            };

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

            if Self::strict_prologue(&code)
                && Self::dry_run(metadata, va, mode, min_exec_va, max_exec_va)
            {
                trace!("maybe fn at {va:#x}");
                fns.push((va, mode));
                va += code.instruction.len().to_const();
            } else {
                trace!("not fn at {va:#x}");
                va += 2;
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
    pub fn dry_run(metadata: &Metadata, start_va: u32, mode: CpuMode, min: u32, max: u32) -> bool {
        let mut va = start_va;
        let mut decoded = 0;
        const MAX_DEPTH: u32 = 15;

        while decoded < MAX_DEPTH {
            trace!("dry run {va:#x}");
            let offset = va.wrapping_sub(metadata.base_address) as usize;

            if va > max || va < min {
                trace!("out of bounds, stop");
                return false;
            }

            let data = if let Some(data) = metadata.data.get(offset..offset + 4) {
                data
            } else {
                trace!("data out of bounds, stop");
                return false;
            };

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
                                trace!("hit POP {{PC}}, stop");
                                return true;
                            }
                        }
                    }
                    Opcode::BX => {
                        if let Operand::Reg(r) = code.instruction.operands[0] {
                            if r.is_lr() {
                                trace!("hit BX LR, stop");
                                return true;
                            }
                        }
                    }
                    Opcode::B | Opcode::BL | Opcode::BLX => {
                        if let Operand::BranchOffset(imm) | Operand::BranchThumbOffset(imm) =
                            code.instruction.operands[0]
                        {
                            let target = code.pc().wrapping_add_signed(imm);

                            if target < metadata.base_address
                                || target >= metadata.base_address + metadata.data.len() as u32
                            {
                                trace!("hit junk branch/call, stop");
                                return false; // junk
                            }
                        }
                    }
                    _ => (),
                }

                va += code.instruction.len().to_const();
                decoded += 1;
            } else {
                trace!("failed to decode ({va:#x}), stop");
                return false;
            }
        }

        trace!("ok");
        // likely a fn
        true
    }
}
