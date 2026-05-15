use tracing::debug;
use yaxpeax_arm::armv7::{Opcode, Operand, Reg};

use crate::{
    phase2::{BasicBlockView, Metadata},
    regext::RegExt,
};

pub struct RefFixup;

impl RefFixup {
    pub fn fix_refs(metadata: &mut Metadata) {
        let mut pending = Vec::new();

        for b in &metadata.blocks {
            let view = BasicBlockView::new(metadata, b);
            for code in view.code() {
                // ADD Rn, PC is common pattern for PIC
                if code.instruction.opcode == Opcode::ADD
                    && let Operand::Reg(rn) = code.instruction.operands[0]
                    && let Operand::Reg(r_should_be_pc) = code.instruction.operands[1]
                    && r_should_be_pc.is_pc()
                {
                    // if there's LDR before ADR with the same Rn, then it's definitely what we want
                    if let Some(ldr) = view.code().rev().skip_while(|c| c.va >= code.va).find(|c| {
                        c.instruction.opcode == Opcode::LDR
                            && c.instruction.operands[0] == Operand::Reg(Reg::from_u8(rn.number()))
                    }) {
                        if metadata.refs.contains_key(&ldr.va) {
                            pending.push((ldr.va, code.pc()));
                        }
                    }
                }
            }
        }

        // apply fixups
        for (ldr_va, pc_value) in pending {
            debug!("fixed ref from {:#x} to {:#x}", ldr_va, pc_value);
            metadata.refs.entry(ldr_va).and_modify(|va| {
                *va += pc_value;
                debug!("final value: {:#x}", va);
            });
        }
    }
}
