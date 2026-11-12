use std::ops::Not;

use yaxpeax_arm::armv7::{Opcode, Operand};

use crate::Code;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMode {
    Arm,
    Thumb,
}

impl From<&Code> for CpuMode {
    fn from(value: &Code) -> Self {
        if value.instruction().thumb() {
            CpuMode::Thumb
        } else {
            CpuMode::Arm
        }
    }
}

impl CpuMode {
    #[must_use]
    pub fn from_code_and_va(code: &Code, va: u32) -> Self {
        if va & 1 != 0 {
            CpuMode::Thumb
        } else {
            let v = Self::from(code);
            match code.instruction.opcode {
                // BLX unconditionally exchanges instruction set
                // BX, BLX, LDR PC use bit 0 of target address
                Opcode::BLX if !matches!(code.instruction.operands[0], Operand::Reg(_)) => !v,
                Opcode::BX | Opcode::BLX | Opcode::LDR => CpuMode::Arm,
                _ => v,
            }
        }
    }

    #[must_use]
    pub fn align_va_on_switch(&self, to: &Self, va: u32) -> u32 {
        match (self, to) {
            // thumb align is 2 bytes
            (Self::Arm, Self::Thumb) => va & !1,
            // arm align is 4 bytes
            (Self::Thumb, Self::Arm) => va & !3,
            // just clear thumb bit
            (_, _) => va & !1,
        }
    }
}

impl Not for CpuMode {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Self::Arm => Self::Thumb,
            Self::Thumb => Self::Arm,
        }
    }
}
