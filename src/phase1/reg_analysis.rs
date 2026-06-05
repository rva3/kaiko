use std::fmt::Display;

use tracing::trace;
use yaxpeax_arm::armv7::{Opcode, Operand, Reg};

use crate::{Code, ext::dataref::a32_ldr_data, regext::RegExt};

pub type RegisterState = [Value; 16];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Value {
    #[default]
    /// Not yet analyzed
    Uninitialized,
    /// Unknown value
    Unknown,
    /// Constant
    Immediate(u32),
    /// Value from `base` with `offset` without derefencing
    RegisterOffset { r: Reg, offset: i32 },
    /// Dereference from `r` with `offset`
    Deref { r: Reg, offset: i32 },
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Uninitialized => write!(f, "Uninitialized"),
            Value::Unknown => write!(f, "Unknown"),
            Value::Immediate(imm) => write!(f, "Immediate ({imm:#x})"),
            Value::RegisterOffset { r, offset } => {
                write!(f, "Offset from r{} with {offset:#x}", r.number())
            }
            Value::Deref { r, offset } => {
                write!(f, "Dereference r{} with {offset:#x} offset", r.number())
            }
        }
    }
}

impl Value {
    pub fn merge(&self, other: &Self) -> Self {
        match (self, other) {
            // select known state if any is uninit
            (Value::Uninitialized, x) | (x, Value::Uninitialized) => x.clone(),

            // equal states
            (a, b) if a == b => a.clone(),

            _ => Value::Unknown,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RegWriteTracker {
    regs: RegisterState,
}

impl RegWriteTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_regs(regs: [Value; 16]) -> Self {
        Self { regs }
    }

    pub fn immediate(&mut self, reg: u8, value: u32) {
        self.regs[reg as usize] = Value::Immediate(value);
    }

    pub fn register_offset(&mut self, reg: u8, r: Reg, offset: i32) {
        self.regs[reg as usize] = Value::RegisterOffset { r, offset }
    }

    pub fn deref(&mut self, reg: u8, r: Reg, offset: i32) {
        self.regs[reg as usize] = Value::Deref { r, offset };
    }

    pub fn call(&mut self) {
        for i in 0..=3 {
            self.regs[i] = Value::Unknown;
        }
    }

    pub fn get(&self, reg: u8) -> Value {
        self.regs[reg as usize].clone()
    }

    pub fn try_get_imm(&self, reg: Reg, base_address: u32, data: &[u8]) -> Option<u32> {
        let mut visited = [false; 16];
        self.try_get_imm_recursive(reg, base_address, data, &mut visited)
    }

    fn try_get_imm_recursive(
        &self,
        reg: Reg,
        base_address: u32,
        data: &[u8],
        visited: &mut [bool; 16],
    ) -> Option<u32> {
        let r = reg.number() as usize;

        if visited[r] {
            trace!("cycle detected at r{}", r);
            return None;
        }

        // lock
        visited[r] = true;

        let result = match self.get(reg.number()) {
            Value::Uninitialized | Value::Unknown => {
                if reg.is_pc() {
                    unreachable!("PC should be known");
                } else {
                    None
                }
            }
            Value::Immediate(imm) => Some(imm),
            Value::RegisterOffset { r, offset } => self
                .try_get_imm_recursive(r, base_address, data, visited)
                .map(|v| v.wrapping_add_signed(offset)),
            Value::Deref { r, offset } => {
                let ptr = self
                    .try_get_imm_recursive(r, base_address, data, visited)?
                    .wrapping_add_signed(offset);

                let load = ptr.checked_sub(base_address)? as usize;
                data.get(load..load + 4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            }
        };

        // unlock
        visited[r] = false;
        result
    }

    pub fn snapshot(&self) -> RegisterState {
        self.regs.clone()
    }

    pub fn merge(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for i in 0..16 {
            let merged = self.regs[i].merge(&other.regs[i]);
            if self.regs[i] != merged {
                self.regs[i] = merged;
                changed = true;
            }
        }
        changed
    }

    pub fn step(&mut self, code: &Code, data: &[u8], base_address: u32) {
        self.immediate(15, code.pc() as u32);

        trace!("register analysis: step in {code}");
        match code.instruction.opcode {
            Opcode::MOV => {
                if let Operand::Reg(r) = code.instruction.operands[0] {
                    if let Operand::Reg(rm) = code.instruction.operands[1] {
                        trace!("MOV: copy r{} to {}", rm.number(), r.number());
                        self.regs[r.number() as usize] = self.regs[rm.number() as usize].clone();
                    } else if let Operand::Imm12(imm) = code.instruction.operands[1] {
                        trace!("MOV: {imm:#x} (imm12) to {}", r.number());
                        self.immediate(r.number(), imm as u32);
                    } else if let Operand::Imm32(imm) = code.instruction.operands[1] {
                        trace!("MOV: {imm:#x} (imm32) to {}", r.number());
                        self.immediate(r.number(), imm);
                    }
                }
            }
            Opcode::MOVT => {
                if let Operand::Reg(r) = code.instruction.operands[0]
                    && let Operand::Imm32(imm) = code.instruction.operands[1]
                    && let Value::Immediate(existing) = self.get(r.number())
                {
                    trace!("MOVT: {imm:#x} to {}", r.number());
                    self.immediate(r.number(), existing | (imm << 16));
                }
            }
            Opcode::BL | Opcode::BLX => {
                trace!("BX/BL/BLX: call");
                self.call();
            }
            Opcode::LDR => {
                if let Operand::Reg(rt) = code.instruction.operands[0] {
                    // for immediate
                    let mut resolved_val: Option<u32> = None;
                    // for deref
                    let mut fallback_deref: Option<(Reg, i32)> = None;

                    match code.instruction.operands[1] {
                        // LDR Rt, [Rn, #imm]
                        Operand::RegDerefPreindexOffset(reg, imm, up, _) => {
                            let offset = if up { imm as i32 } else { -(imm as i32) };

                            if reg.is_pc() {
                                let align_pc = code.pc() & !3;
                                let bin_offset = align_pc
                                    .wrapping_sub(base_address)
                                    .wrapping_add_signed(offset);
                                trace!(
                                    "LDR: literal load at {code} for {bin_offset:#x} to {}",
                                    rt.number()
                                );
                                if let Some(val) = a32_ldr_data(
                                    &data[bin_offset as usize..],
                                    code.instruction.opcode,
                                ) {
                                    resolved_val = Some(val);
                                }
                            } else {
                                if let Some(base_imm) = self.try_get_imm(reg, base_address, data) {
                                    let ptr = base_imm.wrapping_add_signed(offset);
                                    if let Some(load_idx) = ptr.checked_sub(base_address) {
                                        if let Some(bytes) =
                                            data.get(load_idx as usize..load_idx as usize + 4)
                                        {
                                            resolved_val =
                                                Some(u32::from_le_bytes(bytes.try_into().unwrap()));
                                        }
                                    }
                                }

                                if resolved_val.is_none() && rt != reg {
                                    fallback_deref = Some((reg, offset));
                                }
                            }
                        }
                        // LDR Rt, [Rn, Rm]
                        Operand::RegDerefPreindexReg(reg, rm, up, _) => {
                            if let (Some(base_imm), Some(index_imm)) = (
                                self.try_get_imm(reg, base_address, data),
                                self.try_get_imm(rm, base_address, data),
                            ) {
                                let offset = if up {
                                    index_imm as i32
                                } else {
                                    -(index_imm as i32)
                                };
                                let ptr = base_imm.wrapping_add_signed(offset);
                                if let Some(load_idx) = ptr.checked_sub(base_address) {
                                    if let Some(bytes) =
                                        data.get(load_idx as usize..load_idx as usize + 4)
                                    {
                                        resolved_val =
                                            Some(u32::from_le_bytes(bytes.try_into().unwrap()));
                                    }
                                }
                            }

                            if resolved_val.is_none() && rt != reg {
                                if let Some(index_imm) = self.try_get_imm(rm, base_address, data) {
                                    let offset = if up {
                                        index_imm as i32
                                    } else {
                                        -(index_imm as i32)
                                    };
                                    fallback_deref = Some((reg, offset));
                                }
                            }
                        }
                        _ => {}
                    }

                    if let Some(val) = resolved_val {
                        self.immediate(rt.number(), val);
                    } else if let Some((reg, offset)) = fallback_deref {
                        self.deref(rt.number(), reg, offset);
                    } else {
                        self.regs[rt.number() as usize] = Value::Unknown;
                    }
                }
            }
            Opcode::ADD | Opcode::SUB => {
                if let Operand::Reg(rd) = code.instruction.operands[0]
                    && let Operand::Reg(rn) = code.instruction.operands[1]
                {
                    let is_add = code.instruction.opcode == Opcode::ADD;

                    let new_value = match code.instruction.operands[2] {
                        // ADD Rd, Rn, #imm
                        Operand::Imm32(imm) => {
                            let offset = if is_add { imm as i32 } else { -(imm as i32) };
                            if let Value::Immediate(v_rn) = self.get(rn.number()) {
                                Value::Immediate(v_rn.wrapping_add_signed(offset))
                            } else {
                                Value::Unknown
                            }
                        }
                        // ADD Rd, Rn, Rm
                        Operand::Reg(rm) => {
                            if let (Value::Immediate(v_rn), Value::Immediate(v_rm)) =
                                (self.get(rn.number()), self.get(rm.number()))
                            {
                                let result = if is_add {
                                    v_rn.wrapping_add(v_rm)
                                } else {
                                    v_rn.wrapping_sub(v_rm)
                                };
                                Value::Immediate(result)
                            } else {
                                Value::Unknown
                            }
                        }
                        // ADD Rd, Rn
                        Operand::Nothing => {
                            if let (Value::Immediate(v_rd), Value::Immediate(v_rn)) =
                                (self.get(rd.number()), self.get(rn.number()))
                            {
                                let result = if is_add {
                                    v_rd.wrapping_add(v_rn)
                                } else {
                                    v_rd.wrapping_sub(v_rn)
                                };
                                Value::Immediate(result)
                            } else {
                                Value::Unknown
                            }
                        }
                        _ => Value::Unknown,
                    };

                    self.regs[rd.number() as usize] = new_value;
                } else {
                    if let Operand::Reg(rd) = code.instruction.operands[0] {
                        self.regs[rd.number() as usize] = Value::Unknown;
                    }
                }
            }
            _ => (),
        }
    }
}
