use std::collections::HashMap;

use tracing::instrument;
use yaxpeax_arm::armv7::Reg;

#[derive(Debug)]
pub enum JumpType {
    /// BL/BLX with immediate
    DirectCall(u32),
    /// BLX with register
    IndirectCall(Reg),
    /// unconditional B
    DirectJump(u32),
    /// BX
    IndirectJump(Reg),
    /// conditional B/CBZ/CBNZ
    Branch { target: u32, fallthrough: u32 },
}

#[derive(Debug)]
pub struct BranchAnalysis {
    /// caller -> callee (even though it's not always call, but we're not going to use something like jumper and jumpee, right?)
    pub jumps: HashMap<u32, JumpType>,
}

impl BranchAnalysis {
    pub fn new() -> Self {
        Self {
            jumps: HashMap::new(),
        }
    }

    /// mark `target` as function call with `me` as caller VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target)), level = "trace")]
    pub fn mark_as_direct_call(&mut self, me: u32, target: u32) {
        self.jumps.insert(me, JumpType::DirectCall(target));
    }

    /// mark `target` as function call with `me` as caller VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me)), level = "trace")]
    pub fn mark_as_indirect_call(&mut self, me: u32, reg: Reg) {
        self.jumps.insert(me, JumpType::IndirectCall(reg));
    }

    /// mark `target` as direct jump with `me` as jump instruction VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target)), level = "trace")]
    pub fn mark_as_direct_jump(&mut self, me: u32, target: u32) {
        self.jumps.insert(me, JumpType::DirectJump(target));
    }

    /// mark `target` as indirect jump with `me` as jump instruction VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me)), level = "trace")]
    pub fn mark_as_indirect_jump(&mut self, me: u32, reg: Reg) {
        self.jumps.insert(me, JumpType::IndirectJump(reg));
    }

    /// mark `target` as branch target arm with `me` as branch instruction VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target), fallthrough = format_args!("{:#x}", fallthrough)), level = "trace")]
    pub fn mark_as_branch(&mut self, me: u32, target: u32, fallthrough: u32) {
        self.jumps.insert(
            me,
            JumpType::Branch {
                target,
                fallthrough,
            },
        );
    }

    /// is `va` a function?
    ///
    /// if it's a function, then at least one `JumpType::DirectCall` should point to it
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn is_fn(&self, va: u32) -> bool {
        self.jumps.values().any(|ty| match ty {
            JumpType::DirectCall(v) => va == *v,
            _ => false,
        })
    }

    pub fn get_callee(&self, va: u32) -> Option<&JumpType> {
        self.jumps.get(&va)
    }

    /// get all jumps to the `va`, either it's a branch or jump
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn all_jumps_for(&self, va: u32) -> impl Iterator<Item = u32> {
        self.jumps
            .iter()
            .filter_map(move |(caller_va, ty)| match ty {
                JumpType::DirectJump(v) => Some([(va == *v).then_some(*caller_va), None]),
                JumpType::Branch {
                    target,
                    fallthrough,
                } => Some([
                    (va == *target).then_some(*caller_va),
                    (va == *fallthrough).then_some(*caller_va),
                ]),
                _ => None,
            })
            .flatten()
            .filter_map(|va| va)
    }

    /// get all jumps, branches and calls for the `va`
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn all_for(&self, va: u32) -> impl Iterator<Item = u32> {
        self.jumps
            .iter()
            .filter_map(move |(caller_va, ty)| match ty {
                JumpType::DirectCall(v) | JumpType::DirectJump(v) => {
                    Some([(va == *v).then_some(*caller_va), None])
                }
                JumpType::Branch {
                    target,
                    fallthrough,
                } => Some([
                    (va == *target).then_some(*caller_va),
                    (va == *fallthrough).then_some(*caller_va),
                ]),
                _ => None,
            })
            .flatten()
            .filter_map(|va| va)
    }

    /// remove entry
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn discard(&mut self, va: u32) {
        self.jumps.remove_entry(&va);
    }
}
