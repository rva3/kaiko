use ahash::{AHashMap, AHashSet};
use smallvec::SmallVec;
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
    /// TBB/TBH/LDR PC as jumptable
    Table(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub enum EdgeType {
    Call,
    Jump,
    Branch,
    Table,
    Fallthrough,
}

#[derive(Debug)]
pub struct BranchAnalysis {
    /// <caller, callee> (even though it's not always call, but we're not going to use something like jumper and jumpee, right?)
    pub jumps: AHashMap<u32, JumpType>,
    /// explicit fallthroughs after non-terminating calls when a block is split: <call_va, next_block_va>
    pub fallthroughs: AHashMap<u32, u32>,
    /// <callee, Vec<callers>>
    pub rev_jumps: AHashMap<u32, SmallVec<[(u32, EdgeType); 4]>>,
    /// jump table entries
    pub jump_tables: Vec<SmallVec<[u32; 10]>>,
    /// extra function entry points (e.g., from indirect/blind analysis)
    pub extra_fns: AHashSet<u32>,
}

impl BranchAnalysis {
    pub fn new() -> Self {
        Self {
            jumps: AHashMap::new(),
            fallthroughs: AHashMap::new(),
            rev_jumps: AHashMap::new(),
            jump_tables: Vec::new(),
            extra_fns: AHashSet::new(),
        }
    }

    fn push_rev_jump_unchecked(&mut self, target: u32, me: u32, ty: EdgeType) {
        self.rev_jumps.entry(target).or_default().push((me, ty));
    }

    fn push_rev_jump(&mut self, target: u32, me: u32, ty: EdgeType) {
        let entry = self.rev_jumps.entry(target).or_default();
        if !entry.iter().any(|(c, t)| *c == me && *t == ty) {
            entry.push((me, ty));
        }
    }

    fn remove_rev_jumps(&mut self, va: u32, old: JumpType) {
        let mut do_discard = |t: u32| {
            if let Some(callers) = self.rev_jumps.get_mut(&t) {
                callers.retain(|(caller_va, ty)| *caller_va != va || *ty == EdgeType::Fallthrough);
            }
        };

        match old {
            JumpType::DirectCall(t) | JumpType::DirectJump(t) => do_discard(t),
            JumpType::Branch {
                target,
                fallthrough,
            } => {
                do_discard(target);
                do_discard(fallthrough);
            }
            JumpType::Table(idx) => {
                let items = std::mem::take(&mut self.jump_tables[idx]);
                items.into_iter().for_each(|t| do_discard(t));
            }
            _ => (),
        };
    }

    fn remove_jump_only(&mut self, va: u32) {
        if let Some(ty) = self.jumps.remove(&va) {
            self.remove_rev_jumps(va, ty);
        }
    }

    /// mark `target` as fallthrough after call instruction at `me`
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target)), level = "trace")]
    pub fn mark_as_fallthrough(&mut self, me: u32, target: u32) {
        if let Some(old) = self.fallthroughs.insert(me, target) {
            if old == target {
                return;
            }
            if let Some(callers) = self.rev_jumps.get_mut(&old) {
                callers.retain(|(caller_va, ty)| *caller_va != me || *ty != EdgeType::Fallthrough);
            }
        }
        self.push_rev_jump_unchecked(target, me, EdgeType::Fallthrough);
    }

    /// mark `target` as function call with `me` as caller VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target)), level = "trace")]
    pub fn mark_as_direct_call(&mut self, me: u32, target: u32) {
        if let Some(old) = self.jumps.insert(me, JumpType::DirectCall(target)) {
            self.remove_rev_jumps(me, old);
        }
        self.push_rev_jump_unchecked(target, me, EdgeType::Call);
    }

    /// mark `target` as function call with `me` as caller VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me)), level = "trace")]
    pub fn mark_as_indirect_call(&mut self, me: u32, reg: Reg) {
        if let Some(old) = self.jumps.insert(me, JumpType::IndirectCall(reg)) {
            self.remove_rev_jumps(me, old);
        }
    }

    /// mark `target` as direct jump with `me` as jump instruction VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target)), level = "trace")]
    pub fn mark_as_direct_jump(&mut self, me: u32, target: u32) {
        if let Some(old) = self.jumps.insert(me, JumpType::DirectJump(target)) {
            self.remove_rev_jumps(me, old);
        }
        self.push_rev_jump_unchecked(target, me, EdgeType::Jump);
    }

    /// mark `target` as indirect jump with `me` as jump instruction VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me)), level = "trace")]
    pub fn mark_as_indirect_jump(&mut self, me: u32, reg: Reg) {
        if let Some(old) = self.jumps.insert(me, JumpType::IndirectJump(reg)) {
            self.remove_rev_jumps(me, old);
        }
    }

    /// mark `target` as branch target arm with `me` as branch instruction VA
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me), target = format_args!("{:#x}", target), fallthrough = format_args!("{:#x}", fallthrough)), level = "trace")]
    pub fn mark_as_branch(&mut self, me: u32, target: u32, fallthrough: u32) {
        if let Some(old) = self.jumps.insert(
            me,
            JumpType::Branch {
                target,
                fallthrough,
            },
        ) {
            self.remove_rev_jumps(me, old);
        }
        self.push_rev_jump_unchecked(target, me, EdgeType::Branch);
        if fallthrough != target {
            self.push_rev_jump_unchecked(fallthrough, me, EdgeType::Branch);
        }
    }

    /// mark `target` as jump table with `me` as base
    #[instrument(skip(self), fields(me = format_args!("{:#x}", me)), level = "trace")]
    pub fn mark_as_table(&mut self, me: u32, targets: &[u32]) {
        let idx = self.jump_tables.len();
        self.jump_tables.push(SmallVec::from_slice(targets));
        if let Some(old) = self.jumps.insert(me, JumpType::Table(idx)) {
            self.remove_rev_jumps(me, old);
        }

        for &target in targets {
            self.push_rev_jump(target, me, EdgeType::Table);
        }
    }

    /// mark `va` explicitly as a function entry point
    pub fn mark_as_fn(&mut self, va: u32) {
        self.extra_fns.insert(va);
    }

    /// is `va` a function?
    ///
    /// if it's a function, then at least one `JumpType::DirectCall` should point to it
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn is_fn(&self, va: u32) -> bool {
        self.extra_fns.contains(&va)
            || self
                .rev_jumps
                .get(&va)
                .map(|callers| callers.iter().any(|(_, ty)| *ty == EdgeType::Call))
                .unwrap_or(false)
    }

    pub fn get_callee(&self, va: u32) -> Option<&JumpType> {
        self.jumps.get(&va)
    }

    /// get all jumps to the `va`, either it's a branch or jump
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn all_jumps_for(&self, va: u32) -> impl Iterator<Item = u32> {
        self.rev_jumps
            .get(&va)
            .into_iter()
            .flat_map(|callers| callers.iter())
            .filter(|(_, ty)| {
                matches!(
                    ty,
                    EdgeType::Jump | EdgeType::Branch | EdgeType::Table | EdgeType::Fallthrough
                )
            })
            .map(|(caller_va, _)| *caller_va)
    }

    /// get all jumps, branches and calls for the `va`
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn all_for(&self, va: u32) -> impl Iterator<Item = u32> {
        self.rev_jumps
            .get(&va)
            .into_iter()
            .flat_map(|callers| callers.iter())
            .filter(|(_, ty)| {
                matches!(
                    ty,
                    EdgeType::Call
                        | EdgeType::Jump
                        | EdgeType::Branch
                        | EdgeType::Table
                        | EdgeType::Fallthrough
                )
            })
            .map(|(caller_va, _)| *caller_va)
    }

    /// remove entry
    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn discard(&mut self, va: u32) {
        self.extra_fns.remove(&va);
        self.remove_jump_only(va);
        if let Some(ft) = self.fallthroughs.remove(&va)
            && let Some(callers) = self.rev_jumps.get_mut(&ft)
        {
            callers.retain(|(caller_va, _)| *caller_va != va);
        }
    }
}
