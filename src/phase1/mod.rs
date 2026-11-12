//! disassemble as much as possible instructions and create basic blocks
use ahash::{AHashMap, AHashSet};
use smallvec::SmallVec;
use std::{collections::BTreeMap, ops::RangeInclusive};
use tracing::{instrument, warn};
use yaxpeax_arch::LengthedInstruction;

use crate::{
    Code,
    cpu_mode::CpuMode,
    phase1::{branch_analysis::BranchAnalysis, reg_analysis::RegWriteTracker},
    phase2::{BasicBlock as P2BasicBlock, Metadata as P2Metadata},
};

pub(crate) mod asm_analysis;
pub(crate) mod blind_analysis;
pub(crate) mod block_analysis;
pub(crate) mod branch_analysis;
mod disasm;
pub(crate) mod indirect_analysis;
pub(crate) mod indirect_fn_analysis;
pub(crate) mod reg_analysis;

/// phase 1 metadata for disassembling instructions
pub struct Metadata {
    /// binary content
    data: Box<[u8]>,
    /// binary base address
    base_address: u32,

    /// all disassembled instructions
    pub bin: BTreeMap<u32, Code>,
    /// all basic blocks
    pub blocks: BTreeMap<u32, BasicBlock>,
    /// branch metadata
    pub branch: BranchAnalysis,

    /// ldr literal pools
    pub slots: AHashSet<u32>,
    /// literals usage, mapped as <code va, literal va>
    pub refs: AHashMap<u32, u32>,
    /// reverse literals, <literal va, code va>
    pub rev_refs: AHashMap<u32, SmallVec<[u32; 4]>>,
}

impl Metadata {
    pub fn new(data: Box<[u8]>, base_address: u32) -> Self {
        Self {
            data,
            base_address,
            bin: BTreeMap::new(),
            blocks: BTreeMap::new(),
            branch: BranchAnalysis::new(),
            slots: AHashSet::new(),
            refs: AHashMap::new(),
            rev_refs: AHashMap::new(),
        }
    }

    pub fn code(&self) -> impl Iterator<Item = &Code> {
        self.bin.values()
    }

    #[inline(always)]
    pub fn unmap_va(&self, va: u32) -> Option<usize> {
        let off = va.checked_sub(self.base_address)? as usize;
        (off < self.data.len()).then_some(off)
    }

    #[inline(always)]
    pub fn is_valid_va(&self, va: u32) -> bool {
        self.unmap_va(va).is_some()
    }

    /// Return the disassembled instruction whose byte span `[code.va, code.va + len)` covers `va`.
    #[inline(always)]
    pub fn code_covering(&self, va: u32) -> Option<&Code> {
        let (_, code) = self.bin.range(..=va).next_back()?;
        let end = code.va.saturating_add(code.instruction.len().to_const());
        (va < end).then_some(code)
    }

    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    #[inline(always)]
    pub fn map_va(&self, va: u32) -> Option<u32> {
        if self.is_valid_va(va) {
            Some(va)
        } else {
            warn!("failed to map {va:#x}: out of binary range");
            None
        }
    }

    pub fn into_2nd(self) -> P2Metadata {
        let mut blocks = self
            .blocks
            .into_values()
            .map(|b| {
                P2BasicBlock::new(b.range, b.mode, b.predecessors, b.successors, b.entry_state)
            })
            .collect::<Vec<_>>();
        blocks.sort_unstable();
        P2Metadata::new(
            self.data,
            self.base_address,
            self.bin,
            blocks,
            self.refs,
            self.rev_refs,
            self.branch,
        )
    }
}

/// basic block with given range and mode
#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    /// code range for the `bin`
    pub range: RangeInclusive<u32>,
    /// block mode
    pub mode: CpuMode,

    /// previous blocks
    pub predecessors: Vec<u32>,
    /// next blocks
    pub successors: Vec<u32>,

    /// state when block is entered (inherited from the previous block(s))
    pub entry_state: RegWriteTracker,
    /// state when block is finished
    pub exit_state: RegWriteTracker,
}

impl BasicBlock {
    fn new(range: RangeInclusive<u32>, mode: CpuMode) -> Self {
        Self {
            range,
            mode,
            predecessors: Vec::new(),
            successors: Vec::new(),
            // placeholder for initial discovery
            entry_state: RegWriteTracker::new(),
            exit_state: RegWriteTracker::new(),
        }
    }

    /// start of the block range
    pub fn start_va(&self) -> u32 {
        *self.range.start()
    }

    /// end of the block range
    pub fn end_va(&self) -> u32 {
        *self.range.end()
    }

    /// does the current block contain `va`?
    pub fn contains_va(&self, va: u32) -> bool {
        self.range.contains(&va)
    }
}

impl PartialOrd for BasicBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BasicBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start_va().cmp(&other.start_va())
    }
}
