//! disassemble as much as possible instructions and create basic blocks
use std::{
    collections::{BTreeMap, HashMap},
    ops::RangeInclusive,
};
use tracing::{instrument, warn};

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
pub struct Metadata<'a> {
    /// binary content
    data: &'a [u8],
    /// binary base address
    base_address: usize,

    /// all disassembled instructions
    pub bin: BTreeMap<usize, Code>,
    /// all basic blocks
    pub blocks: Vec<BasicBlock>,
    /// branch metadata
    pub branch: BranchAnalysis,

    /// literals usage, mapped as <code va, literal va>
    pub refs: HashMap<usize, usize>,
}

impl<'a> Metadata<'a> {
    pub fn new(data: &'a [u8], base_address: usize) -> Self {
        Self {
            data,
            base_address,
            bin: BTreeMap::new(),
            blocks: Vec::new(),
            branch: BranchAnalysis::new(),
            refs: HashMap::new(),
        }
    }

    pub fn code(&self) -> impl Iterator<Item = &Code> {
        self.bin.values()
    }

    #[instrument(skip(self), fields(va = format_args!("{:#x}", va)), level = "trace")]
    #[inline(always)]
    pub fn map_va(&self, va: usize) -> Option<usize> {
        if va < self.base_address {
            if va < self.data.len() {
                Some(self.base_address + va)
            } else {
                warn!("failed to map {va:#x}: less than base addr but more than data len");
                None
            }
        } else {
            if va < self.base_address + self.data.len() {
                Some(va)
            } else {
                warn!("failed to map {va:#x}: more than base addr and more than data len");
                None
            }
        }
    }

    pub fn into_2nd(self) -> P2Metadata {
        let mut blocks = self
            .blocks
            .into_iter()
            .map(|b| {
                P2BasicBlock::new(b.range, b.mode, b.predecessors, b.successors, b.entry_state)
            })
            .collect::<Vec<_>>();
        blocks.sort_unstable();
        P2Metadata::new(self.base_address, self.bin, blocks, self.refs, self.branch)
    }
}

/// basic block with given range and mode
#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    /// code range for the `bin`
    pub range: RangeInclusive<usize>,
    /// block mode
    pub mode: CpuMode,

    /// previous blocks
    pub predecessors: Vec<usize>,
    /// next blocks
    pub successors: Vec<usize>,

    /// state when block is entered (inherited from the previous block(s))
    pub entry_state: RegWriteTracker,
    /// state when block is finished
    pub exit_state: RegWriteTracker,
}

impl BasicBlock {
    fn new(range: RangeInclusive<usize>, mode: CpuMode) -> Self {
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
    pub fn start_va(&self) -> usize {
        *self.range.start()
    }

    /// end of the block range
    pub fn end_va(&self) -> usize {
        *self.range.end()
    }

    /// does the current block contain `va`?
    pub fn contains_va(&self, va: usize) -> bool {
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
