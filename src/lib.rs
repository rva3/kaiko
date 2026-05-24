#![allow(clippy::inline_always)]

use std::fmt::Display;

use memchr::memmem;
use tracing::{debug, info, warn};

use crate::{
    cpu_mode::CpuMode,
    err::Error,
    phase1::{
        Metadata as P1Metadata, asm_analysis::AsmAnalysis, block_analysis::BlockAnalysis,
        indirect_analysis::IndirectAnalysis, indirect_fn_analysis::IndirectFnAnalysis,
    },
    phase2::{BasicBlockView, FunctionView, Metadata as P2Metadata, fn_analysis::FnAnalysis},
};
use yaxpeax_arm::armv7::Instruction;

pub mod cpu_mode;
pub mod err;
pub(crate) mod phase1;
pub(crate) mod phase2;
pub mod regext;

pub type Result<T> = core::result::Result<T, Error>;

pub use yaxpeax_arm;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Code {
    instruction: Instruction,
    va: usize,
}

impl PartialOrd for Code {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Code {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.va.cmp(&other.va)
    }
}

impl Code {
    pub fn new(instruction: Instruction, va: usize) -> Self {
        Self { instruction, va }
    }

    #[inline(always)]
    #[must_use]
    pub fn instruction(&self) -> &Instruction {
        &self.instruction
    }

    #[inline(always)]
    #[must_use]
    pub fn va(&self) -> usize {
        self.va
    }

    /// get PC offset for current instruction
    #[inline(always)]
    #[must_use]
    pub(crate) fn pc(&self) -> usize {
        self.va + if self.instruction.thumb() { 4 } else { 8 }
    }
}

impl Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}: {}", self.va, self.instruction)
    }
}

pub struct Analyzer {
    data: Vec<u8>,
    base_address: usize,
    metadata: P2Metadata,
}

impl Analyzer {
    pub fn try_new(
        data: Vec<u8>,
        base_address: usize,
        entry_offset: usize,
        entry_mode: CpuMode,
    ) -> Result<Self> {
        debug!("phase 1: disassemble code");
        let mut metadata = P1Metadata::new(&data, base_address);
        let mut analyzer = AsmAnalysis::new();
        let mut indirect = IndirectAnalysis::new();

        analyzer.enqueue_va(&mut metadata, base_address + entry_offset, entry_mode);

        loop {
            analyzer.process_queue(&mut metadata).unwrap();

            #[cfg(feature = "unchecked")]
            warn!("self-test is disabled");
            #[cfg(not(feature = "unchecked"))]
            analyzer
                .self_test(&metadata)
                .inspect(|_| debug!("phase 1: self-test passed"))?;
            let jumps = indirect.resolve_register_state(&mut metadata);
            let indirect_fns = IndirectFnAnalysis::fns(&metadata);

            if indirect.queue.is_empty() && jumps.is_empty() && indirect_fns.is_empty() {
                break;
            }

            for (va, mode) in jumps {
                analyzer.enqueue_va(&mut metadata, va, mode);
            }

            for (va, mode) in indirect_fns {
                analyzer.enqueue_va(&mut metadata, va, mode);
            }
        }

        BlockAnalysis::add_metadata(&mut metadata);

        debug!("phase 1: code len: {}", metadata.code().count());
        debug!("phase 1: block count: {}", metadata.blocks.len());
        debug!("phase 1: literal count: {}", metadata.refs.len());
        debug!("phase 1: ok");

        debug!("phase 2: create functions and prepare final data");
        let mut metadata = metadata.into_2nd();
        FnAnalysis::create_functions(&mut metadata);
        debug!("phase 2: ok");
        info!(
            "analysis complete with {} functions ({} blocks, {} instructions)",
            metadata.fns.len(),
            metadata.blocks.len(),
            metadata.bin.len()
        );

        Ok(Self {
            data,
            base_address,
            metadata,
        })
    }

    /// all instructions
    pub fn code(&self) -> impl Iterator<Item = &Code> {
        self.functions().map(|f| f.code()).flatten()
    }

    pub fn blocks(&self) -> impl Iterator<Item = BasicBlockView<'_>> {
        self.metadata
            .blocks
            .iter()
            .map(|b| BasicBlockView::new(&self.metadata, b))
    }

    /// all functions
    pub fn functions(&self) -> impl Iterator<Item = FunctionView<'_>> {
        self.metadata
            .fns
            .iter()
            .map(|f| FunctionView::new(&self.metadata, f))
    }

    /// get function which has `va`
    pub fn fn_by_va(&self, va: usize) -> Option<FunctionView<'_>> {
        self.functions().find(|f| f.contains_va(va))
    }

    /// get functions which reference `s`
    pub fn fns_by_str(&self, s: &str) -> Option<impl Iterator<Item = FunctionView<'_>>> {
        let data_va = dbg!(self.map_va(memmem::find(&self.data, s.as_bytes())?)?);
        Some(
            self.metadata
                .refs
                .iter()
                .filter(move |(_, known_data_va)| data_va == **known_data_va)
                .map(|(&code_va, _)| self.fn_by_va(code_va))
                .filter_map(|f| f),
        )
    }

    /// map raw `offset` to VA
    ///
    /// `None` if `offset` cannot be mapped (bigger than max binary size)
    pub fn map_va(&self, offset: usize) -> Option<usize> {
        if offset < self.base_address {
            if offset < self.data.len() {
                Some(self.base_address + offset)
            } else {
                warn!("failed to map {offset:#x}: bigger than binary range");
                None
            }
        } else {
            warn!("failed to map {offset:#x}: bigger than base address");
            None
        }
    }

    /// unmap `va` to raw offset
    ///
    /// `None` if `va` cannot be unmapped (out of bounds of `[base_addr; base_addr + data.len()]`)
    pub fn unmap_va(&self, va: usize) -> Option<usize> {
        if va >= self.base_address {
            if va < self.data.len() {
                Some(va - self.base_address)
            } else {
                warn!("failed to unmap {va:#x}: bigger than binary range");
                None
            }
        } else {
            warn!("failed to unmap {va:#x}: less than base address");
            None
        }
    }
}
