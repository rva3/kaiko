//! cleanup data and convert to better structs for external crates
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    ops::RangeInclusive,
};

use yaxpeax_arm::armv7::Reg;

use crate::{
    Code,
    cpu_mode::CpuMode,
    phase1::{
        branch_analysis::BranchAnalysis,
        reg_analysis::{RegWriteTracker, RegisterState, Value},
    },
};

pub(crate) mod fn_analysis;

#[derive(Debug)]
pub struct Metadata<'a> {
    data: &'a [u8],
    /// binary base address
    base_address: u32,
    /// all disassembled instructions
    pub bin: BTreeMap<u32, Code>,
    /// all basic blocks
    pub blocks: Vec<BasicBlock>,
    /// all functions
    pub fns: Vec<Function>,
    /// all data references
    pub refs: HashMap<u32, u32>,
    /// branch data
    branch: BranchAnalysis,
}

impl PartialEq for Metadata<'_> {
    // there's only one metadata instance
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for Metadata<'_> {}

impl<'a> Metadata<'a> {
    pub fn new(
        data: &'a [u8],
        base_address: u32,
        bin: BTreeMap<u32, Code>,
        blocks: Vec<BasicBlock>,
        refs: HashMap<u32, u32>,
        branch: BranchAnalysis,
    ) -> Self {
        Self {
            data,
            base_address,
            bin,
            blocks,
            fns: Vec::new(),
            refs,
            branch,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    /// code range for the `bin`
    range: RangeInclusive<u32>,
    /// block mode
    mode: CpuMode,
    /// previous blocks which jump to this one
    predecessors: Vec<u32>,
    /// next blocks after this one
    successors: Vec<u32>,
    /// state when the block is entered
    state: RegWriteTracker,
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

impl BasicBlock {
    pub(crate) fn new(
        range: RangeInclusive<u32>,
        mode: CpuMode,
        predecessors: Vec<u32>,
        successors: Vec<u32>,
        state: RegWriteTracker,
    ) -> Self {
        Self {
            range,
            mode,
            predecessors,
            successors,
            state,
        }
    }

    /// is the `va` in the block?
    fn contains_va(&self, va: u32) -> bool {
        self.range.contains(&va)
    }

    /// block start VA
    fn start_va(&self) -> u32 {
        *self.range.start()
    }

    /// block end VA
    fn end_va(&self) -> u32 {
        *self.range.end()
    }
}

/// read-only fat pointer to the `BasicBlock` with global metadata
#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlockView<'a> {
    /// global metadata
    metadata: &'a Metadata<'a>,
    /// block ref
    block: &'a BasicBlock,
}

impl Display for BasicBlockView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Basic block @ {:#x}:", self.start_va())?;
        writeln!(
            f,
            "Code range: from {:#x} to {:#x}",
            self.start_va(),
            self.end_va()
        )?;
        self.block
            .predecessors
            .iter()
            .try_for_each(|va| writeln!(f, "Previous block VA: {va:#x}"))?;
        self.block
            .successors
            .iter()
            .try_for_each(|va| writeln!(f, "Next block VA: {va:#x}"))?;
        write!(f, "CPU state: {}", self.regs())
    }
}

impl PartialOrd for BasicBlockView<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BasicBlockView<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start_va().cmp(&other.start_va())
    }
}

impl<'a> BasicBlockView<'a> {
    pub(crate) fn new(metadata: &'a Metadata, block: &'a BasicBlock) -> Self {
        Self { metadata, block }
    }

    /// block code
    pub fn code(&self) -> impl DoubleEndedIterator<Item = &'a Code> + use<'a> {
        let bin = &self.metadata.bin;
        let range = self.block.range.clone();

        bin.range(range).map(|(_, code)| code)
    }

    /// get data references in the current block
    pub fn data_refs(&self) -> impl DoubleEndedIterator<Item = (&Code, u32)> {
        self.code().filter_map(|c| {
            self.metadata
                .refs
                .get(&c.va())
                .map(|&target_va| (c, target_va))
        })
    }

    /// is the `va` in the block?
    pub fn contains_va(&self, va: u32) -> bool {
        self.block.contains_va(va)
    }

    /// block start VA
    pub fn start_va(&self) -> u32 {
        self.block.start_va()
    }

    /// block end VA
    pub fn end_va(&self) -> u32 {
        self.block.end_va()
    }

    /// register state access
    pub fn regs(&self) -> RegisterView<'a> {
        RegisterView::new(self.metadata, &self.block.state)
    }

    /// get all instructions matching an opcode
    pub fn instructions_by_opcode(
        &self,
        opcode: yaxpeax_arm::armv7::Opcode,
    ) -> impl DoubleEndedIterator<Item = &Code> {
        self.code().filter(move |c| {
            core::mem::discriminant(&c.instruction().opcode) == core::mem::discriminant(&opcode)
        })
    }

    /// like `instructions_by_opcode` but only for the first opcode
    pub fn instruction_by_opcode(&self, opcode: yaxpeax_arm::armv7::Opcode) -> Option<&Code> {
        self.instructions_by_opcode(opcode).next()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Function {
    /// block indexes
    blocks: Vec<usize>,
}

impl Function {
    pub(crate) fn new(blocks: Vec<usize>) -> Self {
        Self { blocks }
    }
}

/// read-only fat pointer to the `Function` with global metadata
#[derive(Debug, PartialEq, Eq)]
pub struct FunctionView<'a> {
    /// global metadata
    metadata: &'a Metadata<'a>,
    /// fn ref
    f: &'a Function,
}

impl Display for FunctionView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Function @ {:#x}", self.start_va())?;
        write!(f, "Blocks: ")?;
        let count = self.blocks().count();
        self.blocks()
            .enumerate()
            .try_for_each(|(i, b)| -> std::fmt::Result {
                write!(f, "{:#x}-{:#x}", b.start_va(), b.end_va())?;
                if i == count - 1 {
                    Ok(())
                } else {
                    write!(f, ", ")
                }
            })?;
        writeln!(f)?;
        write!(f, "Code size: {}", self.code().count())
    }
}

impl<'a> FunctionView<'a> {
    pub(crate) fn new(metadata: &'a Metadata, f: &'a Function) -> Self {
        Self { metadata, f }
    }

    /// function basic blocks
    pub fn blocks(&'a self) -> impl DoubleEndedIterator<Item = BasicBlockView<'a>> + use<'a> {
        self.f
            .blocks
            .iter()
            .map(|&i| BasicBlockView::new(self.metadata, &self.metadata.blocks[i]))
    }

    /// function code
    pub fn code(&self) -> impl DoubleEndedIterator<Item = &'a Code> + use<'a> {
        let metadata = self.metadata;

        self.f.blocks.iter().flat_map(|&i| {
            let block = &metadata.blocks[i];
            metadata
                .bin
                .range(block.range.clone())
                .map(|(_, code)| code)
        })
    }

    /// is the `va` in the function?
    pub fn contains_va(&self, va: u32) -> bool {
        self.blocks().any(|b| b.contains_va(va))
    }

    /// function start VA
    pub fn start_va(&self) -> u32 {
        self.blocks()
            .next()
            .expect("function can't have empty body")
            .start_va()
    }

    /// register state access (first basic block)
    pub fn regs(&'a self) -> RegisterView<'a> {
        self.blocks()
            .next()
            .expect("function can't have empty body")
            .regs()
    }
}

/// read-only fat pointer to the `RegWriteTracker` with global metadata
#[derive(Debug, PartialEq, Eq)]
pub struct RegisterView<'a> {
    /// global metadata
    metadata: &'a Metadata<'a>,
    /// rwt ref
    rwt: &'a RegWriteTracker,
}

impl Display for RegisterView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (0..=15).try_for_each(|i| {
            write!(f, "{}", self.rwt.get(i))?;
            if i == 15 { Ok(()) } else { write!(f, ", ") }
        })
    }
}

impl<'a> RegisterView<'a> {
    pub(crate) fn new(metadata: &'a Metadata, rwt: &'a RegWriteTracker) -> Self {
        Self { metadata, rwt }
    }

    /// calculate register state **BEFORE** `va` would be executed
    ///
    /// `None` if `va` doesn't exist
    pub fn state_at(&self, va: u32) -> Option<RegisterState> {
        let block = self.metadata.blocks.iter().find(|b| b.contains_va(va))?;

        // clone is fine because we don't want to mutate existing block
        let mut rwt = block.state.clone();

        // clone is very cheap here
        for (v, code) in self.metadata.bin.range(block.range.clone()) {
            if *v == va {
                return Some(rwt.snapshot());
            }

            rwt.step(code, self.metadata.data, self.metadata.base_address);
        }

        None
    }

    /// calculate register state **AFTER** `va` is executed
    ///
    /// `None` if `va` doesn't exist
    pub fn state_at_after(&self, va: u32) -> Option<RegisterState> {
        let block = self.metadata.blocks.iter().find(|b| b.contains_va(va))?;

        // clone is fine because we don't want to mutate existing block
        let mut rwt = block.state.clone();

        // clone is very cheap here
        for (v, code) in self.metadata.bin.range(block.range.clone()) {
            rwt.step(code, self.metadata.data, self.metadata.base_address);

            if *v == va {
                return Some(rwt.snapshot());
            }
        }

        None
    }

    /// calculate register state for `r` register **BEFORE** `va` would be executed
    ///
    /// `None` if `va` doesn't exist
    pub fn state_for_reg(&self, va: u32, r: u8) -> Option<Value> {
        let block = self.metadata.blocks.iter().find(|b| b.contains_va(va))?;

        // clone is fine because we don't want to mutate existing block
        let mut rwt = block.state.clone();

        // clone is very cheap here
        for (v, code) in self.metadata.bin.range(block.range.clone()) {
            if *v == va {
                return Some(rwt.get(r));
            }

            rwt.step(code, self.metadata.data, self.metadata.base_address);
        }

        None
    }

    /// calculate register state for `r` register **AFTER** `va` is executed
    ///
    /// `None` if `va` doesn't exist
    pub fn state_for_reg_after(&self, va: u32, r: u8) -> Option<Value> {
        let block = self.metadata.blocks.iter().find(|b| b.contains_va(va))?;

        // clone is fine because we don't want to mutate existing block
        let mut rwt = block.state.clone();

        // clone is very cheap here
        for (v, code) in self.metadata.bin.range(block.range.clone()) {
            rwt.step(code, self.metadata.data, self.metadata.base_address);

            if *v == va {
                return Some(rwt.get(r));
            }
        }

        None
    }

    /// get immediate value from the `r` register at `va`
    pub fn try_get_imm(&self, va: u32, r: u8) -> Option<u32> {
        let rwt = RegWriteTracker::from_regs(self.state_at(va)?);
        rwt.try_get_imm(
            Reg::from_u8(r),
            self.metadata.base_address,
            self.metadata.data,
        )
    }
}
