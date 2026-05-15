use std::ops::RangeInclusive;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Phase 1 error: {0}")]
    Phase1(#[from] Phase1Error),
    #[error("Phase 2 error: {0}")]
    Phase2(#[from] Phase2Error),
}

#[derive(Debug, thiserror::Error)]
pub enum Phase1Error {
    /// disassembler error
    #[error("Disassembler error: {0}")]
    Disassembler(#[from] yaxpeax_arm::armv7::DecodeError),

    /// VA is not aligned
    ///
    /// shouldn't happen unless there's a bug in the analyzer
    #[error("BUG: unaligned va: {0:#x}")]
    UnalignedVA(usize),

    #[error("Self-test error: {0}")]
    SelfTest(#[from] Phase1SelfTestError),
}

#[derive(Debug, thiserror::Error)]
pub enum Phase1SelfTestError {
    #[error("VA range {0:#x?} is invalid, start must be less or be the same to end")]
    VARange(RangeInclusive<usize>),

    #[error("Instruction at {0:#x} is used in multiple blocks")]
    DuplicateInstructionUsage(usize),

    #[error("Instruction at {0:#x} doesn't belong to any basic block")]
    UnusedInstruction(usize),

    #[error("Instruction at {0:#x} is jump but there's no basic block starting with it")]
    JumpIsNotBlockStart(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum Phase2Error {
    #[error("Self-test error: {0}")]
    SelfTest(#[from] Phase2SelfTestError),
}

#[derive(Debug, thiserror::Error)]
pub enum Phase2SelfTestError {
    #[error("Block at {0:#x} is marked as function, but has predecessors")]
    InvalidFnStart(usize),
}
