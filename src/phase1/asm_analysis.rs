use tracing::{debug, instrument, trace, warn};

use yaxpeax_arch::LengthedInstruction;
use yaxpeax_arm::armv7::{ConditionCode, Opcode, Operand, Reg};

use crate::{
    Code,
    cpu_mode::CpuMode,
    err::Phase1Error,
    phase1::{
        BasicBlock, Metadata,
        disasm::{disassemble_arm_oneshot, disassemble_thumb_oneshot},
    },
    regext::{RegExt, RegListExt},
};

type Result<T> = core::result::Result<T, Phase1Error>;

pub struct AsmAnalysis {
    /// VA queue
    queue: Vec<(usize, CpuMode)>,
    /// bad callers
    bad: Vec<usize>,
}

impl AsmAnalysis {
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            bad: Vec::new(),
        }
    }

    #[cfg(not(feature = "unchecked"))]
    pub fn self_test(&self, metadata: &Metadata<'_>) -> Result<()> {
        use crate::{err::Phase1SelfTestError, phase1::branch_analysis::JumpType};
        use std::collections::HashSet;

        // all blocks must have start <= end
        for b in &metadata.blocks {
            if b.start_va() <= b.end_va() {
                trace!("{:#x?} has valid range", b.range);
            } else {
                trace!("{:#x?} has invalid range", b.range);
                return Err(Phase1Error::SelfTest(Phase1SelfTestError::VARange(
                    b.range.clone(),
                )));
            }
        }

        let mut visited_vas = HashSet::with_capacity(metadata.bin.len());
        for b in &metadata.blocks {
            // bin.range is O(log N) and efficiently yields only VAs inside the block
            for (&va, _) in metadata.bin.range(b.range.clone()) {
                if !visited_vas.insert(va) {
                    trace!("{va:#x} overlaps in some blocks");
                    return Err(Phase1Error::SelfTest(
                        Phase1SelfTestError::DuplicateInstructionUsage(va),
                    ));
                }
            }
        }

        // something is missing...
        if visited_vas.len() != metadata.bin.len() {
            for &va in metadata.bin.keys() {
                if !visited_vas.contains(&va) {
                    trace!("{va:#x} has no block");
                    return Err(Phase1Error::SelfTest(
                        Phase1SelfTestError::UnusedInstruction(va),
                    ));
                }
            }
        }

        // all jump targets must start block
        let block_starts: HashSet<usize> = metadata.blocks.iter().map(|b| b.start_va()).collect();

        let do_va_check = |va: usize| -> Result<()> {
            if block_starts.contains(&va) {
                Ok(())
            } else {
                Err(Phase1Error::SelfTest(
                    Phase1SelfTestError::JumpIsNotBlockStart(va),
                ))
            }
        };

        for code in metadata.bin.values() {
            if matches!(
                code.instruction.opcode,
                Opcode::B | Opcode::BX | Opcode::BL | Opcode::BLX
            ) && let Some(target) = metadata.branch.jumps.get(&code.va)
            {
                match target {
                    JumpType::DirectCall(va) | JumpType::DirectJump(va) => do_va_check(*va),
                    JumpType::Branch {
                        target,
                        fallthrough,
                    } => {
                        do_va_check(*target)?;
                        do_va_check(*fallthrough)
                    }
                    _ => Ok(()),
                }?;
            }
        }
        Ok(())
    }

    /// ensure basic block at `va` is being split
    fn ensure_split(&mut self, metadata: &mut Metadata<'_>, va: usize) {
        if let Some(idx) = metadata
            .blocks
            .iter()
            // if it's start then we don't to split
            .position(|b| b.contains_va(va) && b.start_va() != va)
        {
            let block = &metadata.blocks[idx];
            let old_start = block.start_va();
            let old_end = block.end_va();
            let mode = block.mode;

            if let Some((&prev_va, _)) = metadata.bin.range(..va).next_back() {
                debug!("splitting {old_start:#x}..{old_end:#x} at {va:#x}");
                metadata.blocks[idx].range = old_start..=prev_va;
                metadata.blocks.push(BasicBlock::new(va..=old_end, mode));

                if !metadata.branch.jumps.contains_key(&prev_va) {
                    trace!("marking implicit fall-through jump from {prev_va:#x} to {va:#x}");
                    metadata.branch.mark_as_direct_jump(prev_va, va);
                }
            } else {
                unreachable!("previous instruction must be available");
            }
        }
    }

    /// add `va` to the internal queue with `mode`
    #[instrument(skip(self, metadata), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn enqueue_va(&mut self, metadata: &mut Metadata<'_>, va: usize, mode: CpuMode) {
        // is there a block which has `va` as start?
        if metadata.blocks.iter().any(|b| b.start_va() == va) {
            // then everything is done
            debug!("{va:#x} already processed and exists as block start, no need to split");
            return;
        }

        self.ensure_split(metadata, va);

        if metadata.bin.contains_key(&va) {
            debug!("{va:#x} already processed");
            return;
        }

        debug!("added {va:#x} to queue");
        self.queue.push((va, mode));
    }

    /// process `start_va` from the queue with `mode` until terminator is hit
    #[instrument(skip(self, metadata), fields(start_va = format_args!("{:#x}", start_va)), level = "trace")]
    fn process_va_block(
        &mut self,
        metadata: &mut Metadata<'_>,
        start_va: usize,
        mode: CpuMode,
    ) -> Result<Vec<Code>> {
        let mut bin: Vec<Code> = Vec::with_capacity(50);
        let mut va = start_va;
        let mut last_va = start_va;

        loop {
            if va != start_va && metadata.bin.contains_key(&va) {
                debug!("{va:#x} already processed");
                break;
            }

            // is va somewhere in the existing block?
            if let Some(block) = metadata.blocks.iter().find(|b| b.contains_va(va)) {
                debug!("{va:#x} overlaps with {:#x?}, stop", block.range);
                break;
            }

            let offset = va.wrapping_sub(metadata.base_address);
            if offset >= metadata.data.len() {
                warn!("{va:#x} out of bounds, abort analysis for the {start_va:#x} entry");
                break;
            }

            let code = match Self::disassemble_oneshot(&metadata.data[offset..], mode) {
                Ok(mut code) => {
                    code.va = va;
                    code
                }
                Err(e) => {
                    // discard invalid instruction which caused jump to here
                    let mut iter = metadata.branch.all_jumps_for(va);
                    if let Some(caller_va) = iter.next() {
                        self.bad.push(caller_va);

                        if iter.next().is_some() {
                            todo!("more than one invalid jump to {va:#x}?");
                        }
                    }
                    // this is debug because we don't track any literal pools or noreturns, so falling into garbage is possible
                    debug!("disassembler error at {va:#x}: {e:?}");
                    break;
                }
            };

            // stop on literals
            if metadata.refs.iter().any(|(caller_va, literal_va)| {
                let should_check = metadata
                    .bin
                    .get(caller_va)
                    // trust ADD
                    .map(|caller| caller.instruction.opcode != Opcode::ADD)
                    .unwrap_or(true);
                should_check && va == *literal_va
            }) {
                debug!("fell into literal at {va:#x}, abort");
                break;
            }

            trace!(
                "new instuction: {code} ({:?} {:?})",
                code.instruction.opcode, code.instruction.operands
            );

            last_va = va;
            let next_va = va + code.instruction.len().to_const() as usize;

            // this is awful, but clone is even worse, right?
            let mut stop = false;

            match code.instruction.opcode {
                Opcode::PUSH => {
                    if start_va != va {
                        // this means we reached valid function after garbage, or compiler decided to put 2 PUSHes, or just PUSH...
                        //
                        // while i tend to think this is kind of bad idea, but we don't care about function/block bounds at this point. we just need disassembled instructions
                        debug!("fell into fn prologue at {code}");
                    }
                }
                Opcode::B | Opcode::CBZ | Opcode::CBNZ => {
                    let is_cbz_cbnz = matches!(code.instruction.opcode, Opcode::CBZ | Opcode::CBNZ);
                    let target_op = if is_cbz_cbnz {
                        code.instruction.operands[1]
                    } else {
                        code.instruction.operands[0]
                    };

                    if let Some(target) = Self::branch_map_imm(&code, target_op) {
                        // B/CBZ/CBNZ never change mode, passing just target is fine
                        Self::sanity_check_va_align(target)?;
                        self.enqueue_va(metadata, target, mode);

                        // conditional B or CBZ/CBNZ have the next arm
                        if code.instruction.condition != ConditionCode::AL || is_cbz_cbnz {
                            self.enqueue_va(metadata, next_va, mode);
                            metadata.branch.mark_as_branch(code.va, target, next_va);
                        } else {
                            metadata.branch.mark_as_direct_jump(code.va, target);
                        }
                    } else {
                        unreachable!("B/CBZ/CBNZ can't have non-imm operand (code: {code})");
                    }

                    stop = true;
                }
                Opcode::BX => {
                    if let Operand::Reg(r) = code.instruction.operands[0] {
                        if r.is_pc() {
                            // BX PC is a bit weird, but basically means mode switch. though it's another function, so we can call it a thunk
                            self.enqueue_va(metadata, code.pc(), !mode);
                            metadata.branch.mark_as_direct_jump(code.va, code.pc());
                        } else if !r.is_lr() {
                            metadata.branch.mark_as_indirect_jump(code.va, r);
                        }
                    } else {
                        unreachable!("BX can't have non-reg operand (code: {code})");
                    }

                    // any BX is block termination
                    stop = true;
                }
                Opcode::BL | Opcode::BLX => {
                    if let Some(target) = Self::branch_map_imm(&code, code.instruction.operands[0])
                    {
                        Self::sanity_check_va_align(target)?;
                        let next_mode = CpuMode::from_code_and_va(&code, target);
                        let next_target = mode.align_va_on_switch(&next_mode, target);

                        self.enqueue_va(metadata, next_target, next_mode);
                        metadata.branch.mark_as_direct_call(code.va, next_target);
                    } else if let Operand::Reg(r) = code.instruction.operands[0] {
                        metadata.branch.mark_as_indirect_call(code.va, r);
                    }
                }
                Opcode::POP => {
                    if let Operand::RegList(list) = code.instruction.operands[0]
                        && list.has_pc()
                    {
                        stop = true;
                    } else if let Operand::Reg(r) = code.instruction.operands[0]
                        && r.is_pc()
                    {
                        stop = true;
                    }
                }
                Opcode::ERET => {
                    stop = true;
                }
                Opcode::LDR => {
                    if let Operand::Reg(rt) = code.instruction.operands[0]
                        && let Operand::RegDerefPreindexOffset(r, imm, up, _) =
                            code.instruction.operands[1]
                        && r.is_pc()
                    {
                        let pc = if mode == CpuMode::Thumb {
                            code.pc() & !3
                        } else {
                            code.pc()
                        };

                        let mut load = pc.wrapping_sub(metadata.base_address);

                        load = if up {
                            load.wrapping_add(imm as usize)
                        } else {
                            load.wrapping_sub(imm as usize)
                        };

                        if let Some(bytes) = metadata.data.get(load..load + 4) {
                            // jump
                            if rt.is_pc() && imm == { if mode == CpuMode::Arm { 4 } else { 0 } } {
                                let reg_val =
                                    u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
                                if reg_val >= metadata.base_address
                                    && reg_val < metadata.base_address + metadata.data.len()
                                {
                                    let next_mode = CpuMode::from_code_and_va(&code, reg_val);
                                    let next_va = mode.align_va_on_switch(&next_mode, reg_val);
                                    self.enqueue_va(metadata, next_va, next_mode);

                                    // i haven't seen any actual jump with LDR. it's mostly calls
                                    metadata.branch.mark_as_direct_call(code.va, next_va);
                                } else {
                                    warn!("jumpout to {reg_val:#x} (at {code}), won't follow");
                                }

                                stop = true;
                            } else {
                                metadata.refs.insert(code.va, load + metadata.base_address);
                                trace!("add {load:#x} to data refs");
                            }
                        }
                    }
                }
                Opcode::ADR => {
                    if let Operand::Imm32(imm) = code.instruction.operands[1] {
                        let addr = code.va().wrapping_add(imm as usize);
                        metadata.refs.insert(code.va, addr);
                        trace!("add {addr:#x} to data refs");
                    } else {
                        unreachable!("ADR can't have non-imm operand (code: {code})");
                    }
                }
                Opcode::MOV => {
                    if let Operand::Reg(rd) = code.instruction.operands[0]
                        && rd.is_pc()
                    {
                        // MOV PC, LR is RET pseudo-instruction, non-LR values are just MOV PC, Rd
                        stop = true;
                    }
                }
                Opcode::ADD => {
                    // ADD Rn, PC is usually used in PIE binaries to fixup relative loads
                    if let Operand::Reg(rn) = code.instruction.operands[0]
                        && let Operand::Reg(r_should_be_pc) = code.instruction.operands[1]
                        && r_should_be_pc.is_pc()
                        // this is ADD Rn, PC, now look for LDR entry to fixup
                        && let Some(ldr) = bin.iter().rev().find(|c| {
                            if let Operand::Reg(r) = c.instruction.operands[0]
                            && r == rn
                            && let Operand::RegDerefPreindexOffset(r_should_be_pc, _, _, _) = c.instruction.operands[1] &&
                            r_should_be_pc.is_pc() && c.instruction.opcode == Opcode::LDR {
                                true
                            } else {
                                false
                            }
                        })
                    {
                        debug!(
                            "fixed ref originally created at {:#x} at {:#x}",
                            ldr.va, code.va
                        );

                        // literal pool address, already stored by LDR
                        let ldr_pool_addr =
                            *metadata.refs.get(&ldr.va).expect("LDR entry must exist");
                        let ldr_pool_off = ldr_pool_addr - metadata.base_address;
                        // literal pool **value**
                        let ldr_va = i32::from_le_bytes(
                            metadata.data[ldr_pool_off..ldr_pool_off + 4]
                                .try_into()
                                .unwrap(),
                        ) as isize;

                        debug!("LDR pool address: {ldr_pool_addr:#x}");
                        debug!("LDR pool value: {ldr_va:#x}");
                        let ldr_va = ldr_va.wrapping_add_unsigned(code.pc());

                        // add new entry because data referenced by the LDR is a literal itself
                        metadata.refs.insert(code.va, ldr_va as usize);
                        debug!("ADD value: {ldr_va:#x}");
                    }
                }
                _ => (),
            }

            bin.push(code);

            if stop {
                break;
            }

            va = next_va;
        }

        trace!("{start_va:#x} code size: {} instructions", bin.len());

        if !bin.is_empty() {
            metadata
                .blocks
                .push(BasicBlock::new(start_va..=last_va, mode));
        }

        Ok(bin)
    }

    /// process `self.queue`
    #[instrument(skip(self, metadata), level = "trace")]
    pub fn process_queue(&mut self, metadata: &mut Metadata<'_>) -> Result<()> {
        while let Some((va, mode)) = self.queue.pop() {
            debug!("pop {va:#x} from queue ({mode:?} mode)");
            if metadata.bin.contains_key(&va) {
                self.ensure_split(metadata, va);
                debug!("{va:#x} already processed");
                continue;
            }

            let bin = self.process_va_block(metadata, va, mode)?;
            metadata
                .bin
                .extend(bin.into_iter().map(|code| (code.va, code)));
        }

        // discard invalid jumps
        self.bad.iter().for_each(|&va| {
            if let Some(block) = metadata.blocks.iter_mut().find(|b| b.contains_va(va)) {
                let end_va = *metadata
                    .bin
                    .range(..block.end_va() - 1)
                    .next_back()
                    .expect("invalid instruction at start")
                    .0;
                block.range = block.start_va()..=end_va;
                metadata.bin.remove_entry(&va);
                metadata.branch.discard(va);
            }
        });

        debug!("jump metadata len: {}", metadata.branch.jumps.len());

        Ok(())
    }

    /// try to disassemble ARM/Thumb instruction (depending on the `mode`) and fixup disassembler error if possible
    #[inline(always)]
    fn disassemble_oneshot(data: &[u8], mode: CpuMode) -> Result<Code> {
        match mode {
            CpuMode::Arm => match disassemble_arm_oneshot(data) {
                Ok(v) => Ok(v),
                // ARM always has 4 byte instructions, so we just replace (likely) NEON with NOP
                Err(yaxpeax_arm::armv7::DecodeError::Incomplete) => Ok(Code {
                    instruction: yaxpeax_arm::armv7::Instruction {
                        condition: ConditionCode::AL,
                        opcode: Opcode::NOP,
                        operands: [
                            Operand::Nothing,
                            Operand::Nothing,
                            Operand::Nothing,
                            Operand::Nothing,
                        ],
                        s: false,
                        wide: false,
                        thumb_w: false,
                        thumb: false,
                    },
                    va: 0,
                }),
                Err(e) => Err(Phase1Error::Disassembler(e)),
            },
            CpuMode::Thumb => disassemble_thumb_oneshot(data).map_err(Into::into),
        }
    }

    /// map branch immediate value to VA
    #[inline(always)]
    fn branch_map_imm(code: &Code, operand: Operand) -> Option<usize> {
        let target = match operand {
            Operand::BranchOffset(target) | Operand::BranchThumbOffset(target) => target,
            Operand::Reg(_) => return None,
            _ => unreachable!(),
        };
        Some(code.pc().wrapping_add_signed(target as isize))
    }

    /// check if VA is aligned
    #[inline(always)]
    fn sanity_check_va_align(va: usize) -> Result<()> {
        if va & 1 == 0 {
            Ok(())
        } else {
            Err(Phase1Error::UnalignedVA(va))
        }
    }
}
