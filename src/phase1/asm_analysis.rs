use smallvec::SmallVec;
use tracing::{debug, instrument, trace, warn};

use yaxpeax_arch::LengthedInstruction;
use yaxpeax_arm::armv7::{ConditionCode, Opcode, Operand, Reg, RegShiftStyle, ShiftStyle};

use crate::{
    Code,
    cpu_mode::CpuMode,
    err::Phase1Error,
    ext::dataref::a32_ldr_data,
    phase1::{
        BasicBlock, Metadata,
        disasm::{disassemble_arm_oneshot, disassemble_thumb_oneshot},
    },
    regext::{RegExt, RegListExt},
};

type Result<T> = core::result::Result<T, Phase1Error>;

pub struct AsmAnalysis {
    /// VA queue
    queue: Vec<(u32, CpuMode)>,
    /// bad callers
    bad: Vec<u32>,
}

impl AsmAnalysis {
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            bad: Vec::new(),
        }
    }

    #[cfg(not(feature = "unchecked"))]
    pub fn self_test(&self, metadata: &Metadata) -> Result<()> {
        use crate::{err::Phase1SelfTestError, phase1::branch_analysis::JumpType};
        use ahash::AHashSet;

        // all blocks must have start <= end
        for b in metadata.blocks.values() {
            if b.start_va() <= b.end_va() {
                trace!("{:#x?} has valid range", b.range);
            } else {
                trace!("{:#x?} has invalid range", b.range);
                return Err(Phase1Error::SelfTest(Phase1SelfTestError::VARange(
                    b.range.clone(),
                )));
            }
        }

        let mut visited_vas = AHashSet::with_capacity(metadata.bin.len());
        for b in metadata.blocks.values() {
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
        let do_va_check = |va: u32| -> Result<()> {
            if metadata.blocks.contains_key(&va) {
                Ok(())
            } else {
                Err(Phase1Error::SelfTest(
                    Phase1SelfTestError::JumpIsNotBlockStart(va),
                ))
            }
        };

        for target in metadata.branch.jumps.values() {
            match target {
                JumpType::DirectCall(va) | JumpType::DirectJump(va) => do_va_check(*va),
                JumpType::Branch {
                    target,
                    fallthrough,
                } => {
                    do_va_check(*target)?;
                    do_va_check(*fallthrough)
                }
                JumpType::Table(idx) => {
                    for &t in &metadata.branch.jump_tables[*idx] {
                        do_va_check(t)?;
                    }
                    Ok(())
                }
                JumpType::IndirectCall(_) | JumpType::IndirectJump(_) => Ok(()),
            }?;
        }
        for &ft in metadata.branch.fallthroughs.values() {
            do_va_check(ft)?;
        }
        Ok(())
    }

    /// ensure basic block at `va` is being split
    fn ensure_split(&self, metadata: &mut Metadata, va: u32) {
        if !metadata.bin.contains_key(&va) {
            return;
        }

        // get the start va from range
        if let Some((start_va, block)) = metadata
            .blocks
            .range(..=va)
            .next_back()
            .map(|(va, block)| (*va, block))
            // check if we actually need splitting
            && block.contains_va(va)
            && start_va != va
        {
            if let Some((&prev_va, _)) = metadata.bin.range(..va).next_back() {
                debug!("splitting block starting at {start_va:#x} at {va:#x}");

                let old_block = metadata.blocks.get_mut(&start_va).unwrap();
                let old_end = old_block.end_va();
                let mode = old_block.mode;

                old_block.range = start_va..=prev_va;

                let new_block = BasicBlock::new(va..=old_end, mode);
                metadata.blocks.insert(va, new_block);

                match metadata.branch.jumps.get(&prev_va) {
                    Some(
                        crate::phase1::branch_analysis::JumpType::DirectCall(_)
                        | crate::phase1::branch_analysis::JumpType::IndirectCall(_),
                    ) => {
                        trace!("marking call fallthrough from {prev_va:#x} to {va:#x}");
                        metadata.branch.mark_as_fallthrough(prev_va, va);
                    }
                    None => {
                        trace!("marking implicit fallthrough jump from {prev_va:#x} to {va:#x}");
                        metadata.branch.mark_as_direct_jump(prev_va, va);
                    }
                    _ => (),
                }
            } else {
                unreachable!("previous instruction must be available");
            }
        }
    }

    /// add `va` to the internal queue with `mode`, returning `false` if invalid or mid-instruction
    #[instrument(skip(self, metadata), fields(va = format_args!("{:#x}", va)), level = "trace")]
    pub fn enqueue_va(&mut self, metadata: &mut Metadata, va: u32, mode: CpuMode) -> bool {
        if !metadata.is_valid_va(va) {
            debug!("{va:#x} out of bounds, ignore");
            return false;
        }

        // is there a block which has `va` as start?
        if metadata.blocks.contains_key(&va) {
            // then everything is done
            debug!("{va:#x} already processed and exists as block start, no need to split");
            return true;
        }

        if let Some(c) = metadata.code_covering(va) {
            if c.va == va {
                self.ensure_split(metadata, va);
                debug!("{va:#x} already processed");
                return true;
            } else {
                debug!("{va:#x} falls inside existing instruction at {:#x}, ignore", c.va);
                return false;
            }
        }

        debug!("added {va:#x} to queue");
        self.queue.push((va, mode));
        true
    }

    fn discard_callers(metadata: &mut Metadata, va: u32) {
        let callers: SmallVec<[u32; 4]> = metadata.branch.all_for(va).collect();
        for caller_va in callers {
            debug!("discard caller at {caller_va:#x} targeting {va:#x}");
            metadata.branch.discard(caller_va);
        }
    }

    /// process `start_va` from the queue with `mode` until terminator is hit
    #[instrument(skip(self, metadata), fields(start_va = format_args!("{:#x}", start_va)), level = "trace")]
    fn process_va_block(
        &mut self,
        metadata: &mut Metadata,
        start_va: u32,
        mode: CpuMode,
    ) -> Result<Vec<Code>> {
        let mut bin: Vec<Code> = Vec::with_capacity(50);
        let mut va = start_va;
        let mut last_va = start_va;

        loop {
            if let Some(c) = metadata.code_covering(va) {
                if c.va == va {
                    if va != start_va {
                        debug!("{va:#x} already processed");
                        self.ensure_split(metadata, va);
                        match metadata.branch.jumps.get(&last_va) {
                            Some(
                                crate::phase1::branch_analysis::JumpType::DirectCall(_)
                                | crate::phase1::branch_analysis::JumpType::IndirectCall(_),
                            ) => metadata.branch.mark_as_fallthrough(last_va, va),
                            _ => metadata.branch.mark_as_direct_jump(last_va, va),
                        }
                    } else {
                        self.ensure_split(metadata, va);
                    }
                } else {
                    debug!(
                        "{va:#x} overlaps existing instruction at {:#x}, stop",
                        c.va
                    );
                    if va == start_va {
                        Self::discard_callers(metadata, va);
                    }
                }
                break;
            }

            // is va somewhere in the existing block?
            if let Some((_, block)) = metadata.blocks.range(..=va).next_back()
                && block.contains_va(va)
            {
                debug!("{va:#x} overlaps with {:#x?}, stop", block.range);
                if va == start_va {
                    Self::discard_callers(metadata, va);
                }
                break;
            }

            let min_len = if mode == CpuMode::Arm { 4 } else { 2 };
            let Some(offset) = metadata.unmap_va(va) else {
                warn!("{va:#x} out of bounds, abort analysis for the {start_va:#x} entry");
                metadata.branch.discard(va);
                if va == start_va {
                    Self::discard_callers(metadata, va);
                }
                break;
            };
            let Some(data) = metadata
                .data
                .get(offset..(offset + 4).min(metadata.data.len()))
                .filter(|s| s.len() >= min_len)
            else {
                warn!("{va:#x} out of bounds, abort analysis for the {start_va:#x} entry");
                metadata.branch.discard(va);
                if va == start_va {
                    Self::discard_callers(metadata, va);
                }
                break;
            };

            let code = match Self::disassemble_oneshot(data, mode) {
                Ok(mut code) => {
                    code.va = va;
                    code
                }
                Err(e) => {
                    // this is debug because we don't track any literal pools or noreturns, so falling into garbage is possible
                    debug!("disassembler error at {va:#x}: {e:?} (data: {data:#04x?})");
                    Self::discard_callers(metadata, va);
                    break;
                }
            };

            // stop on literals
            if va != start_va
                && (metadata.slots.contains(&va) || metadata.rev_refs.contains_key(&va))
            {
                debug!("fell into literal pool/data ref at {va:#x}, stop");
                break;
            }

            let next_va = va + code.instruction.len().to_const();
            if metadata.bin.range(va..next_va).next().is_some()
                || metadata.blocks.range(va..next_va).next().is_some()
            {
                debug!("{va:#x}..{next_va:#x} overlaps existing instruction, stop");
                if va == start_va {
                    Self::discard_callers(metadata, va);
                }
                break;
            }

            trace!(
                "new instuction: {code} ({:?} {:?})",
                code.instruction.opcode, code.instruction.operands
            );

            last_va = va;

            // this is awful, but clone is even worse, right?
            let mut stop = false;
            let is_cond = code.instruction.condition != ConditionCode::AL;

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
                        let target_ok = self.enqueue_va(metadata, target, mode);

                        // conditional B or CBZ/CBNZ have the next arm
                        if is_cond || is_cbz_cbnz {
                            let ft_ok = self.enqueue_va(metadata, next_va, mode);
                            if target_ok && ft_ok {
                                metadata.branch.mark_as_branch(code.va, target, next_va);
                            } else if ft_ok {
                                metadata.branch.mark_as_direct_jump(code.va, next_va);
                            } else if target_ok {
                                metadata.branch.mark_as_direct_jump(code.va, target);
                            }
                        } else if target_ok {
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
                            let target_ok = self.enqueue_va(metadata, code.pc(), !mode);
                            if is_cond {
                                let ft_ok = self.enqueue_va(metadata, next_va, mode);
                                if target_ok && ft_ok {
                                    metadata.branch.mark_as_branch(code.va, code.pc(), next_va);
                                } else if ft_ok {
                                    metadata.branch.mark_as_direct_jump(code.va, next_va);
                                } else if target_ok {
                                    metadata.branch.mark_as_direct_jump(code.va, code.pc());
                                }
                            } else if target_ok {
                                metadata.branch.mark_as_direct_jump(code.va, code.pc());
                            }
                        } else {
                            if !r.is_lr() {
                                metadata.branch.mark_as_indirect_jump(code.va, r);
                            }
                            if is_cond && self.enqueue_va(metadata, next_va, mode) {
                                if r.is_lr() {
                                    metadata.branch.mark_as_direct_jump(code.va, next_va);
                                } else {
                                    metadata.branch.mark_as_fallthrough(code.va, next_va);
                                }
                            }
                        }
                    } else {
                        unreachable!("BX can't have non-reg operand (code: {code})");
                    }

                    // any BX terminates the current block (with fallthrough queued if conditional)
                    stop = true;
                }
                Opcode::BL | Opcode::BLX => {
                    if let Some(target) = Self::branch_map_imm(&code, code.instruction.operands[0])
                    {
                        Self::sanity_check_va_align(target)?;
                        let next_mode = CpuMode::from_code_and_va(&code, target);
                        let next_target = mode.align_va_on_switch(&next_mode, target);

                        if self.enqueue_va(metadata, next_target, next_mode) {
                            metadata.branch.mark_as_direct_call(code.va, next_target);
                        }
                    } else if let Operand::Reg(r) = code.instruction.operands[0] {
                        metadata.branch.mark_as_indirect_call(code.va, r);
                    }
                }
                Opcode::POP => {
                    let writes_pc = match code.instruction.operands[0] {
                        Operand::RegList(list) => list.has_pc(),
                        Operand::Reg(r) => r.is_pc(),
                        _ => false,
                    };
                    if writes_pc {
                        if is_cond && self.enqueue_va(metadata, next_va, mode) {
                            metadata.branch.mark_as_direct_jump(code.va, next_va);
                        }
                        stop = true;
                    }
                }
                Opcode::LDM(..) => {
                    if let Operand::RegList(list) = code.instruction.operands[1]
                        && list.has_pc()
                    {
                        if is_cond && self.enqueue_va(metadata, next_va, mode) {
                            metadata.branch.mark_as_direct_jump(code.va, next_va);
                        }
                        stop = true;
                    }
                }
                Opcode::ERET => {
                    stop = true;
                }
                Opcode::TBB => {
                    if let Operand::RegDerefPreindexReg(base, r, _, _) =
                        code.instruction.operands[0]
                    {
                        if base.is_pc() {
                            self.table_expand(
                                metadata,
                                &bin,
                                code.va,
                                mode,
                                r,
                                code.pc(),
                                None,
                                1,
                            );
                        }
                    } else {
                        warn!("unexpected TBB operands at {code}: {:?}", code.instruction.operands);
                    }

                    if is_cond && self.enqueue_va(metadata, next_va, mode) {
                        metadata.branch.mark_as_fallthrough(code.va, next_va);
                    }
                    stop = true;
                }
                Opcode::TBH => {
                    if let Operand::RegDerefPreindexRegShift(base, shift, _, _) =
                        code.instruction.operands[0]
                    {
                        if base.is_pc()
                            && let RegShiftStyle::RegImm(ris) = shift.into_shift()
                            && ris.imm() == 1
                            && ris.stype() == ShiftStyle::LSL
                        {
                            self.table_expand(
                                metadata,
                                &bin,
                                code.va,
                                mode,
                                ris.shiftee(),
                                code.pc(),
                                None,
                                2,
                            );
                        }
                    } else {
                        warn!("unexpected TBH operands at {code}: {:?}", code.instruction.operands);
                    }

                    if is_cond && self.enqueue_va(metadata, next_va, mode) {
                        metadata.branch.mark_as_fallthrough(code.va, next_va);
                    }
                    stop = true;
                }
                Opcode::LDR => {
                    if let Operand::Reg(rt) = code.instruction.operands[0] {
                        if let Operand::RegDerefPreindexOffset(r, imm, up, _) =
                            code.instruction.operands[1]
                            && r.is_pc()
                        {
                            let pc = if mode == CpuMode::Thumb {
                                code.pc() & !3
                            } else {
                                code.pc()
                            };

                            let slot_va = if up {
                                pc.wrapping_add(imm as u32)
                            } else {
                                pc.wrapping_sub(imm as u32)
                            };

                            if let Some(load) = metadata.unmap_va(slot_va)
                                && let Some(slice) = metadata.data.get(load..)
                                && let Some(reg_val) = a32_ldr_data(slice, code.instruction.opcode)
                            {
                                if rt.is_pc() {
                                    if metadata.is_valid_va(reg_val & !1) {
                                        let next_mode = CpuMode::from_code_and_va(&code, reg_val);
                                        let next_target =
                                            mode.align_va_on_switch(&next_mode, reg_val);
                                        if self.enqueue_va(metadata, next_target, next_mode) {
                                            metadata
                                                .branch
                                                .mark_as_direct_call(code.va, next_target);
                                        }
                                    } else {
                                        warn!("jumpout to {reg_val:#x} (at {code}), won't follow");
                                    }
                                    metadata.slots.insert(slot_va);
                                } else {
                                    metadata.slots.insert(slot_va);
                                    metadata.refs.insert(code.va, reg_val);
                                    metadata.rev_refs.entry(reg_val).or_default().push(code.va);
                                    trace!("add slot {slot_va:#x}");
                                    trace!("add {reg_val:#x} value for {va:#x}");
                                }
                            }
                        }

                        if rt.is_pc() {
                            if is_cond && self.enqueue_va(metadata, next_va, mode) {
                                metadata.branch.mark_as_fallthrough(code.va, next_va);
                            }
                            stop = true;
                        }
                    }
                }
                Opcode::ADR => {
                    if let Operand::Imm32(imm) = code.instruction.operands[1] {
                        let addr = (code.pc() & !3).wrapping_add(imm);
                        metadata.refs.insert(code.va, addr);
                        metadata.rev_refs.entry(addr).or_default().push(code.va);
                        trace!("add {addr:#x} to data refs");
                    } else {
                        warn!("unhandled ADR operands in {code}");
                    }
                }
                Opcode::MOV => {
                    if let Operand::Reg(rd) = code.instruction.operands[0]
                        && rd.is_pc()
                    {
                        if is_cond && self.enqueue_va(metadata, next_va, mode) {
                            metadata.branch.mark_as_direct_jump(code.va, next_va);
                        }
                        stop = true;
                    }
                }
                Opcode::ADD | Opcode::SUB => {
                    let is_add = code.instruction.opcode == Opcode::ADD;
                    if let Operand::Reg(rd) = code.instruction.operands[0]
                        && rd.is_pc()
                    {
                        if is_cond && self.enqueue_va(metadata, next_va, mode) {
                            metadata.branch.mark_as_direct_jump(code.va, next_va);
                        }
                        stop = true;
                    } else if let Operand::Reg(rn) = code.instruction.operands[0]
                        && let Operand::Reg(r_should_be_pc) = code.instruction.operands[1]
                        && r_should_be_pc.is_pc()
                    {
                        if let Operand::Imm32(imm) = code.instruction.operands[2] {
                            // Thumb-2 ADR.W is decoded by yaxpeax-arm as ADD/SUB Rd, PC, #imm
                            let pc = code.pc() & !3;
                            let addr = if is_add {
                                pc.wrapping_add(imm)
                            } else {
                                pc.wrapping_sub(imm)
                            };
                            metadata.refs.insert(code.va, addr);
                            metadata.rev_refs.entry(addr).or_default().push(code.va);
                            trace!("add {addr:#x} to data refs (ADR.W)");
                        } else if is_add
                            && matches!(
                                code.instruction.operands[2],
                                Operand::Nothing | Operand::Reg(_)
                            )
                            // ADD Rn, PC is usually used in PIE binaries to fixup relative loads
                            && let Some(ldr) = bin.iter().rev().find(|c| {
                                if let Operand::Reg(r) = c.instruction.operands[0]
                                    && r == rn
                                    && let Operand::RegDerefPreindexOffset(r_should_be_pc, _, _, _) =
                                        c.instruction.operands[1]
                                    && r_should_be_pc.is_pc()
                                    && c.instruction.opcode == Opcode::LDR
                                {
                                    true
                                } else {
                                    false
                                }
                            })
                            && let Some(&ldr_raw) = metadata.refs.get(&ldr.va)
                        {
                            debug!(
                                "fixed ref originally created at {:#x} at {:#x}",
                                ldr.va, code.va
                            );

                            let ldr_val = ldr_raw as i32;
                            debug!("LDR pool value: {ldr_val:#x}");
                            let ldr_va = ldr_val.wrapping_add_unsigned(code.pc());

                            metadata.refs.insert(code.va, ldr_va as u32);
                            metadata
                                .rev_refs
                                .entry(ldr_va as u32)
                                .or_default()
                                .push(code.va);
                            debug!("ADD value: {ldr_va:#x}");
                        }
                    }
                }
                Opcode::ORR | Opcode::BIC | Opcode::MVN => {
                    if let Operand::Reg(rd) = code.instruction.operands[0]
                        && rd.is_pc()
                    {
                        if is_cond && self.enqueue_va(metadata, next_va, mode) {
                            metadata.branch.mark_as_direct_jump(code.va, next_va);
                        }
                        stop = true;
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

        trace!(
            "{start_va:#x}..={last_va:#x}: code size: {} instructions",
            bin.len()
        );

        if !bin.is_empty() {
            metadata
                .blocks
                .insert(start_va, BasicBlock::new(start_va..=last_va, mode));
        }

        Ok(bin)
    }

    /// process `self.queue`
    #[instrument(skip(self, metadata), level = "trace")]
    pub fn process_queue(&mut self, metadata: &mut Metadata) -> Result<()> {
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
        debug!("discarding invalid jumps");
        self.bad.iter().for_each(|&va| {
            if let Some((_, block)) = metadata.blocks.range_mut(..=va).next_back()
                && block.contains_va(va)
            {
                trace!("dropping {va:#x}");
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
            CpuMode::Thumb => match disassemble_thumb_oneshot(data) {
                Ok(v) => Ok(v),
                Err(yaxpeax_arm::armv7::DecodeError::Incomplete) if data.len() >= 2 => {
                    let hw1 = u16::from_le_bytes([data[0], data[1]]);
                    let is_wide = (hw1 >> 11) >= 0b11101;
                    if is_wide && data.len() < 4 {
                        return Err(Phase1Error::Disassembler(
                            yaxpeax_arm::armv7::DecodeError::Incomplete,
                        ));
                    }
                    Ok(Code {
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
                            wide: is_wide,
                            thumb_w: false,
                            thumb: true,
                        },
                        va: 0,
                    })
                }
                Err(e) => Err(Phase1Error::Disassembler(e)),
            },
        }
    }

    /// create jump table from given parameters
    fn table_expand(
        &mut self,
        metadata: &mut Metadata,
        current_bin: &[Code],
        table_inst_va: u32,
        mode: CpuMode,
        table_target: Reg,
        table_start: u32,
        table_size: Option<u32>,
        word_size: usize,
    ) {
        let size = table_size.or_else(|| {
            let mut branch_cond = None;
            let iter = current_bin
                .iter()
                .rev()
                .chain(metadata.bin.range(..table_inst_va).rev().map(|(_, c)| c))
                .take(20);
            for c in iter {
                if c.instruction.opcode == Opcode::B
                    && c.instruction.condition != ConditionCode::AL
                    && branch_cond.is_none()
                {
                    branch_cond = Some(c.instruction.condition);
                }
                if c.instruction.opcode == Opcode::CMP
                    && let Operand::Reg(r) = c.instruction.operands[0]
                    && r == table_target
                    && let Operand::Imm32(imm) = c.instruction.operands[1]
                {
                    let exclusive = matches!(
                        branch_cond,
                        Some(
                            ConditionCode::HS
                                | ConditionCode::GE
                                | ConditionCode::LO
                                | ConditionCode::LT
                        )
                    );
                    return Some(if exclusive { imm } else { imm + 1 });
                }
            }
            None
        });
        let Some(size) = size else {
            warn!("failed to determine table size at {table_inst_va:#x}");
            return;
        };

        let Some(offset) = metadata.unmap_va(table_start) else {
            warn!("jump table start {table_start:#x} out of bounds");
            return;
        };
        let Some(table_bytes_len) = (size as usize).checked_mul(word_size) else {
            return;
        };
        let Some(table_slice) = metadata.data.get(offset..offset + table_bytes_len) else {
            warn!("jump table at {table_inst_va:#x} exceeds binary bounds");
            return;
        };

        let mut targets = table_slice
            .chunks_exact(word_size)
            .map(|word| {
                let branch_offset = match word_size {
                    1 => word[0] as u32,
                    2 => u16::from_le_bytes(word.try_into().unwrap()) as u32,
                    4 => u32::from_le_bytes(word.try_into().unwrap()),
                    _ => unreachable!("invalid table word size"),
                };

                if word_size == 4 {
                    // LDR jumps are absolute
                    branch_offset
                } else {
                    // TBB/TBH are relative to PC (table_start)
                    table_start.wrapping_add(2 * branch_offset)
                }
            })
            .filter(|t| {
                let va = *t & !1;
                metadata.is_valid_va(va)
                    && (word_size == 4
                        || va < table_start
                        || va >= table_start.wrapping_add(table_bytes_len as u32))
            })
            .collect::<SmallVec<[u32; 10]>>();

        targets.retain(|target| self.enqueue_va(metadata, *target, mode));

        if targets.is_empty() {
            return;
        }

        debug!("jump table at {table_inst_va:#x}: {:#x?}", targets);
        metadata.branch.mark_as_table(table_inst_va, &targets);
    }

    /// map branch immediate value to VA
    #[inline(always)]
    fn branch_map_imm(code: &Code, operand: Operand) -> Option<u32> {
        let target = match operand {
            Operand::BranchOffset(target) | Operand::BranchThumbOffset(target) => target,
            Operand::Reg(_) => return None,
            _ => unreachable!(),
        };
        Some(code.pc().wrapping_add_signed(target))
    }

    /// check if VA is aligned
    #[inline(always)]
    fn sanity_check_va_align(va: u32) -> Result<()> {
        if va & 1 == 0 {
            Ok(())
        } else {
            Err(Phase1Error::UnalignedVA(va))
        }
    }
}
