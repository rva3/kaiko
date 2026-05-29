use tracing::{debug, instrument, trace, warn};

use crate::{
    cpu_mode::CpuMode,
    phase1::{Metadata, branch_analysis::JumpType},
};

pub struct IndirectAnalysis {
    pub queue: Vec<u32>,
}

impl IndirectAnalysis {
    pub fn new() -> Self {
        Self { queue: Vec::new() }
    }

    /// try resolve register values for indirect jumps/calls
    ///
    /// this is similar to `process_va_block`, but instead of raw instructions,
    /// the branch analysis metadata is used
    #[instrument(skip(self, metadata), level = "trace")]
    pub fn resolve_register_state(&mut self, metadata: &mut Metadata<'_>) -> Vec<(u32, CpuMode)> {
        let mut new_jumps = Vec::new();

        // all blocks go into queue
        self.queue.clear();
        for block in metadata.blocks.iter() {
            self.queue.push(block.start_va());
        }

        while let Some(start_va) = self.queue.pop() {
            let (range, mode, mut rwt) = {
                let block = metadata
                    .blocks
                    .iter()
                    .find(|b| b.start_va() == start_va)
                    .unwrap();
                (block.range.clone(), block.mode, block.entry_state.clone())
            };

            for (va, code) in metadata.bin.range(range.clone()) {
                trace!("at {code}");

                rwt.step(code, metadata.data, metadata.base_address);

                match metadata.branch.get_callee(*va) {
                    Some(JumpType::IndirectCall(r) | JumpType::IndirectJump(r)) => {
                        if let Some(value) =
                            rwt.try_get_imm(*r, metadata.base_address, metadata.data)
                            && let Some(value) = metadata.map_va(value)
                        {
                            debug!("solved indirection: r{} -> {value:#x}", r.number());
                            let new_mode = CpuMode::from_code_and_va(&code, value);
                            let new_value = mode.align_va_on_switch(&new_mode, value);

                            // even though this is technically indirect call, let's promote it to direct
                            // so it can be properly resolved by the `AsmAnalysis` and external crates
                            metadata.branch.mark_as_direct_call(*va, new_value);
                            new_jumps.push((new_value, new_mode));
                        }
                    }
                    _ => (),
                }
            }

            trace!("{:?}", rwt.snapshot());

            let mut state_changed = false;
            if let Some(block) = metadata
                .blocks
                .iter_mut()
                .find(|b| b.start_va() == start_va)
            {
                // if block state changed then update it
                if block.exit_state != rwt {
                    block.exit_state = rwt.clone();
                    state_changed = true;
                }
            }

            if state_changed {
                trace!("state changed");
                // set new state to all successor blocks
                let end_va = *range.end();
                let mut successor_vas = Vec::new();

                if let Some(callee) = metadata.branch.get_callee(end_va) {
                    match callee {
                        JumpType::DirectJump(target) => successor_vas.push(*target),
                        JumpType::Branch {
                            target,
                            fallthrough,
                        } => {
                            successor_vas.push(*target);
                            successor_vas.push(*fallthrough);
                        }
                        _ => (),
                    }
                }

                for va in successor_vas {
                    if let Some(block) = metadata.blocks.iter_mut().find(|b| b.start_va() == va) {
                        if block.entry_state.merge(&rwt) {
                            if !self.queue.contains(&va) {
                                debug!("state change propagated, queue {va:#x} again");
                                self.queue.push(va);
                            }
                        }
                    }
                }
            }
        }

        new_jumps
    }
}
