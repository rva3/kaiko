use ahash::AHashSet;
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
    pub fn resolve_register_state(&mut self, metadata: &mut Metadata) -> Vec<(u32, CpuMode)> {
        let mut new_jumps = Vec::new();

        // all blocks go into queue
        self.queue.clear();
        self.queue.reserve(metadata.blocks.len());
        for va in metadata.blocks.keys() {
            self.queue.push(*va);
        }

        let mut qlookup = self.queue.iter().copied().collect::<AHashSet<_>>();

        while let Some(start_va) = self.queue.pop() {
            qlookup.remove(&start_va);
            let (range, mode, mut rwt) = {
                let block = metadata.blocks.get(&start_va).unwrap();
                (block.range.clone(), block.mode, block.entry_state)
            };

            for (va, code) in metadata.bin.range(range.clone()) {
                trace!("at {code}");

                if let Some(JumpType::IndirectCall(r) | JumpType::IndirectJump(r)) =
                    metadata.branch.get_callee(*va)
                {
                    if let Some(value) = rwt.try_get_imm(*r, metadata.base_address, &metadata.data)
                        && let Some(value) = metadata.map_va(value)
                    {
                        let new_mode = CpuMode::from_code_and_va(code, value);
                        let new_value = mode.align_va_on_switch(&new_mode, value);

                        if metadata.is_valid_va(new_value)
                            && metadata.code_covering(new_value).is_none_or(|c| c.va == new_value)
                        {
                            debug!("solved indirection: r{} -> {new_value:#x}", r.number());
                            // even though this is technically indirect call, let's promote it to direct
                            // so it can be properly resolved by the `AsmAnalysis` and external crates
                            metadata.branch.mark_as_direct_call(*va, new_value);
                            new_jumps.push((new_value, new_mode));
                        }
                    }
                }

                rwt.step(code, &metadata.data, metadata.base_address);
            }

            trace!("{:?}", rwt.snapshot());

            let mut state_changed = false;
            if let Some(block) = metadata.blocks.get_mut(&start_va) {
                // if block state changed then update it
                if block.exit_state != rwt {
                    block.exit_state = rwt;
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
                        JumpType::Table(idx) => {
                            if let Some(targets) = metadata.branch.jump_tables.get(*idx) {
                                successor_vas.extend(targets.iter().copied());
                            }
                        }
                        _ => (),
                    }
                }
                if let Some(&ft) = metadata.branch.fallthroughs.get(&end_va) {
                    successor_vas.push(ft);
                }

                for va in successor_vas {
                    if let Some(block) = metadata.blocks.get_mut(&va) {
                        if block.entry_state.merge(&rwt) {
                            if !qlookup.contains(&va) {
                                debug!("state change propagated, queue {va:#x} again");
                                self.queue.push(va);
                                qlookup.insert(va);
                            }
                        }
                    }
                }
            }
        }

        new_jumps
    }
}
