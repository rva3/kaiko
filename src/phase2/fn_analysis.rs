use crate::phase2::{Function, Metadata};
use ahash::{AHashMap, AHashSet};
use tracing::{debug, instrument, trace};

pub struct FnAnalysis;

impl FnAnalysis {
    #[instrument(skip(metadata), level = "trace")]
    pub fn create_functions(metadata: &mut Metadata) {
        let va2idx = metadata
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start_va(), i))
            .collect::<AHashMap<_, _>>();

        for i in 0..metadata.blocks.len() {
            let block = &mut metadata.blocks[i];

            if !metadata.branch.is_fn(block.start_va()) {
                continue;
            }

            debug!("function at {:#x}", block.start_va());

            // if it was tail call, clear all predecessors
            block.predecessors.clear();

            let mut fn_blocks = Vec::new();
            let mut queue = vec![i];
            let mut visited = AHashSet::new();

            while let Some(current_idx) = queue.pop() {
                if !visited.insert(current_idx) {
                    trace!(
                        "already processed {:#x}",
                        metadata.blocks[current_idx].start_va()
                    );
                    // stop if already processed
                    continue;
                }

                trace!(
                    "add {:#x}-{:#x} to fn",
                    metadata.blocks[current_idx].start_va(),
                    metadata.blocks[current_idx].end_va()
                );
                fn_blocks.push(current_idx);

                if let Some(current_block) = metadata.blocks.get(current_idx) {
                    for &successor_va in &current_block.successors {
                        if let Some(&idx) = va2idx.get(&successor_va) {
                            queue.push(idx);
                        } else {
                            unreachable!("block must exist since VA was added by phase 1");
                        }
                    }
                }
            }

            debug!(
                "created function: {:#x?}",
                fn_blocks
                    .iter()
                    .map(|&i| metadata.blocks[i].start_va())
                    .collect::<Vec<_>>()
            );
            metadata.fns.push(Function::new(fn_blocks));
        }
    }
}
