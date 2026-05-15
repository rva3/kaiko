use crate::phase1::{Metadata, branch_analysis::JumpType};

pub struct BlockAnalysis;

impl BlockAnalysis {
    pub fn add_metadata(metadata: &mut Metadata) {
        for block in &mut metadata.blocks {
            // predecessors are blocks which jump to this block, but not function calls
            block
                .predecessors
                .extend(metadata.branch.all_jumps_for(block.start_va()));

            // clone is very cheap here
            let block_code = metadata.bin.range(block.range.clone());

            // XXX: move to branch analysis?
            block.successors.extend(
                block_code
                    .filter_map(|(va, _)| match metadata.branch.get_callee(*va)? {
                        JumpType::DirectJump(v) => Some([Some(*v), None]),
                        JumpType::Branch {
                            target,
                            fallthrough,
                        } => Some([Some(*target), Some(*fallthrough)]),
                        _ => None,
                    })
                    .flatten()
                    .filter_map(|va| va),
            );
        }
    }
}
