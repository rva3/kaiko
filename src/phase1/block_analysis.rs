use crate::phase1::{Metadata, branch_analysis::JumpType};

pub struct BlockAnalysis;

impl BlockAnalysis {
    pub fn add_metadata(metadata: &mut Metadata) {
        for block in metadata.blocks.values_mut() {
            // predecessors are blocks which jump to this block, but not function calls
            block
                .predecessors
                .extend(metadata.branch.all_jumps_for(block.start_va()));

            // clone is very cheap here
            let block_code = metadata.bin.range(block.range.clone());

            block_code.for_each(|(va, _)| match metadata.branch.get_callee(*va) {
                Some(JumpType::DirectJump(v)) => block.successors.push(*v),
                Some(JumpType::Branch {
                    target,
                    fallthrough,
                }) => {
                    block.successors.push(*target);
                    block.successors.push(*fallthrough);
                }
                Some(JumpType::Table(idx)) => {
                    let items = metadata
                        .branch
                        .jump_tables
                        .get(*idx)
                        .expect("jump table must exist");
                    block.successors.extend(items);
                }
                _ => (),
            });
        }
    }
}
