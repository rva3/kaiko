use yaxpeax_arch::{Arch, Decoder, ReaderBuilder};
use yaxpeax_arm::armv7::{ARMv7, DecodeError, InstDecoder};

use crate::Code;

type Result<T> = core::result::Result<T, DecodeError>;

fn disassemble_oneshot(decoder: InstDecoder, data: &[u8]) -> Result<Code> {
    let mut reader =
        ReaderBuilder::<<ARMv7 as Arch>::Address, <ARMv7 as Arch>::Word>::read_from(data);
    decoder.decode(&mut reader).map(|inst| Code::new(inst, 0))
}

pub fn disassemble_thumb_oneshot(data: &[u8]) -> Result<Code> {
    disassemble_oneshot(InstDecoder::armv7_thumb(), data)
}

pub fn disassemble_arm_oneshot(data: &[u8]) -> Result<Code> {
    disassemble_oneshot(InstDecoder::armv7(), data)
}
