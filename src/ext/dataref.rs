use yaxpeax_arm::armv7::Opcode;

pub enum LoadSize {
    DoubleWord,
    Word,
    HalfWord,
    Byte,
}

pub trait DataRefExt {
    fn load_size(&self) -> usize;
    fn is_signed_load(&self) -> bool;
}

impl DataRefExt for Opcode {
    fn load_size(&self) -> usize {
        match self {
            /* LDR */
            Self::LDREXD => 8,
            Self::LDREX | Self::LDR => 4,
            Self::LDREXH | Self::LDRH | Self::LDRSH | Self::LDRSHT => 2,
            Self::LDREXB | Self::LDRB | Self::LDRSB | Self::LDRSBT => 1,
            _ => 0,
        }
    }

    fn is_signed_load(&self) -> bool {
        matches!(
            self,
            /* S = signed */
            Self::LDRSH | Self::LDRSHT | Self::LDRSB | Self::LDRSBT
        )
    }
}

pub fn a32_ldr_data(data: &[u8], op: Opcode) -> Option<usize> {
    let data = &data[..op.load_size()];
    match op.load_size() {
        1 => {
            let v = u8::from_le_bytes(data.try_into().unwrap());
            if op.is_signed_load() {
                Some((v as i8) as usize)
            } else {
                Some(v as usize)
            }
        }
        2 => {
            let v = u16::from_le_bytes(data.try_into().unwrap());
            if op.is_signed_load() {
                Some((v as i16) as usize)
            } else {
                Some(v as usize)
            }
        }
        4 => {
            let v = u32::from_le_bytes(data.try_into().unwrap());
            if op.is_signed_load() {
                Some((v as i32) as usize)
            } else {
                Some(v as usize)
            }
        }
        8 => todo!(),
        _ => None,
    }
}
