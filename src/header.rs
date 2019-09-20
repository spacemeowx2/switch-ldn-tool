use byteorder::{ByteOrder, BigEndian, LittleEndian};

#[derive(Debug)]
pub struct FrameHeader {
    unk1: u32,
    unk2: u16,
    unk3: u64,
    unk4: u64,
}

mod frame_field {
    pub type Field = ::core::ops::Range<usize>;

    pub const UNK1: Field = 0..4;
    pub const UNK2: Field = 8..10;
    pub const UNK3: Field = 16..24;
    pub const UNK4: Field = 24..32;
}

mod byte_field {
    pub type Field = ::core::ops::Range<usize>;

    pub const UNK1: Field = 0..8;
    pub const UNK2: Field = 8..12;
    pub const UNK3: Field = 16..24;
    pub const UNK4: Field = 24..32;
}

pub fn transform_header(data: &[u8; 32]) -> [u8; 32] {
    let unk1 = BigEndian::read_u32(&data[frame_field::UNK1]);
    let unk2 = BigEndian::read_u16(&data[frame_field::UNK2]);
    let unk3 = LittleEndian::read_u64(&data[frame_field::UNK3]);
    let unk4 = LittleEndian::read_u64(&data[frame_field::UNK4]);

    let mut buf = [0; 32];
    LittleEndian::write_u64(&mut buf[byte_field::UNK1], unk1.into());
    LittleEndian::write_u32(&mut buf[byte_field::UNK2], unk2.into());
    LittleEndian::write_u64(&mut buf[byte_field::UNK3], unk3);
    LittleEndian::write_u64(&mut buf[byte_field::UNK4], unk4);
    buf
}

impl FrameHeader {
    pub const SIZE: usize = 32;
    pub fn from_frame(data: &[u8]) -> FrameHeader {
        FrameHeader {
            unk1: BigEndian::read_u32(&data[frame_field::UNK1]),
            unk2: BigEndian::read_u16(&data[frame_field::UNK2]),
            unk3: BigEndian::read_u64(&data[frame_field::UNK3]),
            unk4: BigEndian::read_u64(&data[frame_field::UNK4]),
        }
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0; 32];
        BigEndian::write_u64(&mut buf[byte_field::UNK1], self.unk1.into());
        BigEndian::write_u32(&mut buf[byte_field::UNK2], self.unk2.into());
        BigEndian::write_u64(&mut buf[byte_field::UNK3], self.unk3);
        BigEndian::write_u64(&mut buf[byte_field::UNK4], self.unk4);
        buf
    }
}
