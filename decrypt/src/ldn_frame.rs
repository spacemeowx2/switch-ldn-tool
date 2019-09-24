use crate::keys::{Keys, AesKey, aes_128_ctr_dec};
use std::fs::File;
use std::io::prelude::*;
use sha2::{Sha256, Digest};
use byteorder::{ByteOrder, BigEndian};

#[repr(C, packed)]
pub struct LdnFrameHeader([u8; 40]);

pub struct LdnFrame {
    header: LdnFrameHeader,
    content: Vec<u8>,
}

pub struct LdnFrameBuilder {
    keys: Keys,
    pub verbose: bool,
    pub offset: u64,
    pub padding: usize,
}

impl LdnFrameBuilder {
    const HARDCODED_SOURCE: [u8; 16] =  [0x19, 0x18, 0x84, 0x74, 0x3e, 0x24, 0xc7, 0x7d, 0x87, 0xc6, 0x9e, 0x42, 0x7, 0xd0, 0xc4, 0x38];
    pub fn new(keys: Keys) -> LdnFrameBuilder {
        LdnFrameBuilder {
            keys,
            verbose: false,
            offset: 0,
            padding: 0,
        }
    }
    pub fn encrypt(&self, file: &mut File, output_file: &mut File) -> std::io::Result<()> {
        println!("Building mode");
        let skipped_buf = self.read_offset(file)?;
        let mut frame = LdnFrame::new();
        frame.read_from_file(file)?;

        let header = &frame.header;

        if self.verbose {
            println!("header: {:x?}", &header);
        }

        let key = self.get_key(&header);

        let hash = frame.calculate_sha256();
        if hash == frame.sha256() {
            println!("checksum is not changed");
        } else {
            println!("checksum mismatch, using new checksum: {:x?}", hash);
            frame.set_sha256(&hash);
        }

        frame.encrypt(&key);

        output_file.write(&skipped_buf)?;
        frame.write_to_file(output_file)?;
        output_file.write(&vec![0u8; self.padding][..])?;
        Ok(())
    }
    pub fn decrypt(&self, file: &mut File, output_file: &mut File) -> std::io::Result<()> {
        let skipped_buf = self.read_offset(file)?;
        let mut frame = LdnFrame::new();
        frame.read_from_file(file)?;

        let header = &frame.header;

        if self.verbose {
            println!("header: {:x?}", &header);
        }

        let key = self.get_key(&header);
        frame.decrypt(&key);

        output_file.write(&skipped_buf)?;
        frame.write_to_file(output_file)?;
        output_file.write(&vec![0u8; self.padding][..])?;
        Ok(())
    }
    fn get_key(&self, header: &LdnFrameHeader) -> AesKey {
        let keys = &self.keys;
        let hash = sha256_16(&header.bytes()[0..32]);
        let kek = keys.generate_aes_kek(&LdnFrameBuilder::HARDCODED_SOURCE);
        let key = keys.generate_aes_key(&kek, &hash);

        if self.verbose {
            println!("hash: {:x?}", &hash);
            println!("kek: {:x?}", &kek);
            println!("key: {:x?}", &key);
        }

        key
    }
    fn read_offset(&self, file: &mut File) -> std::io::Result<Vec<u8>> {
        if self.verbose {
            println!("seeking to offset: {:?}", self.offset);
        }
        let offset = self.offset as usize;
        let mut out: Vec<u8> = vec![0; offset];
        file.read_exact(&mut out)?;
        Ok(out)
    }
}

fn s32_16(s32: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&s32[0..16]);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.input(data);
    let result = hasher.result();
    output.copy_from_slice(result.as_slice());
    output
}

fn sha256_16(data: &[u8]) -> [u8; 16] {
    s32_16(&sha256(data))
}

mod header_field {
    type Field = core::ops::Range<usize>;
    pub const UNK1: Field = 0..4;
    pub const UNK2: Field = 10..12;
    pub const SSID: Field = 16..32;
    pub const CONTENT_LENGTH: Field = 34..36;
    pub const NONCE: Field = 36..40;
}
mod frame_field {
    type Field = core::ops::Range<usize>;
    pub const SHA256: Field = 0..32;
}

impl std::fmt::Debug for LdnFrameHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LdnFrameHeader {{
    unk1: {:x?},
    unk2: {:x?},
    ssid: {:x?},
    contnet_length: {},
    nonce: {:x?},
}}",
            &self.0[header_field::UNK1],
            &self.0[header_field::UNK2],
            &self.ssid_str(),
            &self.content_length(),
            &self.nonce(),
        )
    }
}

impl LdnFrameHeader {
    const SIZE: usize = 40;
    fn new() -> LdnFrameHeader {
        LdnFrameHeader([0; LdnFrameHeader::SIZE])
    }
    fn read_from_file(&mut self, file: &mut File) -> std::io::Result<()> {
        file.read_exact(&mut self.0)?;
        Ok(())
    }
    fn nonce(&self) -> &[u8] {
        &self.0[header_field::NONCE]
    }
    fn content_length(&self) -> usize {
        BigEndian::read_u16(&self.0[header_field::CONTENT_LENGTH]) as usize
    }
    fn bytes(&self) -> &[u8; LdnFrameHeader::SIZE] {
        &self.0
    }
    fn ssid_str(&self) -> String {
        hex::encode(&self.0[header_field::SSID])
    }
}

impl LdnFrame {
    fn new() -> LdnFrame {
        LdnFrame {
            header: LdnFrameHeader::new(),
            content: Vec::new(),
        }
    }
    fn read_from_file(&mut self, file: &mut File) -> std::io::Result<()> {
        self.header.read_from_file(file)?;
        self.content = vec![0; self.header.content_length() + 32];
        file.read_exact(&mut self.content)?;
        Ok(())
    }
    fn write_to_file(&self, file: &mut File) -> std::io::Result<()> {
        file.write(self.header.bytes())?;
        file.write(&self.content)?;
        Ok(())
    }
    fn sha256(&self) -> &[u8] {
        &self.content[frame_field::SHA256]
    }
    fn set_sha256(&mut self, hash: &[u8; 32]) {
        &mut self.content[frame_field::SHA256].copy_from_slice(hash);
    }
    fn calculate_sha256(&self) -> [u8; 32] {
        let mut output = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.input(&self.header.bytes()[..]);
        hasher.input(&[0; 32]);
        hasher.input(&self.content[32..]);
        let result = hasher.result();
        output.copy_from_slice(result.as_slice());
        output
    }
    fn decrypt(&mut self, key: &AesKey) {
        let mut nonce = [0u8; 16];
        nonce[0..4].copy_from_slice(self.header.nonce());
        aes_128_ctr_dec(&mut self.content, key, &nonce);
    }
    fn encrypt(&mut self, key: &AesKey) {
        self.decrypt(key)
    }
}