use crate::keys::{Keys, aes_128_ctr_dec};
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use sha2::{Sha256, Digest};

pub struct LdnFrame {
    keys: Keys,
    pub verbose: bool,
    pub offset: u64,
}

impl LdnFrame {
    const HARDCODED_SOURCE: [u8; 16] =  [0x19, 0x18, 0x84, 0x74, 0x3e, 0x24, 0xc7, 0x7d, 0x87, 0xc6, 0x9e, 0x42, 0x7, 0xd0, 0xc4, 0x38];
    pub fn new(keys: Keys) -> LdnFrame {
        LdnFrame {
            keys,
            verbose: false,
            offset: 0,
        }
    }
    pub fn decrypt(&self, file: &mut File, output_file: &mut File) -> std::io::Result<()> {
        let mut header_bytes = [0u8; 32];
        let mut header2_bytes = [0u8; 4];
        let mut nonce_bytes = [0u8; 4];
        let mut nonce = [0u8; 16];
        let mut data = [0u8; 1312];

        let skipped_buf = self.read_offset(file)?;
        file.read_exact(&mut header_bytes)?;
        file.read_exact(&mut header2_bytes)?;
        file.read_exact(&mut nonce_bytes)?;
        file.read_exact(&mut data)?;

        nonce[0..4].copy_from_slice(&nonce_bytes);
        if self.verbose {
            println!("nonce: {:x?}", &nonce);
        }

        // let transformed_header = transform_header(&header_bytes);
        if self.verbose {
            println!("header: {:x?}", &header_bytes);
            // println!("transformed_header: {:x?}", &transformed_header);
        }
        let hash = s32_16(&sha256(&header_bytes));
        if self.verbose {
            println!("hash: {:x?}", &hash);
        }

        let keys = &self.keys;
        let kek = keys.generate_aes_kek(&LdnFrame::HARDCODED_SOURCE);
        let key = keys.generate_aes_key(&kek, &hash);

        if self.verbose {
            println!("kek: {:x?}", &kek);
            println!("key: {:x?}", &key);
        }

        aes_128_ctr_dec(&mut data, &key, &nonce);

        output_file.write(&skipped_buf)?;
        output_file.write(&header_bytes)?;
        output_file.write(&header2_bytes)?;
        output_file.write(&nonce_bytes)?;
        output_file.write(&data)?;
        Ok(())
    }
    fn read_offset(&self, file: &mut File) -> std::io::Result<Vec<u8>> {
        if self.verbose {
            println!("seeking to offset: {:?}", self.offset);
        }
        let offset = self.offset as usize;
        let mut out: Vec<u8> = vec![0; offset];
        file.read_exact(&mut out)?;
        println!("fuck {:x?} {}", out, self.offset);
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
