use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

pub const AES_128_KEY_SIZE: usize = 16;
pub struct KeySource([u8; AES_128_KEY_SIZE]);

#[derive(Debug)]
pub struct Keys {
    aes_kek_generation_source: Vec<u8>,
    aes_key_generation_source: Vec<u8>,
}

fn decode_hex_key(key: &str) -> Vec<u8> {
    hex::decode(key.trim()).expect("Decoding failed")
}

impl Keys {
    pub fn new() -> Keys {
        Keys {
            aes_kek_generation_source: vec![],
            aes_key_generation_source: vec![],
        }
    }
    pub fn read_from_file(&mut self, filename: &str) -> std::io::Result<()> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        while let Some(Ok(line)) = lines.next() {
            let split: Vec<&str> = line.splitn(2, "=").collect();
            let key = decode_hex_key(split[1]);
            match split[0].trim() {
                "aes_kek_generation_source" => self.aes_kek_generation_source = key,
                "aes_key_generation_source" => self.aes_key_generation_source = key,
                &_ => ()
            }
        }
        Ok(())
    }
    pub fn generate_aes_kek(&self, wrapped_kek: &KeySource, master_key_rev: u32, packed_options: u32) {
        
    }
}
