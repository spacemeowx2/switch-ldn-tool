use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use aes_ctr::Aes128Ctr;
use aes_ctr::stream_cipher::{
    NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek
};
use aes::Aes128;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::generic_array::typenum::U16;
use aes::block_cipher_trait::BlockCipher;

pub const AES_128_KEY_SIZE: usize = 16;
pub type AesKey = [u8; AES_128_KEY_SIZE];
pub type KeySource = [u8; AES_128_KEY_SIZE];
// pub struct KeySource(pub [u8; AES_128_KEY_SIZE]);

fn vec2key(vec: &Vec<u8>) -> AesKey {
    let mut out: AesKey = [0; AES_128_KEY_SIZE];
    out.copy_from_slice(vec.as_slice());
    out
}

#[derive(Debug)]
pub struct Keys {
    aes_kek_generation_source: Vec<u8>,
    aes_key_generation_source: Vec<u8>,
    master_key: Vec<u8>,
}

fn decode_hex_key(key: &str) -> Vec<u8> {
    hex::decode(key.trim()).expect("Decoding failed")
}

// fn decode_hex_aeskey(key: &str) -> AesKey {
//     let mut out = [0u8; 16];
//     let bin = hex::decode(key.trim()).expect("Decoding failed");
//     out.copy_from_slice(&bin.as_slice()[0..16]);
//     out
// }

pub fn aes_128_ctr_dec(data: &mut [u8], key: &AesKey, nonce: &AesKey) {
    let mut cipher = Aes128Ctr::new(&GenericArray::from_slice(key), &GenericArray::from_slice(nonce));
    cipher.apply_keystream(data);
}

fn decrypt_key(key: &AesKey, wrapped_key: &AesKey) -> AesKey {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key);
    let dec_key = wrapped_key.clone();
    let mut temp: GenericArray<u8, U16> = dec_key.into();
    cipher.decrypt_block(&mut temp);
    let mut out = [0u8; 16];
    out.copy_from_slice(temp.as_slice());
    out
}

impl Keys {
    pub fn new() -> Keys {
        Keys {
            aes_kek_generation_source: vec![],
            aes_key_generation_source: vec![],
            master_key: vec![],
        }
    }
    pub fn read_from_file(&mut self, filename: &str) -> std::io::Result<()> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        while let Some(Ok(line)) = lines.next() {
            let split: Vec<&str> = line.splitn(2, "=").collect();
            if split.len() != 2 {
                continue
            }
            let key = decode_hex_key(split[1]);
            match split[0].trim() {
                "aes_kek_generation_source" => self.aes_kek_generation_source = key,
                "aes_key_generation_source" => self.aes_key_generation_source = key,
                "master_key_00" => self.master_key = key,
                &_ => ()
            }
        }
        Ok(())
    }
    pub fn generate_aes_kek(&self, wrapped_kek: &KeySource) -> AesKey {
        let master_key = &vec2key(&self.master_key);
        let aes_kek_generation_source = &vec2key(&self.aes_kek_generation_source);
        let temp_key = decrypt_key(master_key, aes_kek_generation_source);
        decrypt_key(&temp_key, wrapped_kek)
    }
    pub fn generate_aes_key(&self, access_key: &AesKey, key_source: &AesKey) -> AesKey {
        let temp_key = decrypt_key(&vec2key(&self.aes_key_generation_source), &access_key);
        decrypt_key(&temp_key, key_source)
    }
}
