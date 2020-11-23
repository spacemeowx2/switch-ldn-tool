use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::path::Path;
use aes_ctr::Aes128Ctr;
use aes_ctr::stream_cipher::{
    NewStreamCipher, SyncStreamCipher
};
use aes::Aes128;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::generic_array::typenum::U16;
use aes::block_cipher_trait::BlockCipher;

pub const AES_128_KEY_SIZE: usize = 16;
pub type AesKey = [u8; AES_128_KEY_SIZE];
pub type KeySource = [u8; AES_128_KEY_SIZE];
const SEAL_KEY_SOURCE: AesKey = [0xF4, 0x0C, 0x16, 0x26, 0x0D, 0x46, 0x3B, 0xE0, 0x8C, 0x6A, 0x56, 0xE5, 0x82, 0xD4, 0x1B, 0xF6];
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

pub fn decode_hex_key(key: &str) -> Vec<u8> {
    hex::decode(key.trim()).expect("Decoding failed")
}

pub fn decode_hex_aeskey(key: &str) -> AesKey {
    let mut out = [0u8; 16];
    let bin = hex::decode(key.trim()).expect("Decoding failed");
    out.copy_from_slice(&bin.as_slice()[0..16]);
    out
}

pub fn aes_128_ctr_dec(data: &mut [u8], key: &AesKey, nonce: &AesKey) {
    let mut cipher = Aes128Ctr::new(&GenericArray::from_slice(key), &GenericArray::from_slice(nonce));
    cipher.apply_keystream(data);
}

fn decrypt_key(key: &AesKey, wrapped_key: &AesKey) -> AesKey {
    let cipher = Aes128::new(&GenericArray::from_slice(key));
    let dec_key = wrapped_key.clone();
    let mut temp: GenericArray<u8, U16> = dec_key.into();
    cipher.decrypt_block(&mut temp);
    let mut out = [0u8; 16];
    out.copy_from_slice(temp.as_slice());
    out
}

fn encrypt_key(key: &AesKey, shit: &AesKey) -> AesKey {
    let cipher = Aes128::new(&GenericArray::from_slice(key));
    let dec_key = shit.clone();
    let mut temp: GenericArray<u8, U16> = dec_key.into();
    cipher.encrypt_block(&mut temp);
    let mut out = [0u8; 16];
    out.copy_from_slice(temp.as_slice());
    out
}

fn seal_key(key: &AesKey) -> AesKey {
    encrypt_key(&SEAL_KEY_SOURCE, key)
}

fn unseal_key(key: &AesKey) -> AesKey {
    decrypt_key(&SEAL_KEY_SOURCE, key)
}

impl Keys {
    const DERIVE_WITH: [u8; 16] = [0xDA, 0xD8, 0xFC, 0x8E, 0x2D, 0x04, 0xAD, 0x06, 0x72, 0xAF, 0x4B, 0x5B, 0x48, 0x53, 0x25, 0xA1];
    pub fn new() -> Keys {
        Keys {
            aes_kek_generation_source: vec![],
            aes_key_generation_source: vec![],
            master_key: vec![],
        }
    }
    pub fn read_from_file(&mut self, filename: &Path) -> std::io::Result<()> {
        macro_rules! check_len {
            ( $field:ident ) => {
                if self.$field.len() != 16 {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{} length is not 16", stringify!($field))));
                }
            };
        }
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
        check_len!(aes_kek_generation_source);
        check_len!(aes_key_generation_source);
        check_len!(master_key);
        Ok(())
    }
    pub fn generate_aes_kek(&self, wrapped_kek: &KeySource) -> AesKey {
        let master_key = &vec2key(&self.master_key);
        let aes_kek_generation_source = &vec2key(&self.aes_kek_generation_source);
        let temp_key = decrypt_key(master_key, aes_kek_generation_source);
        let kek = decrypt_key(&temp_key, wrapped_kek);
        seal_key(&kek)
    }
    pub fn generate_aes_key(&self, access_key: &AesKey, key_source: &AesKey) -> AesKey {
        let kek = unseal_key(&access_key);
        let src_kek = decrypt_key(&kek, &vec2key(&self.aes_key_generation_source));
        decrypt_key(&src_kek, key_source)
    }
    pub fn derive_key(&self, xor: &AesKey, key_source: &AesKey) -> AesKey {
        let mut t = Self::DERIVE_WITH.clone();
        for (i, x) in t.iter_mut().zip(xor.iter()) {
            *i ^= x;
        }
        let kek = self.generate_aes_kek(&t);
        let key = self.generate_aes_key(&kek, key_source);
        key
    }
}

#[test]
fn test_seal_key() {
    let key = [0; 16];
    let result = unseal_key(&seal_key(&key));
    assert_eq!(key, result)
}

#[test]
fn test_generate_keys() {
    let mut keys = Keys::new();
    keys.read_from_file(Path::new("prod.keys")).expect("prod.keys");

    let kek = keys.generate_aes_kek(&[0xf1, 0xe7, 0x1, 0x84, 0x19, 0xa8, 0x4f, 0x71, 0x1d, 0xa7, 0x14, 0xc2, 0xcf, 0x91, 0x9c, 0x9c]);
    let key = keys.generate_aes_key(&kek, &[0x4e, 0x34, 0x7a, 0xd5, 0x18, 0x4a, 0xc8, 0x31, 0x68, 0x2d, 0x56, 0xc3, 0x92, 0x34, 0x5f, 0xdd]);
    assert_eq!(key, [0x52, 0xd6, 0x6a, 0x54, 0x94, 0xf7, 0x5, 0x16, 0xa4, 0x19, 0x49, 0x88, 0x4d, 0xa9, 0xd1, 0x33])
}
