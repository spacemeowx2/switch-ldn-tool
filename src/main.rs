extern crate clap;
extern crate hex;
extern crate byteorder;
extern crate aes;
extern crate aes_ctr;
extern crate sha2;

mod keys;
mod header;

use clap::{Arg, App, ArgMatches};
use keys::{Keys, aes_128_ctr_dec, decode_hex_aeskey};
use header::transform_header;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use sha2::{Sha256, Digest};

// const HARDCODED_SOURCE: [u8; 16] =  [0x19, 0x18, 0x84, 0x74, 0x3e, 0x24, 0xc7, 0x7d, 0x87, 0xc6, 0x9e, 0x42, 0x7, 0xd0, 0xc4, 0x38];
const HARDCODED_SOURCE: [u8; 16] = [0xf1, 0xe7, 0x1, 0x84, 0x19, 0xa8, 0x4f, 0x71, 0x1d, 0xa7, 0x14, 0xc2, 0xcf, 0x91, 0x9c, 0x9c];

fn main() -> std::io::Result<()> {
    let matches = get_matches();
    let verbose = matches.is_present("verbose");
    let keyset = matches.value_of("keyset").unwrap_or_default();
    let mut keys = Keys::new();
    
    println!("Loading keyset from {}...", keyset);
    keys.read_from_file(keyset)?;

    if verbose {
        println!("{:x?}", &keys);
    }

    let input = matches.value_of("INPUT").expect("failed to get filename");
    let output = matches.value_of("OUTPUT").expect("failed to get filename");
    let offset_str = matches.value_of("offset").unwrap_or_default();
    let offset = offset_str.parse::<u64>().expect("offset must be a number");

    let mut file = File::open(input)?;
    if verbose {
        println!("seeking to offset: {:?}", offset);
    }
    file.seek(SeekFrom::Start(offset))?;

    let mut header_bytes = [0u8; 32];
    let mut header2_bytes = [0u8; 4];
    let mut nonce_bytes = [0u8; 4];
    let mut nonce = [0u8; 16];
    let mut data = [0u8; 1312];
    file.read(&mut header_bytes)?;
    file.read(&mut header2_bytes)?;
    file.read(&mut nonce_bytes)?;
    file.read(&mut data)?;

    nonce[0..4].copy_from_slice(&nonce_bytes);
    if verbose {
        println!("nonce: {:x?}", &nonce);
    }

    let transformed_header = transform_header(&header_bytes);
    if verbose {
        println!("header: {:x?}", &header_bytes);
        println!("transformed_header: {:x?}", &transformed_header);
    }
    let hash = s32_16(&sha256(&transformed_header));
    if verbose {
        println!("hash: {:x?}", &hash);
    }

    let kek = keys.generate_aes_kek(&HARDCODED_SOURCE);
    let key = keys.generate_aes_key(&kek, &hash);

    if verbose {
        println!("kek: {:x?}", &kek);
        println!("key: {:x?}", &key);
    }

    aes_128_ctr_dec(&mut data, &key, &nonce);
    let mut output_file = File::create(output)?;
    output_file.write(&data)?;

    Ok(())
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

fn get_matches<'a>() -> ArgMatches<'a> {
    App::new("switch-ldn-tool")
        .version("0.1.0")
        .author("spacemeowx2")
        .help("Decrypt ldn beacon action frame")
        .arg(Arg::with_name("keyset")
            .short("k")
            .long("keyset")
            .value_name("KEY")
            .default_value("prod.keys")
            .help("Load keys from an external file"))
        .arg(Arg::with_name("INPUT")
            .help("Beacon Action frame")
            .required(true))
        .arg(Arg::with_name("OUTPUT")
            .help("Decrypted file")
            .required(true))
        .arg(Arg::with_name("offset")
            .short("o")
            .long("offset")
            .value_name("OFFSET")
            .default_value("0")
            .help("Bytes to skip in INPUT file")
        )
        .arg(Arg::with_name("verbose")
            .short("v")
            .help("Show verbose"))
        .get_matches()
}
