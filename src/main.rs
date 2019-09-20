extern crate clap;
extern crate hex;
extern crate byteorder;
extern crate aes;
extern crate sha2;

mod keys;
mod header;

use clap::{Arg, App, ArgMatches};
use keys::Keys;
use header::transform_header;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use sha2::{Sha256, Digest};

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
    let offset_str = matches.value_of("offset").unwrap_or_default();
    let offset = offset_str.parse::<u64>().expect("offset must be a number");

    let mut file = File::open(input)?;
    if verbose {
        println!("seeking to offset: {:?}", offset);
    }
    file.seek(SeekFrom::Start(offset))?;

    let mut header_bytes = [0; 32];
    file.read(&mut header_bytes)?;
    let transformed_header = transform_header(&header_bytes);
    if verbose {
        println!("header: {:x?}", &header_bytes);
        println!("transformed_header: {:x?}", &transformed_header);
    }
    let hash = sha256(&transformed_header);
    if verbose {
        println!("hash: {:x?}", &hash);
    }

    Ok(())
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
