extern crate clap;
extern crate hex;
extern crate byteorder;
extern crate aes;
extern crate aes_ctr;
extern crate sha2;

mod keys;
mod ldn_frame;

use clap::{Arg, App, ArgMatches};
use keys::Keys;
use std::fs::File;


use ldn_frame::LdnFrame;

fn main() -> std::io::Result<()> {
    let matches = get_matches();
    let verbose = matches.is_present("verbose");
    let encrypt_mode = matches.is_present("encrypt");
    let keyset = matches.value_of("keyset").unwrap_or_default();
    let mut keys = Keys::new();
    
    println!("Loading keyset from {}...", keyset);
    keys.read_from_file(keyset)?;

    if verbose {
        println!("{:x?}", &keys);
    }

    let mut frame = LdnFrame::new(keys);

    let input = matches.value_of("INPUT").expect("failed to get filename");
    let output = matches.value_of("OUTPUT").expect("failed to get filename");

    let offset_str = matches.value_of("offset").unwrap_or_default();
    let offset = offset_str.parse::<u64>().expect("offset must be a number");

    let mut input_file = File::open(input)?;
    let mut output_file = File::create(output)?;

    frame.verbose = verbose;
    frame.offset = offset;

    if encrypt_mode {
        Ok(())
    } else {
        frame.decrypt(&mut input_file, &mut output_file)
    }
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
            .help("Bytes to skip in INPUT file"))
        .arg(Arg::with_name("encrypt")
            .short("e")
            .long("encrypt")
            .help("Encrypt from input to output"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .help("Show verbose"))
        .get_matches()
}
