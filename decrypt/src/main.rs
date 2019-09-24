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


use ldn_frame::LdnFrameBuilder;

fn main() -> std::io::Result<()> {
    let matches = get_matches();
    let verbose = matches.is_present("verbose");
    let build_mode = matches.is_present("build");
    let keyset = matches.value_of("keyset").unwrap_or_default();
    let mut keys = Keys::new();
    
    println!("Loading keyset from {}...", keyset);
    keys.read_from_file(keyset)?;

    if verbose {
        println!("{:x?}", &keys);
    }

    let mut frame = LdnFrameBuilder::new(keys);

    let input = matches.value_of("INPUT").expect("failed to get filename");
    let output = matches.value_of("OUTPUT").expect("failed to get filename");

    let offset_str = matches.value_of("offset").unwrap_or_default();
    let offset = offset_str.parse::<u64>().expect("offset must be a number");
    let padding_str = matches.value_of("padding").unwrap_or_default();
    let padding = padding_str.parse::<usize>().expect("padding must be a number");

    let mut input_file = File::open(input)?;
    let mut output_file = File::create(output)?;

    frame.verbose = verbose;
    frame.offset = offset;
    frame.padding = padding;

    if build_mode {
        frame.encrypt(&mut input_file, &mut output_file)
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
        .arg(Arg::with_name("build")
            .short("b")
            .long("build")
            .help("Override SHA256"))
        .arg(Arg::with_name("padding")
            .short("p")
            .long("padding")
            .default_value("0")
            .help("Add length of 0x00 to the end of file"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .help("Show verbose"))
        .get_matches()
}
