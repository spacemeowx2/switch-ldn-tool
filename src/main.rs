extern crate clap;
extern crate hex;
extern crate rustls;

mod keys;

use clap::{Arg, App, ArgMatches};
use keys::Keys;
fn main() -> std::io::Result<()> {
    let matches = get_matches();
    let verbose = matches.is_present("verbose");
    let keyset = matches.value_of("keyset").unwrap_or_default();
    let mut keys = Keys::new();
    
    println!("Loading keyset from {}...", keyset);
    keys.read_from_file(keyset)?;

    if verbose {
        println!("{:?}", keys);
    }

    Ok(())
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
            .help("Bytes to skip in INPUT file")
        )
        .arg(Arg::with_name("verbose")
            .short("v")
            .help("Show verbose"))
        .get_matches()
}
