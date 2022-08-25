mod keys;
mod ldn_frame;

use std::fs::File;
use std::path::PathBuf;
use structopt::StructOpt;

use keys::Keys;
use ldn_frame::LdnFrameBuilder;

#[derive(Debug, StructOpt)]
#[structopt(name = "switch-ldn-tool", about = "Decrypt ldn beacon action frame.")]
struct Opt {
    /// Load keys from an external file
    #[structopt(short, long, parse(from_os_str), default_value = "prod.keys")]
    keyset: PathBuf,

    /// Beacon Action frame
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    /// Decrypted file
    #[structopt(parse(from_os_str))]
    output: PathBuf,

    /// Bytes to skip in INPUT file. Should be the offset of 00:22:aa + 8
    #[structopt(short, long, default_value = "0")]
    offset: u64,

    /// Add length of 0x00 to the end of file
    #[structopt(short, long, default_value = "0")]
    padding: usize,

    /// Override SHA256
    #[structopt(short, long)]
    build: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::from_args();
    // let build_mode = matches.is_present("build");
    // let keyset = matches.value_of("keyset").unwrap_or_default();
    let mut keys = Keys::new();

    log::info!("Loading keyset from {:?}...", opt.keyset);
    keys.read_from_file(&opt.keyset)?;

    log::debug!("{:x?}", &keys);

    let mut frame = LdnFrameBuilder::new(keys);

    let mut input_file = File::open(opt.input)?;
    let mut output_file = File::create(opt.output)?;

    frame.offset = opt.offset;
    frame.padding = opt.padding;

    if opt.build {
        frame.encrypt(&mut input_file, &mut output_file)?;
    } else {
        frame.decrypt(&mut input_file, &mut output_file)?;
    }
    Ok(())
}
