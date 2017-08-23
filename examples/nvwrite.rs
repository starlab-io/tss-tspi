#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_tspi;

use tss_tspi::*;

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    // create a TSPI context and connect to trousers
    let ctx = Context::new()?.connect(Connect::Localhost)?;

    // load the NVRAM area and set the NVRAM area secret
    let nv_data = NvRamArea::get(&ctx, 0x00100001)?.secret(Secret::Key(b"owner-auth"))?;

    // write 0xFF to the first 128 bytes
    nv_data.write(0, &[0xff; 128])?;

    Ok(())
}
