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

    // get a context to the TPM we are handling
    let tpm = ctx.get_tpm();
    // set the TPM owner auth
    tpm.set_secret(Secret::Key(b"owner-auth"))?;

    // load the NVRAM area we are interested in
    let nv_data = NvRamArea::get(&ctx, 0x00100001)?;

    // delete the NVRAM area
    nv_data.release()
}
