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

    // load the NVRAM index we are interested in
    let nv_data = NvRamArea::define(&ctx,
                                    0x00100001,
                                    128,
                                    tss_tspi::TPM_NV_PER_OWNERREAD |
                                    tss_tspi::TPM_NV_PER_OWNERWRITE,
                                    tss_tspi::PCR_LOCALITY_ALL,
                                    tss_tspi::PCR_LOCALITY_ALL)?;

    println!("{:?}", nv_data);

    Ok(())
}
