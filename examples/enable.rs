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

    // check if the TPM is enabled
    if tpm.is_enabled()? {
        println!("TPM is enabled");
    } else {
        println!("TPM is disabled");
    }

    Ok(())
}
