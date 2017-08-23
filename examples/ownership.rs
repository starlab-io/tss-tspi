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

    // check if the TPM is already owned
    if tpm.is_owned()? {
        println!("TPM is already owned");
        return Ok(());
    } else {
        println!("TPM is unowned");
    }

    // set the TPM owner auth
    tpm.set_secret(Secret::Key(b"owner-auth"))?;

    // create SRK reference and set the secret to unlock it
    let srk = tss_tspi::Srk::get(&ctx)?.secret(Secret::WellKnown)?;

    tpm.take_ownership(srk)
}
