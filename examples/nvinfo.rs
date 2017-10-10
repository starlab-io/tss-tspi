#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_tspi;

use tss_tspi::*;

quick_main!(run);

fn show_nv_area(nv: &NvRamArea) {
    println!("NVRAM index   : 0x{:X} ({})", nv.index, nv.index);
    println!("PCR read selection : {:?}", nv.pcr_read.pcr_selection);
    println!(" Localities   : {:?}", nv.pcr_read.locality);
    println!("PCR write selection : {:?}", nv.pcr_write.pcr_selection);
    println!(" Localities   : {:?}", nv.pcr_write.locality);
    println!("Permissions   : 0x{:X} ({:?})", nv.perms, nv.perms);
    println!("ReadSTClear   : {}", nv.read_st_clear);
    println!("WriteSTClear  : {}", nv.write_st_clear);
    println!("WriteDefine   : {}", nv.write_define);
    println!("Size          : {} (0x{:X})", nv.size, nv.size);
}

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    // create a TSPI context and connect to trousers
    let ctx = Context::new()?.connect(Connect::Localhost)?;

    // get a context to the TPM we are handling
    let tpm = ctx.get_tpm();
    // set the TPM owner auth
    tpm.set_secret(Secret::Key(b"owner-auth"))?;

    // load the NVRAM index we are interested in
    let nv_data = NvRamArea::get(&ctx, 0x00100001)?;

    show_nv_area(&nv_data);

    Ok(())
}
