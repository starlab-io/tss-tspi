use std::env;

fn main() {
    // link to system tspi
    println!("cargo:rustc-link-lib=tspi");

    // add to the search path anything set in the TSPI_LIBS_PATH
    if let Ok(path) = env::var("TSPI_LIBS_PATH") {
        println!("cargo:rustc-link-search={}", path);
    }
}
