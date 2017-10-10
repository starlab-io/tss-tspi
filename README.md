[![Build status](https://gitlab.com/starlab-io/tss-tspi/badges/master/pipeline.svg)](https://gitlab.com/starlab-io/tss-tspi/commits/master)
[![Rust version]( https://img.shields.io/badge/rust-1.15+-blue.svg)]()
[![Documentation](https://docs.rs/tss-tspi/badge.svg)](https://docs.rs/tss-tspi)
[![Latest version](https://img.shields.io/crates/v/tss-tspi.svg)](https://crates.io/crates/tss-tspi)
[![All downloads](https://img.shields.io/crates/d/tss-tspi.svg)](https://crates.io/crates/tss-tspi)
[![Downloads of latest version](https://img.shields.io/crates/dv/tss-tspi.svg)](https://crates.io/crates/tss-tspi)

TPM 1.2 TSS (TPM Software Stack) TSPI Rust Wrapper

## Build

To compile this library you must have libtspi installed from [TrouSerS](http://trousers.sourceforge.net/).
This is available in most distros as libtspi-dev (Debian style name) or trousers-devel (Red Hat style name).

If you have it installed in a non-standard path you can export the following environment variable:

* `TSPI_LIBS_PATH` to where `libtspi.so` lives
