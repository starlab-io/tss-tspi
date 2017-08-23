pub mod tpm {
    error_chain! {
        errors {
            AuditFail {
                description("audit failure")
                display("audit failure")
            }
            AuthConflict {
                description("NVRAM index requires both owner and blob authorization")
                display("NVRAM index requires both owner and blob authorization")
            }
            AuthFail {
                description("authentication failure")
                display("authentication failure")
            }
            BadIndex {
                description("invalid NVRAM index")
                display("invalid NVRAM index")
            }
            BadOrdinal {
                description("ordinal was inconsistent/unknown")
                display("ordinal was inconsistent/unknown")
            }
            BadParam {
                description("bad parameter")
                display("bad parameter")
            }
            ClearDisabled {
                description("clear has been disabled")
                display("clear has been disabled")
            }
            Deactivated {
                description("TPM is deactivated")
                display("TPM is deactivated")
            }
            Disabled {
                description("TPM is disabled")
                display("TPM is disabled")
            }
            DisabledCmd {
                description("TPM command has been disabled")
                display("TPM command has been disabled")
            }
            Fail {
                description("operation failed")
                display("operation failed")
            }
            NoSpace {
                description("no space to load key")
                display("no space to load key")
            }
            NoSrk {
                description("no SRK")
                display("no SRK")
            }
            OwnerSet {
                description("owner already set")
                display("owner already set")
            }
            PermissionNoWrite {
                description("no protection on the write to the NV area")
                display("no protection on the write to the NV area")
            }
            PermissionReadOnly {
                description("read only NV area")
                display("read only NV area")
            }
            Size {
                description("TPM out of space")
                display("TPM out of space")
            }
            NoEndorsement {
                description("no EK")
                display("no EK")
            }
            NotWrapped(e: u32) {
                description("an unwrapped TPM error")
                display("an unwrapped TPM error: 0x{:08X}", e)
            }
        }
    }
}

pub mod tsp {
    error_chain! {
        errors {
            BadParam {
                description("bad parameter")
                display("bad parameter")
            }
            CommFailure {
                description("unable to communicate to the TPM stack")
                display("unable to communicate to the TPM stack")
            }
            InvalidAttributeFlag {
                description("attribute flag in function is inconsistent")
                display("attribute flag in function is inconsistent")
            }
            InvalidAttributeSubFlag {
                description("attribute sub-flag in function is inconsistent")
                display("attribute sub-flag in function is inconsistent")
            }
            InvalidHandle {
                description("invalid object handle")
                display("invalid object handle")
            }
            NotWrapped(e: u32) {
                description("an unwrapped TSP error")
                display("an unwrapped TSP error: 0x{:08X}", e)
            }
            NvAreaExists {
                description("NVRAM area already exists")
                display("NVRAM area already exists")
            }
            NvAreaNotExists {
                description("NVRAM area does not exists")
                display("NVRAM area does not exists")
            }
            PolicyNoSecret {
                description("No secret available for the current policy")
                display("No secret available for the current policy")
            }
        }
    }
}

error_chain! {
    foreign_links {
        Io(::std::io::Error);
    }
    links {
        Tpm(tpm::Error, tpm::ErrorKind);
        Tsp(tsp::Error, tsp::ErrorKind);
    }
    errors {
        BadSize(e: String) {
            description("invalid size provided")
            display("invalid size provided: {}", e)
        }
        Decode(e: String) {
            description("unable to decode")
            display("unable to decode: {}", e)
        }
        Tcs(e: u32) {
            description("unknown TCS error")
            display("unknown TCS error: 0x{:08X}", e)
        }
        Tddl(e: u32) {
            description("unknown TDDL error")
            display("unknown TDDL error: 0x{:08X}", e)
        }
        Unknown(e: u32) {
            description("unknown error")
            display("unknown error: 0x{:08X}", e)
        }
    }
}
