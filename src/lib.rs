#![recursion_limit = "1024"]

#[macro_use]
extern crate bitflags;
extern crate byteorder;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

mod errors;

#[allow(non_snake_case, non_camel_case_types, dead_code)]
#[allow(non_upper_case_globals)]
mod sys {
    include!("bindings.rs");

    // from trousers_types.h
    pub const NULL_HOBJECT: TSS_HOBJECT = 0;
    pub const NULL_HCONTEXT: TSS_HCONTEXT = 0;
    pub const NULL_HPCRS: TSS_HPCRS = 0;
    pub const NULL_HKEY: TSS_HKEY = 0;
    pub const NULL_HTPM: TSS_HTPM = 0;
    pub const NULL_HPOLICY: TSS_HPOLICY = 0;

    // from tss/tss_error.h
    pub const TSS_SUCCESS: TSS_RESULT = 0;

    // from trousers_types.h
    pub const TSS_ERROR_LAYER: u32 = 0x3000;

    // helper to avoid 0 as TSS_FLAG everywhere
    pub const NO_FLAG: TSS_FLAG = 0;

    // no defines for these in the headers they instead are defined in comments
    pub const TSS_TPM_PCR_DEFAULT: TSS_FLAG = 0x0;
    pub const TSS_TPM_PCR_INFO: TSS_FLAG = 0x1;
    pub const TSS_TPM_PCR_INFO_LONG: TSS_FLAG = 0x2;
    pub const TSS_TPM_PCR_INFO_SHORT: TSS_FLAG = 0x3;

    // this never got pulled in
    pub const TSS_WELL_KNOWN_SECRET: &'static [u8] = &[0; 20];

    // from tss/tpm.h
    pub const TPM_TAG_NV_ATTRIBUTES: TPM_STRUCTURE_TAG = 0x0017;
    pub const TPM_TAG_NV_DATA_PUBLIC: TPM_STRUCTURE_TAG = 0x0018;
}

use byteorder::{BigEndian, ReadBytesExt};
pub use errors::{Error, ErrorKind, Result};
pub use errors::tpm::ErrorKind as TpmErrorKind;
use std::io::{Cursor, Read};
use std::ptr;

macro_rules! tss_tpm_err(
    ($kind:path) => ( Err(ErrorKind::Tpm($kind).into()) )
);

macro_rules! tss_tsp_err(
    ($kind:path) => ( Err(ErrorKind::Tsp($kind).into()) )
);

fn tss_err(err: sys::TSS_RESULT) -> Result<()> {
    // match against the error returned
    match err {
        // do nothing for success
        sys::TSS_SUCCESS => Ok(()),
        // any error in the valid error range needs to be taken apart by layer
        val => {
            match val & sys::TSS_ERROR_LAYER {
                sys::TSS_LAYER_TPM => {
                    match val & sys::TSS_MAX_ERROR {
                        0x01 => tss_tpm_err!(errors::tpm::ErrorKind::AuthFail),
                        0x02 => tss_tpm_err!(errors::tpm::ErrorKind::BadIndex),
                        0x03 => tss_tpm_err!(errors::tpm::ErrorKind::BadParam),
                        0x04 => tss_tpm_err!(errors::tpm::ErrorKind::AuditFail),
                        0x05 => tss_tpm_err!(errors::tpm::ErrorKind::ClearDisabled),
                        0x06 => tss_tpm_err!(errors::tpm::ErrorKind::Deactivated),
                        0x07 => tss_tpm_err!(errors::tpm::ErrorKind::Disabled),
                        0x08 => tss_tpm_err!(errors::tpm::ErrorKind::DisabledCmd),
                        0x09 => tss_tpm_err!(errors::tpm::ErrorKind::Fail),
                        0x0A => tss_tpm_err!(errors::tpm::ErrorKind::BadOrdinal),
                        0x11 => tss_tpm_err!(errors::tpm::ErrorKind::NoSpace),
                        0x12 => tss_tpm_err!(errors::tpm::ErrorKind::NoSrk),
                        0x14 => tss_tpm_err!(errors::tpm::ErrorKind::OwnerSet),
                        0x17 => tss_tpm_err!(errors::tpm::ErrorKind::Size),
                        0x23 => tss_tpm_err!(errors::tpm::ErrorKind::NoEndorsement),
                        0x3b => tss_tpm_err!(errors::tpm::ErrorKind::AuthConflict),
                        0x3e => tss_tpm_err!(errors::tpm::ErrorKind::PermissionReadOnly),
                        0x3f => tss_tpm_err!(errors::tpm::ErrorKind::PermissionNoWrite),
                        err => Err(ErrorKind::Tpm(errors::tpm::ErrorKind::NotWrapped(err)).into()),
                    }
                }
                sys::TSS_LAYER_TDDL => Err(ErrorKind::Tddl(err).into()),
                sys::TSS_LAYER_TCS => Err(ErrorKind::Tcs(err).into()),
                sys::TSS_LAYER_TSP => {
                    match val & sys::TSS_MAX_ERROR {
                        0x003 => tss_tsp_err!(errors::tsp::ErrorKind::BadParam),
                        0x011 => tss_tsp_err!(errors::tsp::ErrorKind::CommFailure),
                        0x109 => tss_tsp_err!(errors::tsp::ErrorKind::InvalidAttributeFlag),
                        0x10A => tss_tsp_err!(errors::tsp::ErrorKind::InvalidAttributeSubFlag),
                        0x116 => tss_tsp_err!(errors::tsp::ErrorKind::PolicyNoSecret),
                        0x126 => tss_tsp_err!(errors::tsp::ErrorKind::InvalidHandle),
                        0x13B => tss_tsp_err!(errors::tsp::ErrorKind::NvAreaExists),
                        0x13C => tss_tsp_err!(errors::tsp::ErrorKind::NvAreaNotExists),
                        err => Err(ErrorKind::Tsp(errors::tsp::ErrorKind::NotWrapped(err)).into()),
                    }
                }
                _ => Err(ErrorKind::Unknown(err).into()),
            }
        }
    }
}

#[derive(Debug)]
pub struct Context {
    inner: sys::TSS_HCONTEXT,
}

impl Drop for Context {
    fn drop(&mut self) {
        trace!("Tspi_Context_FreeMemory({})", self.inner);
        unsafe {
            sys::Tspi_Context_FreeMemory(self.inner, ptr::null_mut());
        }
        trace!("Tspi_Context_Close({})", self.inner);
        unsafe {
            sys::Tspi_Context_Close(self.inner);
        }
    }
}

impl Context {
    pub fn new() -> Result<Self> {
        let mut ctx = sys::NULL_HCONTEXT;

        // create our context
        tss_err(unsafe { sys::Tspi_Context_Create(&mut ctx) })?;
        trace!("Tspi_Context_Create() = {}", ctx);
        Ok(Context { inner: ctx })
    }

    pub fn connect(self, dest: Connect) -> Result<ConnectedContext> {

        // connect to trousers (in theory)
        let result = match dest {
            Connect::Host(host) => {
                let mut dest = host.encode_utf16().collect::<Vec<u16>>();
                // null terminate
                dest.push(0 as u16);
                unsafe { sys::Tspi_Context_Connect(self.inner, dest.as_mut_ptr()) }
            }
            Connect::Localhost => unsafe { sys::Tspi_Context_Connect(self.inner, ptr::null_mut()) },
        };

        trace!("Tspi_Context_Connect({}, ...) = {:?}", self.inner, result);

        tss_err(result)?;

        let mut tpm = sys::NULL_HOBJECT;

        tss_err(unsafe { sys::Tspi_Context_GetTpmObject(self.inner, &mut tpm) })?;
        trace!("Tspi_Context_GetTpmObject({}) = TPMObject({})",
               self.inner,
               tpm);
        let obj = Tpm { inner: tpm };

        Ok(ConnectedContext {
               inner: self,
               tpm: obj,
           })
    }
}

pub enum Connect<'a> {
    Localhost,
    Host(&'a str),
}

#[derive(Debug)]
pub struct ConnectedContext {
    inner: Context,
    tpm: Tpm,
}

impl ConnectedContext {
    pub fn get_tpm(&self) -> &Tpm {
        &self.tpm
    }
}

bitflags! {
    pub struct PcrLocality: sys::TPM_LOCALITY_SELECTION {
        const PCR_LOCALITY_0 = 0b00001;
        const PCR_LOCALITY_1 = 0b00010;
        const PCR_LOCALITY_2 = 0b00100;
        const PCR_LOCALITY_3 = 0b01000;
        const PCR_LOCALITY_4 = 0b10000;
        const PCR_LOCALITY_ALL = PCR_LOCALITY_0.bits
                                | PCR_LOCALITY_1.bits
                                | PCR_LOCALITY_2.bits
                                | PCR_LOCALITY_3.bits
                                | PCR_LOCALITY_4.bits;
    }
}

bitflags! {
    pub struct NvPermissions: sys::TPM_NV_PER_ATTRIBUTES {
        // from tss/tpm.h
        const TPM_NV_PER_READ_STCLEAR = (1 << 31);
        const TPM_NV_PER_AUTHREAD = (1 << 18);
        const TPM_NV_PER_OWNERREAD = (1 << 17);
        const TPM_NV_PER_PPREAD = (1 << 16);
        const TPM_NV_PER_GLOBALLOCK = (1 << 15);
        const TPM_NV_PER_WRITE_STCLEAR = (1 << 14);
        const TPM_NV_PER_WRITEDEFINE = (1 << 13);
        const TPM_NV_PER_WRITEALL = (1 << 12);
        const TPM_NV_PER_AUTHWRITE = (1 << 2);
        const TPM_NV_PER_OWNERWRITE = (1 << 1);
        const TPM_NV_PER_PPWRITE = (1 << 0);
    }
}

#[derive(Clone, Debug)]
pub struct PcrInfoShort {
    pub locality: PcrLocality,
    pub pcr_selection: Vec<u8>,
    digest: Vec<u8>,
}

/// reads the byte stream from the TPM that contains details about this NVRAM area
/// corresponds to the C function getNVDataPublic()
fn read_nv_data_public<R: Read>(mut rdr: R, index: u32, obj: NvRamObj) -> Result<NvRamArea> {
    let tag = rdr.read_u16::<BigEndian>()?;
    let nv_index = rdr.read_u32::<BigEndian>()?;
    let pcr_read = read_pcr_info_short(&mut rdr)?;
    let pcr_write = read_pcr_info_short(&mut rdr)?;
    let attrib_tag = rdr.read_u16::<BigEndian>()?;
    let attrib = NvPermissions::from_bits_truncate(rdr.read_u32::<BigEndian>()?);
    let read_st_clear = rdr.read_u8()?;
    let write_st_clear = rdr.read_u8()?;
    let write_define = rdr.read_u8()?;
    let data_size = rdr.read_u32::<BigEndian>()?;

    ensure!(tag == sys::TPM_TAG_NV_DATA_PUBLIC,
            ErrorKind::Decode(format!("Did not receive NV_DATA_PUBLIC tag: {:X}", tag)));

    ensure!(attrib_tag == sys::TPM_TAG_NV_ATTRIBUTES,
            ErrorKind::Decode(format!("Did not receive NV_ATTRIBUTES tag: {:X}", attrib_tag)));

    ensure!(nv_index == index,
            ErrorKind::Decode(format!("Got invalid NVRAM index {:X} vs requested {:X}",
                                      nv_index,
                                      index)));

    Ok(NvRamArea {
           obj: obj,
           policy: None,
           index: nv_index,
           pcr_read: pcr_read,
           pcr_write: pcr_write,
           perms: attrib,
           read_st_clear: (read_st_clear > 0),
           write_st_clear: (write_st_clear > 0),
           write_define: (write_define > 0),
           size: data_size,
       })
}

#[derive(Debug)]
pub struct NvRamArea<'ctx> {
    obj: NvRamObj<'ctx>,
    policy: Option<PolicyUsage<'ctx>>,
    pub index: u32,
    pub pcr_read: PcrInfoShort,
    pub pcr_write: PcrInfoShort,
    pub perms: NvPermissions,
    pub read_st_clear: bool,
    pub write_st_clear: bool,
    pub write_define: bool,
    pub size: u32,
}

impl<'ctx> NvRamArea<'ctx> {
    /// create an NVRAM area
    pub fn define(ctx: &'ctx ConnectedContext,
                  index: u32,
                  size: u32,
                  perms: NvPermissions,
                  read: PcrLocality,
                  write: PcrLocality)
                  -> Result<NvRamArea<'ctx>> {
        // get a reference to the TPM
        let tpm = ctx.get_tpm();

        let nv_obj = NvRamObj::get(ctx, index)?
            .attr(sys::TSS_TSPATTRIB_NV_DATASIZE, sys::NO_FLAG, size)?
            .attr(sys::TSS_TSPATTRIB_NV_PERMISSIONS,
                  sys::NO_FLAG,
                  perms.bits as u32)?;

        let read_pcr = PcrComposite::new(ctx)?.locality(read)?;
        let write_pcr = PcrComposite::new(ctx)?.locality(write)?;

        trace!("Tspi_NV_DefineSpace({}, {:?}, {:?}) for 0x{:08X} of size {}",
               nv_obj.inner,
               read,
               write,
               index,
               size);
        tss_err(unsafe {
                    sys::Tspi_NV_DefineSpace(nv_obj.inner, read_pcr.inner, write_pcr.inner)
                })?;

        read_nv_data_public(tpm.get_nv_data(index)?, index, nv_obj)
    }

    /// get a reference to a NVRAM area
    pub fn get(ctx: &'ctx ConnectedContext, index: u32) -> Result<NvRamArea<'ctx>> {
        // get a reference to the TPM
        let tpm = ctx.get_tpm();

        let nv_obj = NvRamObj::get(ctx, index)?;
        read_nv_data_public(tpm.get_nv_data(index)?, index, nv_obj)
    }

    /// assign a secret to a specific NVRAM arex
    pub fn secret(mut self, secret: Secret) -> Result<Self> {
        let policy = PolicyUsage::new(self.obj.ctx)?.secret(secret)?;
        policy.assign(self.obj.inner)?;
        self.policy = Some(policy);
        Ok(self)
    }

    /// write data to a specific NVRAM area
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<()> {
        ensure!((offset + data.len()) as u32 <= self.size,
                ErrorKind::BadSize(format!("offset {} + write size {} greater than NVRAM area size {}",
                                           offset,
                                           data.len(),
                                           self.size)));

        // due to a bug with some hardware not supporting 1024 byte writes we'll just do
        // a 512 byte write to be safe
        let chunk_size = 512;
        let mut pos = offset;
        for chunk in data.chunks(chunk_size) {
            self.obj.write_chunk(pos as u32, chunk)?;
            pos += chunk_size;
        }

        Ok(())
    }

    /// delete the NVRAM area
    pub fn release(self) -> Result<()> {
        let index = self.index;
        let ret = self.obj.release();

        if let Err(ref e) = ret {
            debug!("Failed to delete NVRAM area 0x{:08}: {}", index, e);
        }
        ret
    }
}

/// copies a pointer we got back from C code and converts it to a Cursor of bytes
fn ptr_to_owned_cursor(buf: *mut sys::BYTE, len: usize) -> Cursor<Vec<u8>> {
    let mut dst = Vec::with_capacity(len);

    unsafe {
        dst.set_len(len);
        ptr::copy(buf, dst.as_mut_ptr(), len);
    };

    Cursor::new(dst)
}

/// reads sys::TPM_PCR_INFO_SHORT and returns PcrInfoShort
fn read_pcr_info_short<T: Read>(rdr: &mut T) -> Result<PcrInfoShort> {

    let pcr_select_size = rdr.read_u16::<BigEndian>()?;
    let mut pcr_select = vec![0; pcr_select_size as usize];
    rdr.read_exact(&mut pcr_select)?;
    let locality = rdr.read_u8()?;
    let mut digest = vec![0; sys::TPM_SHA1_160_HASH_LEN as usize];
    rdr.read_exact(&mut digest)?;

    Ok(PcrInfoShort {
           locality: PcrLocality::from_bits_truncate(locality),
           pcr_selection: pcr_select,
           digest: digest,
       })

}

#[derive(Clone, Debug)]
enum TpmCap {
    NvIndex(u32),
    Owner,
}

#[derive(Debug)]
pub struct Tpm {
    inner: sys::TSS_HTPM,
}

impl Tpm {
    /// checks if the TPM is owned or not
    pub fn is_owned(&self) -> Result<bool> {
        let mut rdr = self.get_cap(TpmCap::Owner)?;
        match rdr.read_u8()? {
            0 => Ok(false),
            _ => Ok(true),
        }
    }

    /// check if the TPM is enabled or not
    pub fn is_enabled(&self) -> Result<bool> {
        // invert the logic of the flag since we get back true if its disabled
        self.get_status(sys::TSS_TPMSTATUS_DISABLED).map(|v| !v)
    }

    /// check if the TPM is active or not
    pub fn is_active(&self) -> Result<bool> {
        // invert the logic of the flag since we get back true if its disabled
        self.get_status(sys::TSS_TPMSTATUS_DEACTIVATED).map(|v| !v)
    }

    fn get_nv_data(&self, index: u32) -> Result<Cursor<Vec<u8>>> {
        self.get_cap(TpmCap::NvIndex(index))
    }

    fn get_cap(&self, cap: TpmCap) -> Result<Cursor<Vec<u8>>> {
        // size of our subarea (param)
        let idx_len = ::std::mem::size_of::<u32>() as u32;

        // variable kept in scope for the call below
        let mut variable: u32 = sys::TSS_TPMCAP_PROP_OWNER;

        let (tpmcap, param) = match cap {
            TpmCap::NvIndex(index) => {
                variable = index;
                (sys::TSS_TPMCAP_NV_INDEX, &mut variable as *mut u32 as *mut u8)
            }
            TpmCap::Owner => {
                (sys::TSS_TPMCAP_PROPERTY, &mut variable as *mut u32 as *mut u8)
            }
        };

        let mut result_len = 0;
        let mut result: *mut sys::BYTE = ptr::null_mut();

        trace!("Tspi_TPM_GetCapability({}, 0x{:X}, {:?}, ...)",
               self.inner,
               tpmcap,
               cap);
        tss_err(unsafe {
                    sys::Tspi_TPM_GetCapability(self.inner,
                                                tpmcap,
                                                idx_len,
                                                param,
                                                &mut result_len,
                                                &mut result)
                })?;

        Ok(ptr_to_owned_cursor(result, result_len as usize))
    }

    fn get_status(&self, status: sys::TSS_FLAG) -> Result<bool> {
        trace!("Tspi_TPM_GetStatus({}, 0x{:08X}, ...)", self.inner, status);
        let mut data: i8 = 0;

        tss_err(unsafe { sys::Tspi_TPM_GetStatus(self.inner, status, &mut data) })?;

        match data {
            0 => Ok(false),
            _ => Ok(true),
        }
    }

    pub fn set_secret(&self, secret: Secret) -> Result<()> {
        set_secret_helper(self.inner, secret)
    }

    pub fn take_ownership(&self, srk: Srk) -> Result<()> {
        trace!("Tspi_TPM_TakeOwnership({}, {}, NULL)",
               self.inner,
               srk.inner);
        tss_err(unsafe { sys::Tspi_TPM_TakeOwnership(self.inner, srk.inner, sys::NULL_HKEY) })?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Secret<'a> {
    WellKnown,
    Key(&'a [u8]),
}

fn set_secret_helper(obj: sys::TSS_HOBJECT, secret: Secret) -> Result<()> {
    let mut policy = sys::NULL_HPOLICY;

    tss_err(unsafe { sys::Tspi_GetPolicyObject(obj, sys::TSS_POLICY_USAGE, &mut policy) })?;
    trace!("Tspi_GetPolicyObject({}, TSS_POLICY_USAGE) = PolicyObject({})",
           obj,
           policy);

    let (mode, key) = match secret {
        Secret::WellKnown => (sys::TSS_SECRET_MODE_SHA1, sys::TSS_WELL_KNOWN_SECRET),
        Secret::Key(k) => (sys::TSS_SECRET_MODE_PLAIN, k),
    };

    trace!("Tspi_Policy_SetSecret({}, {:?}, ...)", policy, secret);
    tss_err(unsafe { sys::Tspi_Policy_SetSecret(policy, mode, key.len() as u32, key.as_ptr()) })?;
    Ok(())
}

macro_rules! tspi_obj {
    ($(#[$attr:meta])* struct $obj:ident {
        const flag = $flag:expr;
        const sub_flag = $sub_flag:expr;
    }) =>
    (
        $(#[$attr])*
        struct $obj<'ctx> {
            ctx: &'ctx ConnectedContext,
            inner: sys::TSS_HOBJECT,
        }

        __impl_tspi_obj!($obj, $flag, $sub_flag);
    );

    ($(#[$attr:meta])* pub struct $obj:ident {
        const flag = $flag:expr;
        const sub_flag = $sub_flag:expr;
    }) =>
    (
        $(#[$attr])*
        pub struct $obj<'ctx> {
            ctx: &'ctx ConnectedContext,
            inner: sys::TSS_HOBJECT,
        }

        __impl_tspi_obj!($obj, $flag, $sub_flag);
    );
}

macro_rules! __impl_tspi_obj {
    ($obj:ident, $flag:expr, $sub_flag:expr) =>
    (
        impl<'ctx> Drop for $obj<'ctx> {
            fn drop(&mut self) {
                trace!("Tspi_Context_CloseObject({}, {}) Object({}, {})",
                    self.ctx.inner.inner,
                    self.inner,
                    stringify!($flag),
                    stringify!($sub_flag));
                unsafe {
                    sys::Tspi_Context_CloseObject(self.ctx.inner.inner, self.inner);
                }
            }
        }

        impl<'ctx> $obj<'ctx> {
            fn new(ctx: &'ctx ConnectedContext) -> Result<Self> {
                let mut obj = sys::NULL_HOBJECT;

                tss_err(unsafe {
                    sys::Tspi_Context_CreateObject(ctx.inner.inner, $flag, $sub_flag, &mut obj)
                })?;
                trace!("Tspi_Context_CreateObject({}, {}, {}) = Object({})",
                    ctx.inner.inner,
                    stringify!($flag),
                    stringify!($sub_flag),
                    obj);

                Ok($obj {
                    ctx: &ctx,
                    inner: obj,
                })
            }
        }
    );
}

tspi_obj!(
    struct PcrComposite {
        const flag = sys::TSS_OBJECT_TYPE_PCRS;
        const sub_flag = sys::TSS_TPM_PCR_INFO_SHORT;
    });

impl<'ctx> PcrComposite<'ctx> {
    fn locality(self, locality: PcrLocality) -> Result<Self> {
        trace!("Tspi_PcrComposite_SetPcrLocality({}, {:?})",
               self.inner,
               locality);
        tss_err(unsafe {
                    sys::Tspi_PcrComposite_SetPcrLocality(self.inner, locality.bits() as u32)
                })
                .map(|_| self)
    }
}

tspi_obj!(
    pub struct Srk {
        const flag = sys::TSS_OBJECT_TYPE_RSAKEY;
        const sub_flag = sys::TSS_KEY_TSP_SRK + sys::TSS_KEY_AUTHORIZATION;
    });

impl<'ctx> Srk<'ctx> {
    /// get a reference to the Storage Root Key object
    pub fn get(ctx: &'ctx ConnectedContext) -> Result<Self> {
        Srk::new(ctx)
    }

    /// set the necessary secret to utilize the Storage Root Key
    pub fn secret(self, secret: Secret) -> Result<Self> {
        set_secret_helper(self.inner, secret).map(|_| self)
    }
}

tspi_obj!(
    #[derive(Debug)]
    pub struct NvRamObj {
        const flag = sys::TSS_OBJECT_TYPE_NV;
        const sub_flag = sys::NO_FLAG;
    });

impl<'ctx> NvRamObj<'ctx> {
    fn get(ctx: &'ctx ConnectedContext, index: u32) -> Result<NvRamObj<'ctx>> {
        NvRamObj::new(ctx)?.attr(sys::TSS_TSPATTRIB_NV_INDEX, sys::NO_FLAG, index)
    }

    fn attr(self, flag: sys::TSS_FLAG, sub_flag: sys::TSS_FLAG, value: u32) -> Result<Self> {
        trace!("Tspi_SetAttribUint32({}, {:X}, {:X}, 0x{:08X})",
               self.inner,
               flag,
               sub_flag,
               value);
        tss_err(unsafe { sys::Tspi_SetAttribUint32(self.inner, flag, sub_flag, value) })
            .map(|_| self)
    }

    fn write_chunk(&self, offset: u32, data: &[u8]) -> Result<()> {
        trace!("Tspi_NV_WriteValue({}, offset={}, len={}, data=[...])",
               self.inner,
               offset,
               data.len());
        tss_err(unsafe {
                    sys::Tspi_NV_WriteValue(self.inner, offset, data.len() as u32, data.as_ptr())
                })
    }

    fn release(self) -> Result<()> {
        trace!("Tspi_NV_ReleaseSpace({})", self.inner);
        tss_err(unsafe { sys::Tspi_NV_ReleaseSpace(self.inner) })
    }
}

tspi_obj!(
    #[derive(Debug)]
    struct PolicyUsage {
        const flag = sys::TSS_OBJECT_TYPE_POLICY;
        const sub_flag = sys::TSS_POLICY_USAGE;
    });

impl<'ctx> PolicyUsage<'ctx> {
    fn secret(self, secret: Secret) -> Result<Self> {
        let (mode, key) = match secret {
            Secret::WellKnown => (sys::TSS_SECRET_MODE_SHA1, sys::TSS_WELL_KNOWN_SECRET),
            Secret::Key(k) => (sys::TSS_SECRET_MODE_PLAIN, k),
        };
        let mut key = key.to_owned();

        trace!("Tspi_Policy_SetSecret({}, {})",
               self.inner,
               stringify!(mode));
        tss_err(unsafe {
                    sys::Tspi_Policy_SetSecret(self.inner, mode, key.len() as u32, key.as_mut_ptr())
                })
                .map(|_| self)
    }

    fn assign(&self, target: sys::TSS_HOBJECT) -> Result<()> {
        trace!("Tspi_Policy_AssignToObject({}, {})", self.inner, target);
        tss_err(unsafe { sys::Tspi_Policy_AssignToObject(self.inner, target) })
    }
}
