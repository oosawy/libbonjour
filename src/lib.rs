use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

mod bindings;
mod constants;

pub use constants::*;

pub struct MDNSClient {
    _ref: bindings::DNSServiceRef,
}

impl MDNSClient {
    pub fn process_result(&self) -> Result<(), MDNSError> {
        let error = unsafe { bindings::DNSServiceProcessResult(self._ref) };
        if error == 0 {
            Ok(())
        } else {
            Err(MDNSError::from(error))
        }
    }

    // fn get_fd(&self) -> i32 {
    //     unsafe { bindings::DNSServiceRefSockFD(self._ref) }
    // }
}

impl Drop for MDNSClient {
    fn drop(&mut self) {
        if !self._ref.is_null() {
            unsafe {
                bindings::DNSServiceRefDeallocate(self._ref);
            }
        }
    }
}

extern "C" fn query_callback(
    _service_ref: bindings::DNSServiceRef,
    flags: bindings::DNSServiceFlags,
    interface_index: u32,
    error_code: bindings::DNSServiceErrorType,
    fullname: *const c_char,
    rrtype: u16,
    rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    ttl: u32,
    _context: *mut c_void,
) {
    if error_code != bindings::kDNSServiceErr_NoError {
        let error = MDNSError::from(error_code);
        eprintln!("DNSServiceQueryRecord error: {:?}", error);
        return;
    }

    let fullname = unsafe { CStr::from_ptr(fullname).to_string_lossy().into_owned() };
    let rdata_slice = unsafe { std::slice::from_raw_parts(rdata as *const u8, rdlen as usize) };

    println!("Query callback:");
    println!("  Fullname: {}", fullname);
    println!("  Flags: {}", flags);
    println!("  Interface Index: {}", interface_index);
    println!("  Record Type: {}", rrtype);
    println!("  Record Class: {}", rrclass);
    println!("  TTL: {}", ttl);
    println!("  RData: {:?}", rdata_slice);
}

pub fn query_record(hostname: &str, record_type: RecordType) -> Result<MDNSClient, MDNSError> {
    let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
    let flags = 0;
    let hostname_c = CString::new(hostname).map_err(|_| MDNSError::BadParam)?;

    let error = unsafe {
        bindings::DNSServiceQueryRecord(
            &mut service_ref,
            flags,
            bindings::kDNSServiceInterfaceIndexAny,
            hostname_c.as_ptr(),
            record_type.into(),
            bindings::kDNSServiceClass_IN,
            Some(query_callback),
            ptr::null_mut(),
        )
    };

    if error != 0 {
        return Err(MDNSError::from(error));
    }

    Ok(MDNSClient { _ref: service_ref })
}
