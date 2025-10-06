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
    pub fn get_fd(&self) -> i32 {
        unsafe { bindings::DNSServiceRefSockFD(self._ref) }
    }

    pub fn process_result(&self) -> Result<(), MDNSError> {
        let error = unsafe { bindings::DNSServiceProcessResult(self._ref) };
        if error == bindings::kDNSServiceErr_NoError {
            Ok(())
        } else {
            Err(MDNSError::from(error))
        }
    }
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

impl MDNSClient {
    // DNSServiceErrorType DNSServiceEnumerateDomains(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceDomainEnumReply callBack, void *context);
    pub fn enumerate_domains(
        flags: Flags,
        interface_index: u32,
        callback: bindings::DNSServiceDomainEnumReply,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();

        let error = unsafe {
            bindings::DNSServiceEnumerateDomains(
                &mut service_ref,
                flags.bits(),
                interface_index,
                callback,
                context,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient { _ref: service_ref })
    }

    // DNSServiceErrorType DNSServiceRegister(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *name, const char *regtype, const char *domain, const char *host, uint16_t port, uint16_t txtLen, const void *txtRecord, DNSServiceRegisterReply callBack, void *context);
    pub fn register(
        flags: Flags,
        interface_index: u32,
        name: Option<&str>,
        regtype: &str,
        domain: Option<&str>,
        host: Option<&str>,
        port: u16, /* In network byte order */
        txt_len: u16,
        txt_record: *mut c_void, /* may be NULL */
        callback: Option<bindings::DNSServiceRegisterReply>,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();

        let name_c = name.map_or(ptr::null(), |n| CString::new(n).unwrap().into_raw());
        let regtype_c = CString::new(regtype).unwrap().into_raw();
        let domain_c = domain.map_or(ptr::null(), |d| CString::new(d).unwrap().into_raw());
        let host_c = host.map_or(ptr::null(), |h| CString::new(h).unwrap().into_raw());

        let error = unsafe {
            bindings::DNSServiceRegister(
                &mut service_ref,
                flags.bits(),
                interface_index,
                name_c,
                regtype_c,
                domain_c,
                host_c,
                port,
                txt_len,
                txt_record,
                callback,
                context,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient { _ref: service_ref })
    }

    // DNSServiceErrorType DNSServiceAddRecord(DNSServiceRef sdRef, DNSRecordRef *RecordRef, DNSServiceFlags flags, uint16_t rrtype, uint16_t rdlen, const void *rdata, uint32_t ttl);
    pub fn add_record(
        &self,
        record_ref: *mut bindings::DNSRecordRef,
        flags: Flags,
        rrtype: RecordType,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> Result<(), MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceUpdateRecord(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags, uint16_t rdlen, const void *rdata, uint32_t ttl);
    fn update_record(
        &self,
        record_ref: bindings::DNSRecordRef, /* may be NULL */
        flags: Flags,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> Result<(), MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceRemoveRecord(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags);
    fn remove_record(
        &self,
        record_ref: bindings::DNSRecordRef,
        flags: Flags,
    ) -> Result<(), MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceBrowse(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *regtype, const char *domain, DNSServiceBrowseReply callBack, void *context);
    pub fn browse(
        flags: Flags,
        interface_index: u32,
        regtype: &str,
        domain: Option<&str>,
        callback: bindings::DNSServiceBrowseReply,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let regtype_c = CString::new(regtype)
            .map_err(|_| MDNSError::BadParam)?
            .into_raw();
        let domain_c = domain.map_or(ptr::null(), |d| CString::new(d).unwrap().into_raw());

        let error = unsafe {
            bindings::DNSServiceBrowse(
                &mut service_ref,
                flags.bits(),
                interface_index,
                regtype_c,
                domain_c,
                callback,
                context,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient { _ref: service_ref })
    }

    // DNSServiceErrorType DNSServiceResolve(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *name, const char *regtype, const char *domain, DNSServiceResolveReply callBack, void *context);
    pub fn resolve(
        flags: Flags,
        interface_index: u32,
        name: &str,
        regtype: &str,
        domain: Option<&str>,
        callback: bindings::DNSServiceResolveReply,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let name_c = CString::new(name)
            .map_err(|_| MDNSError::BadParam)?
            .into_raw();
        let regtype_c = CString::new(regtype)
            .map_err(|_| MDNSError::BadParam)?
            .into_raw();
        let domain_c = domain.map_or(ptr::null(), |d| CString::new(d).unwrap().into_raw());

        let error = unsafe {
            bindings::DNSServiceResolve(
                &mut service_ref,
                flags.bits(),
                interface_index,
                name_c,
                regtype_c,
                domain_c,
                callback,
                context,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient { _ref: service_ref })
    }

    // DNSServiceErrorType DNSServiceQueryRecord(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *fullname, uint16_t rrtype, uint16_t rrclass, DNSServiceQueryRecordReply callBack, void *context);
    pub fn query_record(
        flags: Flags,
        interface_index: u32,
        fullname: &str,
        rrtype: RecordType,
        rrclass: RecordClass,
        _callback: bindings::DNSServiceQueryRecordReply,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let fullname_c = CString::new(fullname)
            .map_err(|_| MDNSError::BadParam)?
            .into_raw();

        let callback = query_callback; // wip: function tranpolin

        let error = unsafe {
            bindings::DNSServiceQueryRecord(
                &mut service_ref,
                flags.bits(),
                interface_index,
                fullname_c,
                rrtype.into(),
                rrclass.into(),
                callback,
                context,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient { _ref: service_ref })
    }

    // DNSServiceErrorType DNSServiceGetAddrInfo(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceProtocol protocol, const char *hostname, DNSServiceGetAddrInfoReply callBack, void *context);
    fn get_addr_info(
        flags: Flags,
        interface_index: u32,
        protocol: Protocol,
        hostname: &str,
        callback: bindings::DNSServiceGetAddrInfoReply,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceCreateConnection(DNSServiceRef *sdRef);
    fn create_connection() -> Result<MDNSClient, MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceRegisterRecord(DNSServiceRef sdRef, DNSRecordRef *RecordRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, DNSServiceRegisterRecordReply callBack, void *context);
    fn register_record(
        &self,
        record_ref: *mut bindings::DNSRecordRef,
        flags: Flags,
        interface_index: u32,
        fullname: &str,
        rrtype: RecordType,
        rrclass: RecordClass,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        callback: Option<bindings::DNSServiceRegisterRecordReply>,
        context: *mut c_void, /* may be NULL */
    ) -> Result<(), MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceReconfirmRecord(DNSServiceFlags flags, uint32_t interfaceIndex, const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata);
    fn reconfirm_record(
        flags: Flags,
        interface_index: u32,
        fullname: &str,
        rrtype: RecordType,
        rrclass: RecordClass,
        rdlen: u16,
        rdata: *const c_void,
    ) -> Result<(), MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceNATPortMappingCreate(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceProtocol protocol, uint16_t internalPort, uint16_t externalPort, uint32_t ttl, DNSServiceNATPortMappingReply callBack, void *context);
    fn nat_port_mapping_create(
        flags: Flags,
        interface_index: u32,
        protocol: Protocol, /* TCP and/or UDP */
        internal_port: u16, /* network byte order */
        external_port: u16, /* network byte order */
        ttl: u32,           /* time to live in seconds */
        callback: bindings::DNSServiceNATPortMappingReply,
        context: *mut c_void, /* may be NULL */
    ) -> Result<MDNSClient, MDNSError> {
        unimplemented!()
    }

    // DNSServiceErrorType DNSServiceConstructFullName(char *const fullName, const char *const service, const char *const regtype, const char *const domain);
    fn construct_full_name(
        service: &str,
        regtype: &str,
        domain: &str,
    ) -> Result<String, MDNSError> {
        unimplemented!()
    }

    // void TXTRecordCreate(TXTRecordRef *txtRecord, uint16_t bufferLen, void *buffer);
    // void TXTRecordDeallocate(TXTRecordRef *txtRecord);
    // const void *TXTRecordGetBytesPtr(const TXTRecordRef *txtRecord);
    // int TXTRecordContainsKey(uint16_t txtLen, const void *txtRecord, const char *key);
    // const void *TXTRecordGetValuePtr(uint16_t txtLen, const void *txtRecord, const char *key, uint8_t *valueLen);
}

pub extern "C" fn query_callback(
    _service_ref: bindings::DNSServiceRef,
    flags: bindings::DNSServiceFlags,
    interface_index: u32,
    error_code: bindings::DNSServiceErrorType,
    fullname: *const c_char,
    rrtype: bindings::DNSServiceRecordType,
    rrclass: bindings::DNSServiceClass,
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
