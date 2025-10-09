use std::ffi::{c_uchar, CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

mod bindings;
pub mod constants;
mod context;

pub use constants::*;
use context::*;

pub struct MDNSClient {
    _ref: bindings::DNSServiceRef,
    _ctx: Option<OwnedCtx>,
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
            unsafe { bindings::DNSServiceRefDeallocate(self._ref) };
        }
        drop(self._ctx.take());
    }
}

pub struct Record<'a> {
    #[allow(dead_code)]
    client: &'a MDNSClient,
    _ref: bindings::DNSRecordRef,
    _ctx: Option<OwnedCtx>,
}

impl<'a> Record<'a> {
    // fn _remove(self, flags: Flags) -> Result<(), MDNSError> {
    //     let err =
    //         unsafe { bindings::DNSServiceRemoveRecord(self.client._ref, self._ref, flags.bits()) };

    //     if err != bindings::kDNSServiceErr_NoError {
    //         return Err(MDNSError::from(err));
    //     }

    //     Ok(())
    // }
}

impl<'a> Drop for Record<'a> {
    fn drop(&mut self) {
        drop(self._ctx.take());
    }
}

impl MDNSClient {
    // DNSServiceErrorType DNSServiceEnumerateDomains(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceDomainEnumReply callBack, void *context);
    pub fn enumerate_domains(
        flags: Flags,
        interface_index: u32,
        callback: impl Fn(Flags, u32, MDNSError, String) + Send + 'static,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let ctx = OwnedCtx::new(trampolines::DomainEnumContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceEnumerateDomains(
                &mut service_ref,
                flags.bits(),
                interface_index,
                trampolines::domain_enum_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceRegister(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *name, const char *regtype, const char *domain, const char *host, uint16_t port, uint16_t txtLen, const void *txtRecord, DNSServiceRegisterReply callBack, void *context);
    pub fn register(
        flags: Flags,
        interface_index: u32,
        name: Option<&str>,
        regtype: &str,
        domain: Option<&str>,
        host: Option<&str>,
        port: u16,
        txt_len: u16,
        txt_record: *const c_void, /* may be NULL */
        callback: Option<impl Fn(Flags, MDNSError, String, String, String) + Send + 'static>,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();

        let name = name.map(|s| CString::new(s).expect("invalid NUL in name string"));
        let regtype = CString::new(regtype).expect("invalid NUL in regtype string");
        let domain = domain.map(|s| CString::new(s).expect("invalid NUL in domain string"));
        let host = host.map(|s| CString::new(s).expect("invalid NUL in host string"));
        let port = port.to_be();

        let (callback_ptr, ctx_opt): (*mut c_void, Option<OwnedCtx>) = match callback {
            Some(cb) => {
                let ctx = OwnedCtx::new(trampolines::RegisterContext {
                    callback: Box::new(cb),
                });
                (ctx.as_ptr(), Some(ctx))
            }
            None => (ptr::null_mut(), None),
        };

        let error = unsafe {
            bindings::DNSServiceRegister(
                &mut service_ref,
                flags.bits(),
                interface_index,
                name.map_or(ptr::null(), |s| s.as_ptr()),
                regtype.as_ptr(),
                domain.map_or(ptr::null(), |d| d.as_ptr()),
                host.map_or(ptr::null(), |h| h.as_ptr()),
                port, /* In network byte order */
                txt_len,
                txt_record,
                if callback_ptr.is_null() {
                    None
                } else {
                    Some(trampolines::register_reply)
                },
                callback_ptr,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: ctx_opt,
        })
    }

    // DNSServiceErrorType DNSServiceAddRecord(DNSServiceRef sdRef, DNSRecordRef *RecordRef, DNSServiceFlags flags, uint16_t rrtype, uint16_t rdlen, const void *rdata, uint32_t ttl);
    pub fn add_record(
        &self,
        flags: Flags,
        rrtype: RecordType,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> Result<Record<'_>, MDNSError> {
        let mut record_ref: bindings::DNSRecordRef = ptr::null_mut();

        let error = unsafe {
            bindings::DNSServiceAddRecord(
                self._ref,
                &mut record_ref,
                flags.bits(),
                rrtype.into(),
                rdlen,
                rdata,
                ttl,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(Record {
            client: self,
            _ref: record_ref,
            _ctx: None,
        })
    }

    // DNSServiceErrorType DNSServiceUpdateRecord(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags, uint16_t rdlen, const void *rdata, uint32_t ttl);
    pub fn update_record(
        &self,
        record_ref: bindings::DNSRecordRef, /* may be NULL */
        flags: Flags,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> Result<(), MDNSError> {
        let error = unsafe {
            bindings::DNSServiceUpdateRecord(self._ref, record_ref, flags.bits(), rdlen, rdata, ttl)
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(())
    }

    // DNSServiceErrorType DNSServiceRemoveRecord(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags);
    pub fn remove_record(
        &self,
        record_ref: bindings::DNSRecordRef,
        flags: Flags,
    ) -> Result<(), MDNSError> {
        let error =
            unsafe { bindings::DNSServiceRemoveRecord(self._ref, record_ref, flags.bits()) };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(())
    }

    // DNSServiceErrorType DNSServiceBrowse(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *regtype, const char *domain, DNSServiceBrowseReply callBack, void *context);
    pub fn browse(
        flags: Flags,
        interface_index: u32,
        regtype: &str,
        domain: Option<&str>,
        callback: impl Fn(Flags, u32, MDNSError, String, String, String) + Send + 'static,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let regtype = CString::new(regtype).expect("invalid NUL in regtype string");
        let domain = domain.map(|s| CString::new(s).expect("invalid NUL in domain string"));
        let ctx = OwnedCtx::new(trampolines::BrowseContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceBrowse(
                &mut service_ref,
                flags.bits(),
                interface_index,
                regtype.as_ptr(),
                domain.map_or(ptr::null(), |d| d.as_ptr()),
                trampolines::browse_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceResolve(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *name, const char *regtype, const char *domain, DNSServiceResolveReply callBack, void *context);
    pub fn resolve(
        flags: Flags,
        interface_index: u32,
        name: &str,
        regtype: &str,
        domain: Option<&str>,
        callback: impl Fn(Flags, u32, MDNSError, String, String, u16, u16, *const c_uchar)
            + Send
            + 'static,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let name = CString::new(name).expect("invalid NUL in name string");
        let regtype = CString::new(regtype).expect("invalid NUL in regtype string");
        let domain = domain.map(|s| CString::new(s).expect("invalid NUL in domain string"));
        let ctx = OwnedCtx::new(trampolines::ResolveContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceResolve(
                &mut service_ref,
                flags.bits(),
                interface_index,
                name.as_ptr(),
                regtype.as_ptr(),
                domain.map_or(ptr::null(), |d| d.as_ptr()),
                trampolines::resolve_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceQueryRecord(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *fullname, uint16_t rrtype, uint16_t rrclass, DNSServiceQueryRecordReply callBack, void *context);
    pub fn query_record(
        flags: Flags,
        interface_index: u32,
        fullname: &str,
        rrtype: RecordType,
        rrclass: RecordClass,
        callback: impl Fn(Flags, u32, MDNSError, String, u16, u16, u16, *const c_void, u32)
            + Send
            + 'static,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();
        let fullname = CString::new(fullname).expect("invalid NUL in fullname string");
        let ctx = OwnedCtx::new(trampolines::QueryRecordContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceQueryRecord(
                &mut service_ref,
                flags.bits(),
                interface_index,
                fullname.as_ptr(),
                rrtype.into(),
                rrclass.into(),
                trampolines::query_record_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceGetAddrInfo(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceProtocol protocol, const char *hostname, DNSServiceGetAddrInfoReply callBack, void *context);
    pub fn get_addr_info(
        flags: Flags,
        interface_index: u32,
        protocol: Protocol,
        hostname: &str,
        callback: impl Fn(Flags, u32, MDNSError, String, *const c_void, u32) + Send + 'static,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();

        let hostname = CString::new(hostname).expect("invalid NUL in hostname string");
        let ctx = OwnedCtx::new(trampolines::GetAddrInfoContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceGetAddrInfo(
                &mut service_ref,
                flags.bits(),
                interface_index,
                protocol.into(),
                hostname.as_ptr(),
                trampolines::get_addr_info_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceCreateConnection(DNSServiceRef *sdRef);
    pub fn create_connection() -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();

        let error = unsafe { bindings::DNSServiceCreateConnection(&mut service_ref) };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: None,
        })
    }

    // DNSServiceErrorType DNSServiceRegisterRecord(DNSServiceRef sdRef, DNSRecordRef *RecordRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, DNSServiceRegisterRecordReply callBack, void *context);
    pub fn register_record(
        &self,
        flags: Flags,
        interface_index: u32,
        fullname: &str,
        rrtype: RecordType,
        rrclass: RecordClass,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        callback: impl Fn(Flags, MDNSError) + Send + 'static,
    ) -> Result<Record<'_>, MDNSError> {
        let mut record_ref: bindings::DNSRecordRef = ptr::null_mut();

        let fullname = CString::new(fullname).expect("invalid NUL in fullname string");
        let ctx = OwnedCtx::new(trampolines::RegisterRecordContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceRegisterRecord(
                self._ref,
                &mut record_ref,
                flags.bits(),
                interface_index,
                fullname.as_ptr(),
                rrtype.into(),
                rrclass.into(),
                rdlen,
                rdata,
                ttl,
                trampolines::register_record_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(Record {
            client: self,
            _ref: record_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceReconfirmRecord(DNSServiceFlags flags, uint32_t interfaceIndex, const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata);
    pub fn reconfirm_record(
        flags: Flags,
        interface_index: u32,
        fullname: &str,
        rrtype: RecordType,
        rrclass: RecordClass,
        rdlen: u16,
        rdata: *const c_void,
    ) -> Result<(), MDNSError> {
        let fullname = CString::new(fullname).expect("invalid NUL in fullname string");

        let error = unsafe {
            bindings::DNSServiceReconfirmRecord(
                flags.bits(),
                interface_index,
                fullname.as_ptr(),
                rrtype.into(),
                rrclass.into(),
                rdlen,
                rdata,
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(())
    }

    // DNSServiceErrorType DNSServiceNATPortMappingCreate(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceProtocol protocol, uint16_t internalPort, uint16_t externalPort, uint32_t ttl, DNSServiceNATPortMappingReply callBack, void *context);
    pub fn nat_port_mapping_create(
        flags: Flags,
        interface_index: u32,
        protocol: Protocol, /* TCP and/or UDP */
        internal_port: u16,
        external_port: u16,
        ttl: u32, /* time to live in seconds */
        callback: impl Fn(Flags, u32, MDNSError, std::net::Ipv4Addr, Protocol, u16, u16, u32)
            + Send
            + 'static,
    ) -> Result<Self, MDNSError> {
        let mut service_ref: bindings::DNSServiceRef = ptr::null_mut();

        let internal_port = internal_port.to_be();
        let external_port = external_port.to_be();
        let ctx = OwnedCtx::new(trampolines::NATPortMappingContext {
            callback: Box::new(callback),
        });

        let error = unsafe {
            bindings::DNSServiceNATPortMappingCreate(
                &mut service_ref,
                flags.bits(),
                interface_index,
                protocol.into(),
                internal_port, /* network byte order */
                external_port, /* network byte order */
                ttl,
                trampolines::nat_port_mapping_reply,
                ctx.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        Ok(MDNSClient {
            _ref: service_ref,
            _ctx: Some(ctx),
        })
    }

    // DNSServiceErrorType DNSServiceConstructFullName(char *const fullName, const char *const service, const char *const regtype, const char *const domain);
    pub fn construct_full_name(
        service: &str,
        regtype: &str,
        domain: &str,
    ) -> Result<String, MDNSError> {
        let mut full_name = vec![0i8 /* c_char */; bindings::kDNSServiceMaxDomainName as usize];
        let service = CString::new(service).expect("invalid NUL in service string");
        let regtype = CString::new(regtype).expect("invalid NUL in regtype string");
        let domain = CString::new(domain).expect("invalid NUL in domain string");

        let error = unsafe {
            bindings::DNSServiceConstructFullName(
                full_name.as_mut_ptr(),
                service.as_ptr(),
                regtype.as_ptr(),
                domain.as_ptr(),
            )
        };

        if error != bindings::kDNSServiceErr_NoError {
            return Err(MDNSError::from(error));
        }

        let c_str = unsafe { CStr::from_ptr(full_name.as_ptr() as *const c_char) };
        let rust_str = c_str.to_str().unwrap().to_owned();
        Ok(rust_str)
    }
}

pub struct TextRecord {
    _ref: bindings::TXTRecordRef,
}

impl Drop for TextRecord {
    fn drop(&mut self) {
        self.deallocate();
    }
}

impl TextRecord {
    // void TXTRecordCreate(TXTRecordRef *txtRecord, uint16_t bufferLen, void *buffer);
    pub fn create(buffer_len: u16, buffer: *mut c_void) -> Self {
        let mut txt_record: bindings::TXTRecordRef = unsafe { std::mem::zeroed() };

        unsafe {
            bindings::TXTRecordCreate(&mut txt_record, buffer_len, buffer);
        }

        TextRecord { _ref: txt_record }
    }

    // void TXTRecordDeallocate(TXTRecordRef *txtRecord);
    fn deallocate(&mut self) {
        unsafe {
            bindings::TXTRecordDeallocate(&mut self._ref);
        }
    }

    // const void *TXTRecordGetBytesPtr(const TXTRecordRef *txtRecord);
    pub fn get_bytes_ptr(&self) -> *const c_void {
        unsafe { bindings::TXTRecordGetBytesPtr(&self._ref) }
    }

    // int TXTRecordContainsKey(uint16_t txtLen, const void *txtRecord, const char *key);
    pub fn contains_key(&self, txt_len: u16, txt_record: *const c_void, key: &str) -> bool {
        let key = CString::new(key).unwrap();

        let result = unsafe { bindings::TXTRecordContainsKey(txt_len, txt_record, key.as_ptr()) };

        result != 0
    }

    // const void *TXTRecordGetValuePtr(uint16_t txtLen, const void *txtRecord, const char *key, uint8_t *valueLen);
    pub fn get_value_ptr(
        txt_len: u16,
        txt_record: *const c_void,
        key: &str,
    ) -> Option<(*const c_void, u8)> {
        let mut value_len: u8 = 0;

        let key = CString::new(key).unwrap();

        let value_ptr = unsafe {
            bindings::TXTRecordGetValuePtr(txt_len, txt_record, key.as_ptr(), &mut value_len)
        };

        if value_ptr.is_null() {
            None
        } else {
            Some((value_ptr, value_len))
        }
    }
}

// Trampolines for C function pointers
#[allow(unused_variables)]
mod trampolines {
    use super::*;

    // DomainEnum
    type DomainEnumCallback = dyn Fn(
            Flags,     /* flags */
            u32,       /* interfaceIndex */
            MDNSError, /* error */
            String,    /* replyDomain */
        ) + Send;
    pub struct DomainEnumContext {
        pub callback: Box<DomainEnumCallback>,
    }
    impl Context for DomainEnumContext {}

    // Register
    type RegisterCallback = dyn Fn(
            Flags,     /* flags */
            MDNSError, /* error */
            String,    /* name */
            String,    /* regtype */
            String,    /* domain */
        ) + Send;
    pub struct RegisterContext {
        pub callback: Box<RegisterCallback>,
    }
    impl Context for RegisterContext {}

    // Browse
    type BrowseCallback = dyn Fn(
            Flags,     /* flags */
            u32,       /* interfaceIndex */
            MDNSError, /* error */
            String,    /* serviceName */
            String,    /* regtype */
            String,    /* replyDomain */
        ) + Send;
    pub struct BrowseContext {
        pub callback: Box<BrowseCallback>,
    }
    impl Context for BrowseContext {}

    // Resolve
    type ResolveCallback = dyn Fn(
            Flags,          /* flags */
            u32,            /* interfaceIndex */
            MDNSError,      /* error */
            String,         /* fullname */
            String,         /* hosttarget */
            u16,            /* port */
            u16,            /* txtLen */
            *const c_uchar, /* txtRecord */
        ) + Send;
    pub struct ResolveContext {
        pub callback: Box<ResolveCallback>,
    }
    impl Context for ResolveContext {}

    // QueryRecord
    type QueryRecordCallback = dyn Fn(
            Flags,         /* flags */
            u32,           /* interfaceIndex */
            MDNSError,     /* error */
            String,        /* fullname */
            u16,           /* rrtype */
            u16,           /* rrclass */
            u16,           /* rdlen */
            *const c_void, /* rdata */
            u32,           /* ttl */
        ) + Send;
    pub struct QueryRecordContext {
        pub callback: Box<QueryRecordCallback>,
    }
    impl Context for QueryRecordContext {}

    // GetAddrInfo
    type GetAddrInfoCallback = dyn Fn(
            Flags,         /* flags */
            u32,           /* interfaceIndex */
            MDNSError,     /* error */
            String,        /* hostname */
            *const c_void, /* address (sockaddr) */
            u32,           /* ttl */
        ) + Send;
    pub struct GetAddrInfoContext {
        pub callback: Box<GetAddrInfoCallback>,
    }
    impl Context for GetAddrInfoContext {}

    // RegisterRecord
    type RegisterRecordCallback = dyn Fn(Flags /* flags */, MDNSError /* error */) + Send;
    pub struct RegisterRecordContext {
        pub callback: Box<RegisterRecordCallback>,
    }
    impl Context for RegisterRecordContext {}

    // NATPortMapping
    type NATPortMappingCallback = dyn Fn(
            Flags,              /* flags */
            u32,                /* interfaceIndex */
            MDNSError,          /* error */
            std::net::Ipv4Addr, /* externalAddress */
            Protocol,           /* protocol */
            u16,                /* internalPort */
            u16,                /* externalPort */
            u32,                /* ttl */
        ) + Send;
    pub struct NATPortMappingContext {
        pub callback: Box<NATPortMappingCallback>,
    }
    impl Context for NATPortMappingContext {}

    unsafe fn lossy_string_from_ptr(ptr: *const c_char) -> String {
        assert!(!ptr.is_null());
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }

    // DNSServiceDomainEnumReply
    pub extern "C" fn domain_enum_reply(
        sd_ref: bindings::DNSServiceRef,
        flags: bindings::DNSServiceFlags,
        interface_index: u32,
        error_code: bindings::DNSServiceErrorType,
        reply_domain: *const c_char,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut DomainEnumContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let reply_domain = unsafe { lossy_string_from_ptr(reply_domain) };

        callback(flags, interface_index, error, reply_domain);
    }

    // DNSServiceRegisterReply
    pub extern "C" fn register_reply(
        sd_ref: bindings::DNSServiceRef,
        flags: bindings::DNSServiceFlags,
        error_code: bindings::DNSServiceErrorType,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut RegisterContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let name = unsafe { lossy_string_from_ptr(name) };
        let regtype = unsafe { lossy_string_from_ptr(regtype) };
        let domain = unsafe { lossy_string_from_ptr(domain) };

        callback(flags, error, name, regtype, domain);
    }

    // DNSServiceBrowseReply
    pub extern "C" fn browse_reply(
        sd_ref: bindings::DNSServiceRef,
        flags: bindings::DNSServiceFlags,
        interface_index: u32,
        error_code: bindings::DNSServiceErrorType,
        service_name: *const c_char,
        regtype: *const c_char,
        reply_domain: *const c_char,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut BrowseContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let service_name = unsafe { lossy_string_from_ptr(service_name) };
        let regtype = unsafe { lossy_string_from_ptr(regtype) };
        let reply_domain = unsafe { lossy_string_from_ptr(reply_domain) };

        callback(
            flags,
            interface_index,
            error,
            service_name,
            regtype,
            reply_domain,
        );
    }

    // DNSServiceResolveReply
    pub extern "C" fn resolve_reply(
        sd_ref: bindings::DNSServiceRef,
        flags: bindings::DNSServiceFlags,
        interface_index: u32,
        error_code: bindings::DNSServiceErrorType,
        fullname: *const c_char,
        hosttarget: *const c_char,
        port: u16, /* In network byte order */
        txt_len: u16,
        txt_record: *const c_uchar,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut ResolveContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let fullname = unsafe { lossy_string_from_ptr(fullname) };
        let hosttarget = unsafe { lossy_string_from_ptr(hosttarget) };
        let port = u16::from_be(port);

        callback(
            flags,
            interface_index,
            error,
            fullname,
            hosttarget,
            port,
            txt_len,
            txt_record,
        );
    }

    // DNSServiceQueryRecordReply
    pub extern "C" fn query_record_reply(
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
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut QueryRecordContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let fullname = unsafe { lossy_string_from_ptr(fullname) };
        let rrtype = rrtype as u16;
        let rrclass = rrclass as u16;

        callback(
            flags,
            interface_index,
            error,
            fullname,
            rrtype,
            rrclass,
            rdlen,
            rdata,
            ttl,
        );
    }

    // DNSServiceGetAddrInfoReply
    pub extern "C" fn get_addr_info_reply(
        sd_ref: bindings::DNSServiceRef,
        flags: bindings::DNSServiceFlags,
        interface_index: u32,
        error_code: bindings::DNSServiceErrorType,
        hostname: *const c_char,
        address: *const c_void, // sockaddr is platform-dependent; keep opaque pointer
        ttl: u32,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut GetAddrInfoContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let hostname = unsafe { lossy_string_from_ptr(hostname) };

        callback(flags, interface_index, error, hostname, address, ttl);
    }

    // DNSServiceRegisterRecordReply
    pub extern "C" fn register_record_reply(
        sd_ref: bindings::DNSServiceRef,
        record_ref: bindings::DNSRecordRef,
        flags: bindings::DNSServiceFlags,
        error_code: bindings::DNSServiceErrorType,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut RegisterRecordContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);

        callback(flags, error);
    }

    // DNSServiceNATPortMappingReply
    pub extern "C" fn nat_port_mapping_reply(
        sd_ref: bindings::DNSServiceRef,
        flags: bindings::DNSServiceFlags,
        interface_index: u32,
        error_code: bindings::DNSServiceErrorType,
        external_address: u32, /* four byte IPv4 address in network byte order */
        protocol: bindings::DNSServiceProtocol,
        internal_port: u16, /* In network byte order */
        external_port: u16, /* In network byte order */
        ttl: u32,
        context: *mut c_void,
    ) {
        let callback = unsafe {
            assert!(!context.is_null());
            &*(context as *mut NATPortMappingContext)
        }
        .callback
        .as_ref();

        let flags = Flags::from_bits_truncate(flags);
        let error = MDNSError::from(error_code);
        let protocol = protocol.into();
        let external_address = std::net::Ipv4Addr::from(u32::from_be(external_address));
        let internal_port = u16::from_be(internal_port);
        let external_port = u16::from_be(external_port);

        callback(
            flags,
            interface_index,
            error,
            external_address,
            protocol,
            internal_port,
            external_port,
            ttl,
        );
    }
}
