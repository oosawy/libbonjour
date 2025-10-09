#![allow(unused_variables)]

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
pub extern "system" fn domain_enum_reply(
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
pub extern "system" fn register_reply(
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
pub extern "system" fn browse_reply(
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
pub extern "system" fn resolve_reply(
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
pub extern "system" fn query_record_reply(
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
pub extern "system" fn get_addr_info_reply(
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
pub extern "system" fn register_record_reply(
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
pub extern "system" fn nat_port_mapping_reply(
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
