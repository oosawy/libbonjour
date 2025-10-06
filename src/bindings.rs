#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    dead_code
)]

use std::os::raw::{c_char, c_int, c_uchar, c_void};

// Opaque refs
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _DNSServiceRef_t {
    _unused: [u8; 0],
}
pub type DNSServiceRef = *mut _DNSServiceRef_t;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _DNSRecordRef_t {
    _unused: [u8; 0],
}
pub type DNSRecordRef = *mut _DNSRecordRef_t;

// Flags, protocols, error type aliases
pub type DNSServiceFlags = u32;
pub type DNSServiceProtocol = u32;
pub type DNSServiceRecordType = u16;
pub type DNSServiceErrorType = i32;

// Common constants
pub const kDNSServiceMaxServiceName: u32 = 64;
pub const kDNSServiceMaxDomainName: u32 = 1009;
pub const kDNSServiceInterfaceIndexAny: u32 = 0;
pub const kDNSServiceProperty_DaemonVersion: &[u8; 14] = b"DaemonVersion\0";

pub const kDNSServiceFlagsMoreComing: DNSServiceFlags = 1;
pub const kDNSServiceFlagsAdd: DNSServiceFlags = 2;
pub const kDNSServiceFlagsDefault: DNSServiceFlags = 4;
pub const kDNSServiceFlagsNoAutoRename: DNSServiceFlags = 8;
pub const kDNSServiceFlagsShared: DNSServiceFlags = 16;
pub const kDNSServiceFlagsUnique: DNSServiceFlags = 32;
pub const kDNSServiceFlagsBrowseDomains: DNSServiceFlags = 64;
pub const kDNSServiceFlagsRegistrationDomains: DNSServiceFlags = 128;
pub const kDNSServiceFlagsLongLivedQuery: DNSServiceFlags = 256;
pub const kDNSServiceFlagsAllowRemoteQuery: DNSServiceFlags = 512;
pub const kDNSServiceFlagsForceMulticast: DNSServiceFlags = 1024;
pub const kDNSServiceFlagsForce: DNSServiceFlags = 2048;
pub const kDNSServiceFlagsReturnIntermediates: DNSServiceFlags = 4096;
pub const kDNSServiceFlagsNonBrowsable: DNSServiceFlags = 8192;
pub const kDNSServiceFlagsShareConnection: DNSServiceFlags = 16384;
pub const kDNSServiceFlagsSuppressUnusable: DNSServiceFlags = 32768;
pub const kDNSServiceFlagsTimeout: DNSServiceFlags = 65536;
pub const kDNSServiceFlagsIncludeP2P: DNSServiceFlags = 131072;
pub const kDNSServiceFlagsWakeOnResolve: DNSServiceFlags = 262144;

pub const kDNSServiceProtocol_IPv4: DNSServiceProtocol = 1;
pub const kDNSServiceProtocol_IPv6: DNSServiceProtocol = 2;
pub const kDNSServiceProtocol_UDP: DNSServiceProtocol = 16;
pub const kDNSServiceProtocol_TCP: DNSServiceProtocol = 32;

pub const kDNSServiceClass_IN: u16 = 1;

pub const kDNSServiceType_A: u32 = 1;
pub const kDNSServiceType_NS: u32 = 2;
pub const kDNSServiceType_MD: u32 = 3;
pub const kDNSServiceType_MF: u32 = 4;
pub const kDNSServiceType_CNAME: u32 = 5;
pub const kDNSServiceType_SOA: u32 = 6;
pub const kDNSServiceType_MB: u32 = 7;
pub const kDNSServiceType_MG: u32 = 8;
pub const kDNSServiceType_MR: u32 = 9;
pub const kDNSServiceType_NULL: u32 = 10;
pub const kDNSServiceType_WKS: u32 = 11;
pub const kDNSServiceType_PTR: u32 = 12;
pub const kDNSServiceType_HINFO: u32 = 13;
pub const kDNSServiceType_MINFO: u32 = 14;
pub const kDNSServiceType_MX: u32 = 15;
pub const kDNSServiceType_TXT: u32 = 16;
pub const kDNSServiceType_RP: u32 = 17;
pub const kDNSServiceType_AFSDB: u32 = 18;
pub const kDNSServiceType_X25: u32 = 19;
pub const kDNSServiceType_ISDN: u32 = 20;
pub const kDNSServiceType_RT: u32 = 21;
pub const kDNSServiceType_NSAP: u32 = 22;
pub const kDNSServiceType_NSAP_PTR: u32 = 23;
pub const kDNSServiceType_SIG: u32 = 24;
pub const kDNSServiceType_KEY: u32 = 25;
pub const kDNSServiceType_PX: u32 = 26;
pub const kDNSServiceType_GPOS: u32 = 27;
pub const kDNSServiceType_AAAA: u32 = 28;
pub const kDNSServiceType_LOC: u32 = 29;
pub const kDNSServiceType_NXT: u32 = 30;
pub const kDNSServiceType_EID: u32 = 31;
pub const kDNSServiceType_NIMLOC: u32 = 32;
pub const kDNSServiceType_SRV: u32 = 33;
pub const kDNSServiceType_ATMA: u32 = 34;
pub const kDNSServiceType_NAPTR: u32 = 35;
pub const kDNSServiceType_KX: u32 = 36;
pub const kDNSServiceType_CERT: u32 = 37;
pub const kDNSServiceType_A6: u32 = 38;
pub const kDNSServiceType_DNAME: u32 = 39;
pub const kDNSServiceType_SINK: u32 = 40;
pub const kDNSServiceType_OPT: u32 = 41;
pub const kDNSServiceType_APL: u32 = 42;
pub const kDNSServiceType_DS: u32 = 43;
pub const kDNSServiceType_SSHFP: u32 = 44;
pub const kDNSServiceType_IPSECKEY: u32 = 45;
pub const kDNSServiceType_RRSIG: u32 = 46;
pub const kDNSServiceType_NSEC: u32 = 47;
pub const kDNSServiceType_DNSKEY: u32 = 48;
pub const kDNSServiceType_DHCID: u32 = 49;
pub const kDNSServiceType_NSEC3: u32 = 50;
pub const kDNSServiceType_NSEC3PARAM: u32 = 51;
pub const kDNSServiceType_HIP: u32 = 55;
pub const kDNSServiceType_SPF: u32 = 99;
pub const kDNSServiceType_UINFO: u32 = 100;
pub const kDNSServiceType_UID: u32 = 101;
pub const kDNSServiceType_GID: u32 = 102;
pub const kDNSServiceType_UNSPEC: u32 = 103;
pub const kDNSServiceType_TKEY: u32 = 249;
pub const kDNSServiceType_TSIG: u32 = 250;
pub const kDNSServiceType_IXFR: u32 = 251;
pub const kDNSServiceType_AXFR: u32 = 252;
pub const kDNSServiceType_MAILB: u32 = 253;
pub const kDNSServiceType_MAILA: u32 = 254;
pub const kDNSServiceType_ANY: u32 = 255;

pub const kDNSServiceErr_NoError: DNSServiceErrorType = 0;
pub const kDNSServiceErr_Unknown: DNSServiceErrorType = -65537;
pub const kDNSServiceErr_NoSuchName: DNSServiceErrorType = -65538;
pub const kDNSServiceErr_NoMemory: DNSServiceErrorType = -65539;
pub const kDNSServiceErr_BadParam: DNSServiceErrorType = -65540;
pub const kDNSServiceErr_BadReference: DNSServiceErrorType = -65541;
pub const kDNSServiceErr_BadState: DNSServiceErrorType = -65542;
pub const kDNSServiceErr_BadFlags: DNSServiceErrorType = -65543;
pub const kDNSServiceErr_Unsupported: DNSServiceErrorType = -65544;
pub const kDNSServiceErr_NotInitialized: DNSServiceErrorType = -65545;
pub const kDNSServiceErr_AlreadyRegistered: DNSServiceErrorType = -65547;
pub const kDNSServiceErr_NameConflict: DNSServiceErrorType = -65548;
pub const kDNSServiceErr_Invalid: DNSServiceErrorType = -65549;
pub const kDNSServiceErr_Firewall: DNSServiceErrorType = -65550;
pub const kDNSServiceErr_Incompatible: DNSServiceErrorType = -65551;
pub const kDNSServiceErr_BadInterfaceIndex: DNSServiceErrorType = -65552;
pub const kDNSServiceErr_Refused: DNSServiceErrorType = -65553;
pub const kDNSServiceErr_NoSuchRecord: DNSServiceErrorType = -65554;
pub const kDNSServiceErr_NoAuth: DNSServiceErrorType = -65555;
pub const kDNSServiceErr_NoSuchKey: DNSServiceErrorType = -65556;
pub const kDNSServiceErr_NATTraversal: DNSServiceErrorType = -65557;
pub const kDNSServiceErr_DoubleNAT: DNSServiceErrorType = -65558;
pub const kDNSServiceErr_BadTime: DNSServiceErrorType = -65559;
pub const kDNSServiceErr_BadSig: DNSServiceErrorType = -65560;
pub const kDNSServiceErr_BadKey: DNSServiceErrorType = -65561;
pub const kDNSServiceErr_Transient: DNSServiceErrorType = -65562;
pub const kDNSServiceErr_ServiceNotRunning: DNSServiceErrorType = -65563;
pub const kDNSServiceErr_NATPortMappingUnsupported: DNSServiceErrorType = -65564;
pub const kDNSServiceErr_NATPortMappingDisabled: DNSServiceErrorType = -65565;
pub const kDNSServiceErr_NoRouter: DNSServiceErrorType = -65566;
pub const kDNSServiceErr_PollingMode: DNSServiceErrorType = -65567;
pub const kDNSServiceErr_Timeout: DNSServiceErrorType = -65568;

// Callback types
pub type DNSServiceDomainEnumReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        replyDomain: *const c_char,
        context: *mut c_void,
    ),
>;

pub type DNSServiceRegisterReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        errorCode: DNSServiceErrorType,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        context: *mut c_void,
    ),
>;

pub type DNSServiceBrowseReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        serviceName: *const c_char,
        regtype: *const c_char,
        replyDomain: *const c_char,
        context: *mut c_void,
    ),
>;

pub type DNSServiceResolveReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        fullname: *const c_char,
        hosttarget: *const c_char,
        port: u16,
        txtLen: u16,
        txtRecord: *const c_uchar,
        context: *mut c_void,
    ),
>;

pub type DNSServiceQueryRecordReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        context: *mut c_void,
    ),
>;

pub type DNSServiceGetAddrInfoReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        hostname: *const c_char,
        address: *const c_void, // sockaddr is platform-dependent; keep opaque pointer
        ttl: u32,
        context: *mut c_void,
    ),
>;

pub type DNSServiceNATPortMappingReply = Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        externalAddress: u32,
        protocol: DNSServiceProtocol,
        internalPort: u16,
        externalPort: u16,
        ttl: u32,
        context: *mut c_void,
    ),
>;

#[repr(C)]
#[derive(Copy, Clone)]
pub union _TXTRecordRef_t {
    pub PrivateData: [c_char; 16usize],
    pub ForceNaturalAlignment: *mut c_char,
}
type TXTRecordRef = _TXTRecordRef_t;

// FFI function declarations
extern "C" {
    pub fn DNSServiceGetProperty(
        property: *const c_char,
        result: *mut c_void,
        size: *mut u32,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceRefSockFD(sdRef: DNSServiceRef) -> c_int;

    pub fn DNSServiceProcessResult(sdRef: DNSServiceRef) -> DNSServiceErrorType;

    pub fn DNSServiceRefDeallocate(sdRef: DNSServiceRef);

    pub fn DNSServiceEnumerateDomains(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        callBack: DNSServiceDomainEnumReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceRegister(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port: u16,
        txtLen: u16,
        txtRecord: *const c_void,
        callBack: DNSServiceRegisterReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceAddRecord(
        sdRef: DNSServiceRef,
        RecordRef: *mut DNSRecordRef,
        flags: DNSServiceFlags,
        rrtype: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceUpdateRecord(
        sdRef: DNSServiceRef,
        RecordRef: DNSRecordRef,
        flags: DNSServiceFlags,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceRemoveRecord(
        sdRef: DNSServiceRef,
        RecordRef: DNSRecordRef,
        flags: DNSServiceFlags,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceBrowse(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        regtype: *const c_char,
        domain: *const c_char,
        callBack: DNSServiceBrowseReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceResolve(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        callBack: DNSServiceResolveReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceQueryRecord(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        callBack: DNSServiceQueryRecordReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceGetAddrInfo(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        protocol: DNSServiceProtocol,
        hostname: *const c_char,
        callBack: DNSServiceGetAddrInfoReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceCreateConnection(sdRef: *mut DNSServiceRef) -> DNSServiceErrorType;

    pub fn DNSServiceRegisterRecord(
        sdRef: DNSServiceRef,
        RecordRef: *mut DNSRecordRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        callBack: Option<
            unsafe extern "C" fn(
                DNSServiceRef,
                DNSRecordRef,
                DNSServiceFlags,
                DNSServiceErrorType,
                *mut c_void,
            ),
        >,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceReconfirmRecord(
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceNATPortMappingCreate(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        protocol: DNSServiceProtocol,
        internalPort: u16,
        externalPort: u16,
        ttl: u32,
        callBack: DNSServiceNATPortMappingReply,
        context: *mut c_void,
    ) -> DNSServiceErrorType;

    pub fn DNSServiceConstructFullName(
        fullName: *mut c_char,
        service: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
    ) -> DNSServiceErrorType;

    pub fn TXTRecordCreate(txtRecord: *mut TXTRecordRef, bufferLen: u16, buffer: *mut c_void);

    pub fn TXTRecordDeallocate(txtRecord: *mut TXTRecordRef);

    pub fn TXTRecordSetValue(
        txtRecord: *mut TXTRecordRef,
        key: *const c_char,
        valueSize: u8,
        value: *const c_void,
    ) -> DNSServiceErrorType;

    pub fn TXTRecordRemoveValue(
        txtRecord: *mut TXTRecordRef,
        key: *const c_char,
    ) -> DNSServiceErrorType;

    pub fn TXTRecordGetLength(txtRecord: *const TXTRecordRef) -> u16;

    pub fn TXTRecordGetBytesPtr(txtRecord: *const TXTRecordRef) -> *const c_void;

    pub fn TXTRecordContainsKey(txtLen: u16, txtRecord: *const c_void, key: *const c_char)
        -> c_int;

    pub fn TXTRecordGetValuePtr(
        txtLen: u16,
        txtRecord: *const c_void,
        key: *const c_char,
        valueLen: *mut u8,
    ) -> *const c_void;
    pub fn TXTRecordGetCount(txtLen: u16, txtRecord: *const c_void) -> u16;

    pub fn TXTRecordGetItemAtIndex(
        txtLen: u16,
        txtRecord: *const c_void,
        itemIndex: u16,
        keyBufLen: u16,
        key: *mut c_char,
        valueLen: *mut u8,
        value: *mut *const c_void,
    ) -> DNSServiceErrorType;
}
