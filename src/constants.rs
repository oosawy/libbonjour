#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use bitflags::bitflags;

use crate::bindings;

bitflags! {
    pub struct Flags: bindings::DNSServiceFlags {
        const NONE = 0;
        const MoreComing = bindings::kDNSServiceFlagsMoreComing;
        const Add = bindings::kDNSServiceFlagsAdd;
        const Default = bindings::kDNSServiceFlagsDefault;
        const NoAutoRename = bindings::kDNSServiceFlagsNoAutoRename;
        const Shared = bindings::kDNSServiceFlagsShared;
        const Unique = bindings::kDNSServiceFlagsUnique;
        const BrowseDomains = bindings::kDNSServiceFlagsBrowseDomains;
        const RegistrationDomains = bindings::kDNSServiceFlagsRegistrationDomains;
        const LongLivedQuery = bindings::kDNSServiceFlagsLongLivedQuery;
        const AllowRemoteQuery = bindings::kDNSServiceFlagsAllowRemoteQuery;
        const ForceMulticast = bindings::kDNSServiceFlagsForceMulticast;
        const Force = bindings::kDNSServiceFlagsForce;
        const ReturnIntermediates = bindings::kDNSServiceFlagsReturnIntermediates;
        const NonBrowsable = bindings::kDNSServiceFlagsNonBrowsable;
        const ShareConnection = bindings::kDNSServiceFlagsShareConnection;
        const SuppressUnusable = bindings::kDNSServiceFlagsSuppressUnusable;
        const Timeout = bindings::kDNSServiceFlagsTimeout;
        const IncludeP2P = bindings::kDNSServiceFlagsIncludeP2P;
        const WakeOnResolve = bindings::kDNSServiceFlagsWakeOnResolve;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    IPv4,
    IPv6,
    UDP,
    TCP,
    Other(bindings::DNSServiceProtocol),
}

impl From<bindings::DNSServiceProtocol> for Protocol {
    fn from(code: bindings::DNSServiceProtocol) -> Self {
        match code {
            1 => Protocol::IPv4,
            2 => Protocol::IPv6,
            16 => Protocol::UDP,
            32 => Protocol::TCP,
            other => Protocol::Other(other),
        }
    }
}

impl From<Protocol> for bindings::DNSServiceProtocol {
    fn from(proto: Protocol) -> bindings::DNSServiceProtocol {
        match proto {
            Protocol::IPv4 => 1,
            Protocol::IPv6 => 2,
            Protocol::UDP => 16,
            Protocol::TCP => 32,
            Protocol::Other(code) => code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    RP,
    AFSDB,
    X25,
    ISDN,
    RT,
    NSAP,
    NSAP_PTR,
    SIG,
    KEY,
    PX,
    GPOS,
    AAAA,
    LOC,
    NXT,
    EID,
    NIMLOC,
    SRV,
    ATMA,
    NAPTR,
    KX,
    CERT,
    A6,
    DNAME,
    SINK,
    OPT,
    APL,
    DS,
    SSHFP,
    IPSECKEY,
    RRSIG,
    NSEC,
    DNSKEY,
    DHCID,
    NSEC3,
    NSEC3PARAM,
    HIP,
    SPF,
    UINFO,
    UID,
    GID,
    UNSPEC,
    TKEY,
    TSIG,
    IXFR,
    AXFR,
    MAILB,
    MAILA,
    ANY,
    Other(bindings::DNSServiceRecordType),
}

impl From<bindings::DNSServiceRecordType> for RecordType {
    fn from(code: bindings::DNSServiceRecordType) -> Self {
        match code {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::NULL,
            11 => RecordType::WKS,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            17 => RecordType::RP,
            18 => RecordType::AFSDB,
            19 => RecordType::X25,
            20 => RecordType::ISDN,
            21 => RecordType::RT,
            22 => RecordType::NSAP,
            23 => RecordType::NSAP_PTR,
            24 => RecordType::SIG,
            25 => RecordType::KEY,
            26 => RecordType::PX,
            27 => RecordType::GPOS,
            28 => RecordType::AAAA,
            29 => RecordType::LOC,
            30 => RecordType::NXT,
            31 => RecordType::EID,
            32 => RecordType::NIMLOC,
            33 => RecordType::SRV,
            34 => RecordType::ATMA,
            35 => RecordType::NAPTR,
            36 => RecordType::KX,
            37 => RecordType::CERT,
            38 => RecordType::A6,
            39 => RecordType::DNAME,
            40 => RecordType::SINK,
            41 => RecordType::OPT,
            42 => RecordType::APL,
            43 => RecordType::DS,
            44 => RecordType::SSHFP,
            45 => RecordType::IPSECKEY,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            49 => RecordType::DHCID,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            55 => RecordType::HIP,
            99 => RecordType::SPF,
            100 => RecordType::UINFO,
            101 => RecordType::UID,
            102 => RecordType::GID,
            103 => RecordType::UNSPEC,
            249 => RecordType::TKEY,
            250 => RecordType::TSIG,
            251 => RecordType::IXFR,
            252 => RecordType::AXFR,
            253 => RecordType::MAILB,
            254 => RecordType::MAILA,
            255 => RecordType::ANY,
            other => RecordType::Other(other),
        }
    }
}

impl From<RecordType> for bindings::DNSServiceRecordType {
    fn from(t: RecordType) -> bindings::DNSServiceRecordType {
        match t {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::RP => 17,
            RecordType::AFSDB => 18,
            RecordType::X25 => 19,
            RecordType::ISDN => 20,
            RecordType::RT => 21,
            RecordType::NSAP => 22,
            RecordType::NSAP_PTR => 23,
            RecordType::SIG => 24,
            RecordType::KEY => 25,
            RecordType::PX => 26,
            RecordType::GPOS => 27,
            RecordType::AAAA => 28,
            RecordType::LOC => 29,
            RecordType::NXT => 30,
            RecordType::EID => 31,
            RecordType::NIMLOC => 32,
            RecordType::SRV => 33,
            RecordType::ATMA => 34,
            RecordType::NAPTR => 35,
            RecordType::KX => 36,
            RecordType::CERT => 37,
            RecordType::A6 => 38,
            RecordType::DNAME => 39,
            RecordType::SINK => 40,
            RecordType::OPT => 41,
            RecordType::APL => 42,
            RecordType::DS => 43,
            RecordType::SSHFP => 44,
            RecordType::IPSECKEY => 45,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::DHCID => 49,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::HIP => 55,
            RecordType::SPF => 99,
            RecordType::UINFO => 100,
            RecordType::UID => 101,
            RecordType::GID => 102,
            RecordType::UNSPEC => 103,
            RecordType::TKEY => 249,
            RecordType::TSIG => 250,
            RecordType::IXFR => 251,
            RecordType::AXFR => 252,
            RecordType::MAILB => 253,
            RecordType::MAILA => 254,
            RecordType::ANY => 255,
            RecordType::Other(code) => code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MDNSError {
    NoError,
    Unknown,
    NoSuchName,
    NoMemory,
    BadParam,
    BadReference,
    BadState,
    BadFlags,
    Unsupported,
    NotInitialized,
    AlreadyRegistered,
    NameConflict,
    Invalid,
    Firewall,
    Incompatible,
    BadInterfaceIndex,
    Refused,
    NoSuchRecord,
    NoAuth,
    NoSuchKey,
    NATTraversal,
    DoubleNAT,
    BadTime,
    BadSig,
    BadKey,
    Transient,
    ServiceNotRunning,
    NATPortMappingUnsupported,
    NATPortMappingDisabled,
    NoRouter,
    PollingMode,
    Timeout,
    Other(bindings::DNSServiceErrorType),
}

impl From<bindings::DNSServiceErrorType> for MDNSError {
    fn from(code: bindings::DNSServiceErrorType) -> Self {
        match code {
            0 => MDNSError::NoError,
            -65537 => MDNSError::Unknown,
            -65538 => MDNSError::NoSuchName,
            -65539 => MDNSError::NoMemory,
            -65540 => MDNSError::BadParam,
            -65541 => MDNSError::BadReference,
            -65542 => MDNSError::BadState,
            -65543 => MDNSError::BadFlags,
            -65544 => MDNSError::Unsupported,
            -65545 => MDNSError::NotInitialized,
            -65547 => MDNSError::AlreadyRegistered,
            -65548 => MDNSError::NameConflict,
            -65549 => MDNSError::Invalid,
            -65550 => MDNSError::Firewall,
            -65551 => MDNSError::Incompatible,
            -65552 => MDNSError::BadInterfaceIndex,
            -65553 => MDNSError::Refused,
            -65554 => MDNSError::NoSuchRecord,
            -65555 => MDNSError::NoAuth,
            -65556 => MDNSError::NoSuchKey,
            -65557 => MDNSError::NATTraversal,
            -65558 => MDNSError::DoubleNAT,
            -65559 => MDNSError::BadTime,
            -65560 => MDNSError::BadSig,
            -65561 => MDNSError::BadKey,
            -65562 => MDNSError::Transient,
            -65563 => MDNSError::ServiceNotRunning,
            -65564 => MDNSError::NATPortMappingUnsupported,
            -65565 => MDNSError::NATPortMappingDisabled,
            -65566 => MDNSError::NoRouter,
            -65567 => MDNSError::PollingMode,
            -65568 => MDNSError::Timeout,
            other => MDNSError::Other(other),
        }
    }
}

impl From<MDNSError> for bindings::DNSServiceErrorType {
    fn from(err: MDNSError) -> bindings::DNSServiceErrorType {
        match err {
            MDNSError::NoError => 0,
            MDNSError::Unknown => -65537,
            MDNSError::NoSuchName => -65538,
            MDNSError::NoMemory => -65539,
            MDNSError::BadParam => -65540,
            MDNSError::BadReference => -65541,
            MDNSError::BadState => -65542,
            MDNSError::BadFlags => -65543,
            MDNSError::Unsupported => -65544,
            MDNSError::NotInitialized => -65545,
            MDNSError::AlreadyRegistered => -65547,
            MDNSError::NameConflict => -65548,
            MDNSError::Invalid => -65549,
            MDNSError::Firewall => -65550,
            MDNSError::Incompatible => -65551,
            MDNSError::BadInterfaceIndex => -65552,
            MDNSError::Refused => -65553,
            MDNSError::NoSuchRecord => -65554,
            MDNSError::NoAuth => -65555,
            MDNSError::NoSuchKey => -65556,
            MDNSError::NATTraversal => -65557,
            MDNSError::DoubleNAT => -65558,
            MDNSError::BadTime => -65559,
            MDNSError::BadSig => -65560,
            MDNSError::BadKey => -65561,
            MDNSError::Transient => -65562,
            MDNSError::ServiceNotRunning => -65563,
            MDNSError::NATPortMappingUnsupported => -65564,
            MDNSError::NATPortMappingDisabled => -65565,
            MDNSError::NoRouter => -65566,
            MDNSError::PollingMode => -65567,
            MDNSError::Timeout => -65568,
            MDNSError::Other(code) => code,
        }
    }
}
