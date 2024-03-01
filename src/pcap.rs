use serde::Serialize;

#[repr(C)]
#[derive(Serialize)]
pub(crate) struct pcap_hdr_t {
    pub(crate) magic_number: u32,  /* magic number */
    pub(crate) version_major: u16, /* major version number */
    pub(crate) version_minor: u16, /* minor version number */
    pub(crate) thiszone: i32,      /* GMT to local correction */
    pub(crate) sigfigs: u32,       /* accuracy of timestamps */
    pub(crate) snaplen: u32,       /* max length of captured packets, in octets */
    /// https://www.tcpdump.org/linktypes.html
    pub(crate) network: u32, /* data link type */
}

impl pcap_hdr_t {
    pub(crate) fn new(linktype: u32) -> pcap_hdr_t {
        pcap_hdr_t {
            magic_number: u32::from_be_bytes([0xa1, 0xb2, 0xc3, 0xd4]),
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535, // 1k should be enough tho
            network: linktype,
        }
    }
}

#[repr(C)]
#[derive(Serialize)]
pub(crate) struct pcaprec_hdr_t {
    pub(crate) ts_sec: u32,   /* timestamp seconds */
    pub(crate) ts_usec: u32,  /* timestamp microseconds */
    pub(crate) incl_len: u32, /* number of octets of packet saved in file */
    pub(crate) orig_len: u32, /* actual length of packet */
}

impl pcaprec_hdr_t {
    pub(crate) fn new(size: u32) -> pcaprec_hdr_t {
        pcaprec_hdr_t {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: size,
            orig_len: size,
        }
    }
}
