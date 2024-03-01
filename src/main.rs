use std::fs::File;
use std::io::prelude::*;

mod pcap;
const LINKTYPE_USER_CUSTOM_1: u32 = 147;
fn main() -> std::io::Result<()> {
    let mut inbytes = Vec::new();
    File::open("/home/david/Downloads/u/rover3.ubx")?.read_to_end(&mut inbytes)?;
    inbytes = inbytes[0x1B..].to_vec();

    let mut outfile = File::create("out.pcap")?;
    let h = pcap::pcap_hdr_t::new(LINKTYPE_USER_CUSTOM_1);
    bincode::serialize_into(&mut outfile, &h).unwrap();

    let mut i = 0;
    loop {
        if inbytes[i] == 0 && inbytes[i + 1] == 0 {
            break;
        }
        assert_eq!(inbytes[i], 0xb5);
        assert_eq!(inbytes[i + 1], 0x62);
        let payload_len = u16::from_le_bytes([inbytes[i + 4], inbytes[i + 5]]);
        let packet_len = 8 + payload_len;

        let ph = pcap::pcaprec_hdr_t::new(packet_len as u32);
        outfile.write(&bincode::serialize(&ph).unwrap())?;
        //outfile.write(&[0, 0, 0, 0])?;
        outfile.write(&inbytes[i..(i + packet_len as usize)])?;
        i += packet_len as usize;
        if i == inbytes.len() {
            break;
        }
    }
    println!("Hello, world!");
    Ok(())
}
