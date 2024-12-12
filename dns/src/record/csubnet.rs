use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::wire::*;

/// ECS Client Subnet implementation
/// https://datatracker.ietf.org/doc/html/rfc7871
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct CSUBNET {
    /// The payload of the CSUBNET record.
    pub address: std::net::IpAddr,
}

impl CSUBNET {

    /// The code for Client subnet option in an OPT record.
    pub const ECS_CODE: u16 = 8;
    /// The address family number for IPv4
    pub const ADDRESS_FAMILY_NUMBER_IPV4: u16 = 1;
    /// The address family number for IPv6
    pub const ADDRESS_FAMILY_NUMBER_IPV6: u16 = 2;


    /// Serialises this CSUBNET option into a vector of bytes.
    ///
    /// This is necessary for CSUBNET option to be sent in an OPT record of the
    /// Additional section of requests.
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32);

        bytes.write_u16::<BigEndian>(CSUBNET::ECS_CODE)?;

        match self.address {
            IpAddr::V6(address) => {
                let source_prefix: u8 = Ipv6Addr::BITS as u8;
                bytes.write_u16::<BigEndian>(4 + source_prefix as u16 / 8)?; // Length
                bytes.write_u16::<BigEndian>(CSUBNET::ADDRESS_FAMILY_NUMBER_IPV6)?; // Family
                bytes.write_u8(source_prefix)?; // source_prefix
                bytes.write_u8(0)?; // scope_prefix

                for b in &address.octets() {
                    bytes.write_u8(*b)?;
                }
            },
            IpAddr::V4(address) => {
                let source_prefix: u8 = Ipv4Addr::BITS as u8;
                bytes.write_u16::<BigEndian>(4 + source_prefix as u16 / 8)?; // Length
                bytes.write_u16::<BigEndian>(CSUBNET::ADDRESS_FAMILY_NUMBER_IPV4)?; // Family
                bytes.write_u8(source_prefix)?; // source_prefix
                bytes.write_u8(0)?; // scope_prefix

                for b in &address.octets() {
                    bytes.write_u8(*b)?;
                }

            }
        }

        Ok(bytes)
    }
}
