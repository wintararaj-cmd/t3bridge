use crate::errors::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VirtualIp {
    addr: Ipv4Addr,
    subnet_mask: u8,
}

impl VirtualIp {
    pub fn new(ip_str: &str, subnet_mask: u8) -> DomainResult<Self> {
        let addr = Ipv4Addr::from_str(ip_str)
            .map_err(|_| DomainError::InvalidIpAddress(ip_str.to_string()))?;

        if subnet_mask > 32 {
            return Err(DomainError::InvalidIpAddress(format!("Mask /{} is invalid", subnet_mask)));
        }

        Ok(Self { addr, subnet_mask })
    }

    pub fn addr(&self) -> &Ipv4Addr {
        &self.addr
    }

    pub fn subnet_mask(&self) -> u8 {
        self.subnet_mask
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.addr, self.subnet_mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_virtual_ip() {
        let ip = VirtualIp::new("10.99.0.2", 24).unwrap();
        assert_eq!(ip.cidr(), "10.99.0.2/24");
    }

    #[test]
    fn test_invalid_virtual_ip() {
        assert!(VirtualIp::new("999.999.1.1", 24).is_err());
        assert!(VirtualIp::new("10.99.0.1", 33).is_err());
    }
}
