use async_trait::async_trait;
use t3_application::ports::NatTraversalPort;
use t3_domain::{DomainError, DomainResult};
use rand::RngCore;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub struct StunClientAdapter;

impl StunClientAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Builds a 20-byte RFC 5389 STUN Binding Request packet
    pub fn build_binding_request(transaction_id: &[u8; 12]) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        packet[2..4].copy_from_slice(&0u16.to_be_bytes()); // Length 0
        packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet[8..20].copy_from_slice(transaction_id);
        packet
    }

    /// Parses a STUN response packet to extract the public IPv4 and Port
    pub fn parse_binding_response(
        response: &[u8],
        expected_transaction_id: &[u8; 12],
    ) -> DomainResult<SocketAddr> {
        if response.len() < 20 {
            return Err(DomainError::InvalidIpAddress("STUN response too short".into()));
        }

        let msg_type = u16::from_be_bytes([response[0], response[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(DomainError::InvalidIpAddress(format!(
                "Unexpected STUN message type: 0x{:04X}",
                msg_type
            )));
        }

        let magic_cookie = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
        if magic_cookie != STUN_MAGIC_COOKIE {
            return Err(DomainError::InvalidIpAddress("Invalid STUN magic cookie".into()));
        }

        if &response[8..20] != expected_transaction_id {
            return Err(DomainError::InvalidIpAddress(
                "STUN transaction ID mismatch".into(),
            ));
        }

        let msg_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        let mut offset = 20;
        let end = (20 + msg_len).min(response.len());

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                break;
            }

            let attr_data = &response[offset..offset + attr_len];
            offset += attr_len;
            // Attributes are padded to 4-byte boundaries
            let remainder = attr_len % 4;
            if remainder != 0 {
                offset += 4 - remainder;
            }

            if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_data.len() >= 8 {
                let family = attr_data[1];
                let xor_port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
                let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

                if family == 0x01 {
                    // IPv4
                    let xor_ip = u32::from_be_bytes([
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    ]);
                    let ip_num = xor_ip ^ STUN_MAGIC_COOKIE;
                    let ip = std::net::Ipv4Addr::from(ip_num);

                    return Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
                } else if family == 0x02 && attr_data.len() >= 20 {
                    // IPv6 (RFC 5389 Section 15.2: XOR first 4 bytes with magic cookie, next 12 bytes with tx_id)
                    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                    let mut raw_v6 = [0u8; 16];
                    for i in 0..4 {
                        raw_v6[i] = attr_data[4 + i] ^ cookie_bytes[i];
                    }
                    for i in 0..12 {
                        raw_v6[4 + i] = attr_data[8 + i] ^ expected_transaction_id[i];
                    }
                    let ip6 = std::net::Ipv6Addr::from(raw_v6);
                    return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(ip6, port, 0, 0)));
                }
            } else if attr_type == ATTR_MAPPED_ADDRESS && attr_data.len() >= 8 {
                let family = attr_data[1];
                let port = u16::from_be_bytes([attr_data[2], attr_data[3]]);
                if family == 0x01 {
                    let ip = std::net::Ipv4Addr::new(
                        attr_data[4],
                        attr_data[5],
                        attr_data[6],
                        attr_data[7],
                    );
                    return Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
                } else if family == 0x02 && attr_data.len() >= 20 {
                    let mut raw_v6 = [0u8; 16];
                    raw_v6.copy_from_slice(&attr_data[4..20]);
                    let ip6 = std::net::Ipv6Addr::from(raw_v6);
                    return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(ip6, port, 0, 0)));
                }
            }
        }

        Err(DomainError::InvalidIpAddress(
            "STUN response did not contain MAPPED-ADDRESS attribute".into(),
        ))
    }
}

impl Default for StunClientAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NatTraversalPort for StunClientAdapter {
    async fn discover_public_endpoint(
        &self,
        stun_server: &str,
        local_port: u16,
    ) -> DomainResult<String> {
        let bind_addr = format!("0.0.0.0:{}", local_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| DomainError::InvalidIpAddress(format!("Failed to bind UDP port {}: {}", local_port, e)))?;

        let mut tx_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut tx_id);

        let request = Self::build_binding_request(&tx_id);
        socket
            .send_to(&request, stun_server)
            .await
            .map_err(|e| DomainError::InvalidIpAddress(format!("Failed to send STUN request: {}", e)))?;

        let mut buf = [0u8; 512];
        let recv_result = timeout(Duration::from_millis(2500), socket.recv_from(&mut buf)).await;

        match recv_result {
            Ok(Ok((len, _))) => {
                let addr = Self::parse_binding_response(&buf[..len], &tx_id)?;
                Ok(addr.to_string())
            }
            Ok(Err(e)) => Err(DomainError::InvalidIpAddress(format!("STUN recv error: {}", e))),
            Err(_) => Err(DomainError::InvalidIpAddress("STUN request timed out".into())),
        }
    }

    async fn send_hole_punch_burst(
        &self,
        local_port: u16,
        remote_endpoint: &str,
    ) -> DomainResult<()> {
        let bind_addr = format!("0.0.0.0:{}", local_port);
        let socket = match UdpSocket::bind(&bind_addr).await {
            Ok(s) => s,
            Err(_) => {
                // If port is already bound by WireGuard, skip binding a new one
                return Ok(());
            }
        };

        // Fire 5 rapid UDP keepalive probe packets to open NAT mapping
        let dummy_probe = b"\x00\x00t3Bridge_PUNCH\x00";
        for _ in 0..5 {
            let _ = socket.send_to(dummy_probe, remote_endpoint).await;
            tokio::time::sleep(Duration::from_millis(15)).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_xor_mapped_address_parser() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut response = Vec::new();

        // 20-byte Header: Binding Success Response (0x0101)
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes()); // Message Length: 12 bytes
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tx_id);

        // Attribute: XOR-MAPPED-ADDRESS (0x0020), length 8
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());

        // Target: 203.0.113.195 (0xCB0071C3), Port 54321 (0xD431)
        let raw_ip = 0xCB0071C3u32;
        let raw_port = 54321u16;

        let xor_port = raw_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let xor_ip = raw_ip ^ STUN_MAGIC_COOKIE;

        response.push(0x00); // Reserved
        response.push(0x01); // IPv4
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_ip.to_be_bytes());

        let parsed = StunClientAdapter::parse_binding_response(&response, &tx_id).unwrap();
        assert_eq!(parsed.to_string(), "203.0.113.195:54321");
    }

    #[test]
    fn test_stun_xor_mapped_ipv6_address_parser() {
        let tx_id = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];
        let mut response = Vec::new();

        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&24u16.to_be_bytes()); // Message Length: 24 bytes (4 attr hdr + 20 payload)
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tx_id);

        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&20u16.to_be_bytes());

        let target_v6: std::net::Ipv6Addr = "2409:40e1:432:2c7a:dcf0:b718:b32b:dc88".parse().unwrap();
        let raw_octets = target_v6.octets();
        let raw_port = 49633u16;
        let xor_port = raw_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
        let mut xor_v6 = [0u8; 16];
        for i in 0..4 {
            xor_v6[i] = raw_octets[i] ^ cookie_bytes[i];
        }
        for i in 0..12 {
            xor_v6[4 + i] = raw_octets[4 + i] ^ tx_id[i];
        }

        response.push(0x00);
        response.push(0x02); // IPv6 family
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_v6);

        let parsed = StunClientAdapter::parse_binding_response(&response, &tx_id).unwrap();
        assert_eq!(parsed, SocketAddr::V6(std::net::SocketAddrV6::new(target_v6, raw_port, 0, 0)));
    }
}
