use std::net::Ipv4Addr;

/// Tunnel subnet prefix: 10.99.0.0/24
const TUNNEL_NET_PREFIX: [u8; 3] = [10, 99, 0];

/// Returns `Some(dst_ipv4)` if `pkt` is a valid IPv4 unicast packet targeting the
/// `10.99.0.1..=10.99.0.254` tunnel subnet.
///
/// Drops IPv6, multicast (`224.0.0.0/4`), global broadcast (`255.255.255.255`),
/// subnet broadcast (`10.99.0.255`), and unrelated OS chatter (mDNS, SSDP, IGMP).
pub fn extract_routable_ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }

    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let octets = dst.octets();
    if octets[0..3] != TUNNEL_NET_PREFIX {
        return None;
    }
    // Reject network (.0) and broadcast (.255)
    if octets[3] == 0 || octets[3] == 255 {
        return None;
    }

    Some(dst)
}

/// Extracts source IPv4 address from a valid IPv4 packet.
pub fn extract_ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Clamps the TCP Maximum Segment Size (MSS) option on IPv4 TCP SYN / SYN-ACK packets
/// so SMB TCP segments never fragment across WireGuard UDP / PPPoE / NAT paths.
///
/// Updates the TCP checksum incrementally per RFC 1624. Returns `true` if MSS was modified.
pub fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) -> bool {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 {
        return false;
    }
    // Protocol 6 == TCP
    if pkt[9] != 6 {
        return false;
    }

    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 20 {
        return false;
    }

    let tcp_flags = pkt[ihl + 13];
    // Only SYN packets carry the MSS option (SYN bit = 0x02)
    if (tcp_flags & 0x02) == 0 {
        return false;
    }

    let tcp_data_offset = ((pkt[ihl + 12] >> 4) as usize) * 4;
    if tcp_data_offset <= 20 || pkt.len() < ihl + tcp_data_offset {
        return false;
    }

    let options_start = ihl + 20;
    let options_end = ihl + tcp_data_offset;
    let mut offset = options_start;

    while offset < options_end {
        let kind = pkt[offset];
        if kind == 0 {
            // End of Option List
            break;
        }
        if kind == 1 {
            // NOP
            offset += 1;
            continue;
        }
        if offset + 1 >= options_end {
            break;
        }
        let len = pkt[offset + 1] as usize;
        if len < 2 || offset + len > options_end {
            break;
        }

        if kind == 2 && len == 4 {
            let old_mss = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
            if old_mss > max_mss {
                pkt[offset + 2..offset + 4].copy_from_slice(&max_mss.to_be_bytes());
                // Incremental TCP checksum update (RFC 1624)
                let old_cksum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);
                let new_cksum = rfc1624_update(old_cksum, old_mss, max_mss);
                pkt[ihl + 16..ihl + 18].copy_from_slice(&new_cksum.to_be_bytes());
                return true;
            }
            return false;
        }

        offset += len;
    }

    false
}

/// Incremental 1's-complement checksum update per RFC 1624:
/// `HC' = ~(~HC + ~m + m')`
fn rfc1624_update(old_checksum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum = (!old_checksum as u32) + (!old_val as u32) + (new_val as u32);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute_tcp_checksum(pkt: &[u8]) -> u16 {
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let tcp = &pkt[ihl..];
        let mut sum: u32 = 0;

        // Pseudo-header: src IP, dst IP, zero+proto, tcp len
        for chunk in pkt[12..20].chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += 6u32; // TCP protocol
        sum += tcp.len() as u32;

        let mut i = 0;
        while i + 1 < tcp.len() {
            if i != 16 {
                sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
            }
            i += 2;
        }
        if tcp.len() % 2 == 1 {
            sum += (tcp[tcp.len() - 1] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn test_packet_filter_allows_tunnel_unicast_and_drops_noise() {
        // Valid 10.99.0.1 -> 10.99.0.2
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 99, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 99, 0, 2]);
        assert_eq!(extract_routable_ipv4_dst(&pkt), Some(Ipv4Addr::new(10, 99, 0, 2)));
        assert_eq!(extract_ipv4_src(&pkt), Some(Ipv4Addr::new(10, 99, 0, 1)));

        // Subnet broadcast 10.99.0.255 -> drop
        pkt[16..20].copy_from_slice(&[10, 99, 0, 255]);
        assert_eq!(extract_routable_ipv4_dst(&pkt), None);

        // Multicast 224.0.0.251 (mDNS) -> drop
        pkt[16..20].copy_from_slice(&[224, 0, 0, 251]);
        assert_eq!(extract_routable_ipv4_dst(&pkt), None);

        // IPv6 packet -> drop
        pkt[0] = 0x60;
        pkt[16..20].copy_from_slice(&[10, 99, 0, 2]);
        assert_eq!(extract_routable_ipv4_dst(&pkt), None);
    }

    #[test]
    fn test_clamp_tcp_mss_updates_mss_and_checksum_accurately() {
        // 20B IPv4 + 24B TCP SYN with MSS=1460
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45; // IPv4, IHL=5 (20B)
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes());
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 99, 0, 2]);
        pkt[16..20].copy_from_slice(&[10, 99, 0, 1]);

        // TCP header at offset 20
        pkt[20..22].copy_from_slice(&50000u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&445u16.to_be_bytes()); // dst port (SMB)
        pkt[32] = 0x60; // data offset = 6 * 4 = 24 bytes
        pkt[33] = 0x02; // SYN flag
        // MSS option: kind=2, len=4, value=1460
        pkt[40] = 2;
        pkt[41] = 4;
        pkt[42..44].copy_from_slice(&1460u16.to_be_bytes());

        // Compute initial valid TCP checksum
        let init_cksum = compute_tcp_checksum(&pkt);
        pkt[36..38].copy_from_slice(&init_cksum.to_be_bytes());

        let modified = clamp_tcp_mss(&mut pkt, 1340);
        assert!(modified);
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1340);

        // Verify incremental checksum matches freshly computed checksum
        let updated_cksum = u16::from_be_bytes([pkt[36], pkt[38 - 1]]);
        assert_eq!(updated_cksum, compute_tcp_checksum(&pkt));

        // Clamping again with same limit is a no-op
        assert!(!clamp_tcp_mss(&mut pkt, 1340));
    }
}
