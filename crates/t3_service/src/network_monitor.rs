use std::collections::BTreeSet;
use std::net::UdpSocket;
use tokio::sync::mpsc;

/// Option 3: Detects network interface / default route changes (e.g. Wi-Fi <-> Mobile Hotspot,
/// Ethernet unplug/plug, or DHCP IP renewal) and emits a debounced change notification.
/// Ignores transient blips to `offline` when the same interface IP comes right back (common on
/// mobile hotspots) and enforces a cooldown to prevent reconnect storms.
pub fn spawn_network_change_monitor(change_tx: mpsc::UnboundedSender<String>) {
    tokio::spawn(async move {
        let mut last_online_fingerprint = capture_network_fingerprint();
        let mut last_emit = tokio::time::Instant::now()
            .checked_sub(tokio::time::Duration::from_secs(60))
            .unwrap_or_else(tokio::time::Instant::now);

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
            let current = capture_network_fingerprint();

            // Do not trigger a reconnect just because the route briefly went offline;
            // wait for an actual online IP that differs from the last known online IP.
            if current.is_empty() || current == last_online_fingerprint {
                continue;
            }

            // Debounce 3s so mobile hotspot / Wi-Fi DHCP & routing settle before reconnecting
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            let settled = capture_network_fingerprint();
            if settled.is_empty() || settled == last_online_fingerprint {
                continue;
            }

            // Enforce minimum 10s cooldown between network-change triggers
            if last_emit.elapsed() < tokio::time::Duration::from_secs(10) {
                continue;
            }

            let msg = format!(
                "Network interface changed ({} -> {})",
                format_fp(&last_online_fingerprint),
                format_fp(&settled)
            );
            last_online_fingerprint = settled;
            last_emit = tokio::time::Instant::now();
            if change_tx.send(msg).is_err() {
                break;
            }
        }
    });
}

fn format_fp(fp: &BTreeSet<String>) -> String {
    if fp.is_empty() {
        "offline".into()
    } else {
        fp.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

/// Captures the active outbound local IPv4 address(es) by probing UDP route selection
/// (no packets are actually sent over the wire). Ignores our own virtual 10.99.0.x subnet.
fn capture_network_fingerprint() -> BTreeSet<String> {
    let mut ips = BTreeSet::new();
    for probe in ["1.1.1.1:80", "8.8.8.8:80"] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(probe).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    let ip = local.ip().to_string();
                    if !ip.starts_with("10.99.0.") && !ip.starts_with("127.") {
                        ips.insert(ip);
                    }
                }
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_fp() {
        let empty = BTreeSet::new();
        assert_eq!(format_fp(&empty), "offline");
        let mut set = BTreeSet::new();
        set.insert("192.168.1.50".to_string());
        assert_eq!(format_fp(&set), "192.168.1.50");
    }
}
