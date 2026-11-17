use crate::errors::{DomainError, DomainResult};
use crate::value_objects::VirtualIp;

// State markers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnected;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Licensed {
    pub license_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelActive {
    pub license_id: String,
    pub virtual_ip: VirtualIp,
    pub host_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveMounted {
    pub license_id: String,
    pub virtual_ip: VirtualIp,
    pub drive_letter: char,
}

// Connection State wrapper
#[derive(Debug, Clone)]
pub struct ConnectionMachine<S> {
    pub state: S,
}

impl ConnectionMachine<Disconnected> {
    pub fn new() -> Self {
        Self { state: Disconnected }
    }

    pub fn mark_licensed(self, license_id: String) -> ConnectionMachine<Licensed> {
        ConnectionMachine {
            state: Licensed { license_id },
        }
    }
}

impl Default for ConnectionMachine<Disconnected> {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMachine<Licensed> {
    pub fn mark_tunnel_active(
        self,
        virtual_ip: VirtualIp,
        host_endpoint: String,
    ) -> ConnectionMachine<TunnelActive> {
        ConnectionMachine {
            state: TunnelActive {
                license_id: self.state.license_id,
                virtual_ip,
                host_endpoint,
            },
        }
    }
}

impl ConnectionMachine<TunnelActive> {
    pub fn mark_drive_mounted(self, drive_letter: char) -> DomainResult<ConnectionMachine<DriveMounted>> {
        let upper_letter = drive_letter.to_ascii_uppercase();
        if !('C'..='Z').contains(&upper_letter) {
            return Err(DomainError::DriveLetterInUse(upper_letter));
        }

        Ok(ConnectionMachine {
            state: DriveMounted {
                license_id: self.state.license_id,
                virtual_ip: self.state.virtual_ip,
                drive_letter: upper_letter,
            },
        })
    }

    pub fn smb_unc_path(&self, share_name: &str) -> String {
        let clean_share = share_name.trim_matches('\\').trim_matches('/');
        format!(r"\\{}\{}", self.state.virtual_ip.addr(), clean_share)
    }
}

impl ConnectionMachine<DriveMounted> {
    pub fn mark_disconnected(self) -> ConnectionMachine<Disconnected> {
        ConnectionMachine { state: Disconnected }
    }
}
