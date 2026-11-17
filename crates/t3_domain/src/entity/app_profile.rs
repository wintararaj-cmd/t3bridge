use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppProfile {
    pub id: String,
    pub name: String,               // e.g. "Marg ERP 9+", "Tally Prime", "Busy Accounting"
    pub default_share_name: String, // e.g. "MargERP", "TallyData", "BusyData"
    pub suggested_drive_letter: char, // e.g. 'Z'
    pub executable_name: Option<String>, // e.g. "marg2014.exe"
}

impl AppProfile {
    pub fn marg_erp() -> Self {
        Self {
            id: "marg_erp".into(),
            name: "Marg ERP 9+".into(),
            default_share_name: "MargERP".into(),
            suggested_drive_letter: 'Z',
            executable_name: Some("marg2014.exe".into()),
        }
    }

    pub fn tally_prime() -> Self {
        Self {
            id: "tally_prime".into(),
            name: "Tally Prime".into(),
            default_share_name: "TallyData".into(),
            suggested_drive_letter: 'Y',
            executable_name: Some("tally.exe".into()),
        }
    }

    pub fn busy_erp() -> Self {
        Self {
            id: "busy_erp".into(),
            name: "Busy Accounting".into(),
            default_share_name: "BusyData".into(),
            suggested_drive_letter: 'X',
            executable_name: Some("busy.exe".into()),
        }
    }

    pub fn custom(name: &str, share_name: &str, drive_letter: char) -> Self {
        Self {
            id: name.to_lowercase().replace(' ', "_"),
            name: name.to_string(),
            default_share_name: share_name.to_string(),
            suggested_drive_letter: drive_letter.to_ascii_uppercase(),
            executable_name: None,
        }
    }
}
