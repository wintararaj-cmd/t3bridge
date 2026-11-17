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
    pub fn primary_erp() -> Self {
        Self {
            id: "primary_erp".into(),
            name: "Primary Business ERP (Database & Share)".into(),
            default_share_name: "SharedData".into(),
            suggested_drive_letter: 'Z',
            executable_name: None,
        }
    }

    pub fn branch_share() -> Self {
        Self {
            id: "branch_share".into(),
            name: "Branch Accounting & Document Share".into(),
            default_share_name: "BranchData".into(),
            suggested_drive_letter: 'Y',
            executable_name: None,
        }
    }

    pub fn marg_erp() -> Self {
        Self::primary_erp()
    }

    pub fn tally_prime() -> Self {
        Self::branch_share()
    }

    pub fn busy_erp() -> Self {
        Self::custom("Secondary Business Share", "AccountingData", 'X')
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
