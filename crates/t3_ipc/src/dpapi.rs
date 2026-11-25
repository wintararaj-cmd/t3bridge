use base64::Engine;

/// Encrypts sensitive UTF-8 text using Windows DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`)
/// so both the `LocalSystem` Windows Service and the logged-in user's Tray App
/// on the same machine can protect/unprotect stored credentials without plaintext on disk.
#[cfg(windows)]
pub fn protect_secret(plaintext: &str) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut std::ffi::c_void,
            p_prompt_struct: *mut std::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x01;
    const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x04;

    let mut input_bytes = plaintext.as_bytes().to_vec();
    let in_blob = DataBlob {
        cb_data: input_bytes.len() as u32,
        pb_data: input_bytes.as_mut_ptr(),
    };
    let mut out_blob = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
    };

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err("Windows DPAPI CryptProtectData failed".into());
    }

    let protected = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pb_data as *mut std::ffi::c_void);
        vec
    };

    Ok(base64::engine::general_purpose::STANDARD.encode(protected))
}

#[cfg(windows)]
pub fn unprotect_secret(encoded: &str) -> Result<String, String> {
    if encoded.is_empty() {
        return Ok(String::new());
    }

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut std::ffi::c_void,
            p_prompt_struct: *mut std::ffi::c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x01;

    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Invalid base64 secret: {}", e))?;

    let in_blob = DataBlob {
        cb_data: raw.len() as u32,
        pb_data: raw.as_mut_ptr(),
    };
    let mut out_blob = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err("Windows DPAPI CryptUnprotectData failed".into());
    }

    let decrypted = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pb_data as *mut std::ffi::c_void);
        vec
    };

    String::from_utf8(decrypted).map_err(|e| format!("Invalid UTF-8 in secret: {}", e))
}

#[cfg(not(windows))]
pub fn protect_secret(plaintext: &str) -> Result<String, String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes()))
}

#[cfg(not(windows))]
pub fn unprotect_secret(encoded: &str) -> Result<String, String> {
    if encoded.is_empty() {
        return Ok(String::new());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Invalid base64 secret: {}", e))?;
    String::from_utf8(raw).map_err(|e| format!("Invalid UTF-8 in secret: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protect_and_unprotect_roundtrip() {
        let secret = "Tally@2026#Office!";
        let encrypted = protect_secret(secret).expect("protect_secret should succeed");
        assert_ne!(encrypted, secret);
        let decrypted = unprotect_secret(&encrypted).expect("unprotect_secret should succeed");
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_protect_empty_string() {
        assert_eq!(protect_secret("").unwrap(), "");
        assert_eq!(unprotect_secret("").unwrap(), "");
    }
}
