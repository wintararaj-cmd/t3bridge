use crate::engine::ServiceEngine;
use std::sync::Arc;
use t3_ipc::{IpcRequest, IpcResponse, PIPE_NAME};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Starts the Windows Named Pipe IPC server (`\\.\pipe\t3bridge_service`) with a DACL
/// allowing authenticated local users (Session 1 Tray UI) to communicate with the
/// `LocalSystem` Windows Service (Session 0).
#[cfg(windows)]
pub async fn run_ipc_server(engine: Arc<ServiceEngine>) {
    let mut first_instance = true;

    loop {
        let server_res = create_pipe_instance(&mut first_instance);
        let server = match server_res {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[t3_service][ipc] Failed to create named pipe instance: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        if let Err(e) = server.connect().await {
            eprintln!("[t3_service][ipc] Pipe connect error: {}", e);
            continue;
        }

        let engine_clone = Arc::clone(&engine);
        tokio::spawn(async move {
            let (read_half, mut write_half) = tokio::io::split(server);
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();

            match reader.read_line(&mut line).await {
                Ok(0) => return,
                Ok(_) => {
                    let response = match serde_json::from_str::<IpcRequest>(line.trim()) {
                        Ok(req) => engine_clone.handle_request(req).await,
                        Err(e) => IpcResponse::Error {
                            message: format!("Invalid IPC request: {}", e),
                        },
                    };
                    if let Ok(mut out) = serde_json::to_string(&response) {
                        out.push('\n');
                        let _ = write_half.write_all(out.as_bytes()).await;
                        let _ = write_half.flush().await;
                    }
                }
                Err(e) => {
                    eprintln!("[t3_service][ipc] Pipe read error: {}", e);
                }
            }
        });
    }
}

#[cfg(windows)]
fn create_pipe_instance(
    first_instance: &mut bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut std::ffi::c_void,
        b_inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut std::ffi::c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    const SDDL_REVISION_1: u32 = 1;
    // SYSTEM = full, Builtin Admins = full, Authenticated Users = read/write
    let sddl: Vec<u16> = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)\0"
        .encode_utf16()
        .collect();

    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };

    let mut opts = ServerOptions::new();
    if *first_instance {
        opts.first_pipe_instance(true);
        *first_instance = false;
    }

    let result = if ok != 0 && !sd.is_null() {
        let mut sa = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd,
            b_inherit_handle: 0,
        };
        let res = unsafe {
            opts.create_with_security_attributes_raw(
                PIPE_NAME,
                &mut sa as *mut SecurityAttributes as *mut std::ffi::c_void,
            )
        };
        unsafe {
            LocalFree(sd);
        }
        res
    } else {
        opts.create(PIPE_NAME)
    };

    result
}

#[cfg(not(windows))]
pub async fn run_ipc_server(_engine: Arc<ServiceEngine>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
