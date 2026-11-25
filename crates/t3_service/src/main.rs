mod engine;
mod ipc_server;
mod network_monitor;
mod power;

use engine::ServiceEngine;
use std::sync::Arc;
use t3_ipc::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        PowerEventParam, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

#[derive(Debug)]
enum DaemonControlEvent {
    Stop,
    Suspend,
    Resume,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(cmd) = args.get(1).map(|s| s.as_str()) {
        match cmd {
            "install" => return install_service(),
            "uninstall" => return uninstall_service(),
            "status" => return query_service_status(),
            "--console" | "console" => return run_console_mode(),
            "--help" | "-h" => {
                println!("t3Bridge Windows Service Daemon");
                println!("Usage:");
                println!("  t3bridge-service install     Install & start Windows Service (Admin required)");
                println!("  t3bridge-service uninstall   Stop & remove Windows Service (Admin required)");
                println!("  t3bridge-service status      Check Windows Service status");
                println!("  t3bridge-service --console   Run interactively in foreground console");
                return Ok(());
            }
            _ => {}
        }
    }

    #[cfg(windows)]
    {
        // Default entrypoint when launched by Windows Service Control Manager (SCM)
        if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            eprintln!(
                "Failed to connect to Windows Service Control Manager ({}).\n\
                 Hint: Run `t3bridge-service --console` to test interactively, or `t3bridge-service install` as Administrator.",
                e
            );
            std::process::exit(1);
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        run_console_mode()
    }
}

fn run_console_mode() -> anyhow::Result<()> {
    println!("[t3_service] Running in interactive console mode. Press Ctrl+C to stop.");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::unbounded_channel::<DaemonControlEvent>();
        let ctrl_tx_sig = ctrl_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = ctrl_tx_sig.send(DaemonControlEvent::Stop);
        });
        run_engine_loop(ctrl_rx).await;
    });
    Ok(())
}

async fn run_engine_loop(mut ctrl_rx: tokio::sync::mpsc::UnboundedReceiver<DaemonControlEvent>) {
    let engine = ServiceEngine::new();

    // Start Named Pipe IPC Server so the System Tray UI can talk to us immediately
    let ipc_engine = Arc::clone(&engine);
    tokio::spawn(async move {
        ipc_server::run_ipc_server(ipc_engine).await;
    });

    // Option 3: Start Network Interface / Route Change Monitor (Wi-Fi <-> Hotspot auto-reconnect)
    let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    network_monitor::spawn_network_change_monitor(net_tx);
    let net_engine = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(reason) = net_rx.recv().await {
            net_engine.on_network_change(reason).await;
        }
    });

    // Auto-start persisted Host or Client mode on Windows boot
    engine.startup_auto_resume().await;

    // Handle SCM Stop / Shutdown / Sleep / Wake events
    while let Some(ev) = ctrl_rx.recv().await {
        match ev {
            DaemonControlEvent::Stop => {
                engine.shutdown().await;
                break;
            }
            DaemonControlEvent::Suspend => {
                engine.on_system_suspend().await;
            }
            DaemonControlEvent::Resume => {
                engine.on_system_resume().await;
            }
        }
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_windows_service() {
        eprintln!("[t3_service] Service runtime error: {:?}", e);
    }
}

#[cfg(windows)]
fn run_windows_service() -> anyhow::Result<()> {
    let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::unbounded_channel::<DaemonControlEvent>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = ctrl_tx.send(DaemonControlEvent::Stop);
                ServiceControlHandlerResult::NoError
            }
            // Option 2: Windows Power Events (Sleep / Wake)
            ServiceControl::PowerEvent(power_param) => {
                match power_param {
                    PowerEventParam::Suspend => {
                        let _ = ctrl_tx.send(DaemonControlEvent::Suspend);
                    }
                    PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend => {
                        let _ = ctrl_tx.send(DaemonControlEvent::Resume);
                    }
                    _ => {}
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report RUNNING with STOP, SHUTDOWN, and POWER_EVENT acceptance
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::POWER_EVENT,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_engine_loop(ctrl_rx));

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(windows)]
fn install_service() -> anyhow::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT)?;
    let exe_path = std::env::current_exe()?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = match manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => s,
        Err(_) => manager.open_service(
            SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )?,
    };

    let _ = service.set_description(SERVICE_DESCRIPTION);

    // Configure automatic crash recovery: restart after 5s, 10s, 30s
    let recovery = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: std::time::Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: std::time::Duration::from_secs(10),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: std::time::Duration::from_secs(30),
            },
        ]),
    };
    let _ = service.update_failure_actions(recovery);

    let status = service.query_status()?;
    if status.current_state != ServiceState::Running {
        service.start(&[OsString::new()][0..0])?;
    }

    println!("t3BridgeService installed (AutoStart) and started successfully.");
    Ok(())
}

#[cfg(windows)]
fn uninstall_service() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;

    if let Ok(st) = service.query_status() {
        if st.current_state != ServiceState::Stopped {
            let _ = service.stop();
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    service.delete()?;
    println!("t3BridgeService uninstalled successfully.");
    Ok(())
}

#[cfg(windows)]
fn query_service_status() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(svc) => {
            let st = svc.query_status()?;
            println!("t3BridgeService status: {:?}", st.current_state);
        }
        Err(_) => {
            println!("t3BridgeService is not installed.");
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn install_service() -> anyhow::Result<()> {
    anyhow::bail!("Windows Service installation is only supported on Windows.")
}

#[cfg(not(windows))]
fn uninstall_service() -> anyhow::Result<()> {
    anyhow::bail!("Windows Service removal is only supported on Windows.")
}

#[cfg(not(windows))]
fn query_service_status() -> anyhow::Result<()> {
    println!("Not running on Windows.");
    Ok(())
}
