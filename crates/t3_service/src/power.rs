use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
extern "system" {
    fn SetThreadExecutionState(es_flags: u32) -> u32;
}

#[cfg(windows)]
const ES_SYSTEM_REQUIRED: u32 = 0x00000001;
#[cfg(windows)]
const ES_AWAYMODE_REQUIRED: u32 = 0x00000040;
#[cfg(windows)]
const ES_CONTINUOUS: u32 = 0x80000000;

/// Option 1: Controls Windows sleep prevention (`SetThreadExecutionState`) for Host Mode.
/// Uses a dedicated OS thread because `SetThreadExecutionState` is thread-affine on Windows.
pub struct SleepPreventionController {
    active: Arc<AtomicBool>,
}

impl SleepPreventionController {
    pub fn new() -> Self {
        let active = Arc::new(AtomicBool::new(false));
        let active_clone = Arc::clone(&active);

        std::thread::spawn(move || {
            let mut currently_prevented = false;
            loop {
                let should_prevent = active_clone.load(Ordering::SeqCst);
                if should_prevent {
                    #[cfg(windows)]
                    unsafe {
                        // Keeps system & network awake; allows monitor/display to turn off normally.
                        SetThreadExecutionState(
                            ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED,
                        );
                    }
                    currently_prevented = true;
                } else if currently_prevented {
                    #[cfg(windows)]
                    unsafe {
                        // Release sleep inhibition cleanly.
                        SetThreadExecutionState(ES_CONTINUOUS);
                    }
                    currently_prevented = false;
                }
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        });

        Self { active }
    }

    pub fn set_prevent_sleep(&self, enable: bool) {
        self.active.store(enable, Ordering::SeqCst);
        // Apply immediately on current thread as well for zero-delay transitions
        #[cfg(windows)]
        unsafe {
            if enable {
                SetThreadExecutionState(ES_SYSTEM_REQUIRED);
            }
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}

impl Default for SleepPreventionController {
    fn default() -> Self {
        Self::new()
    }
}
