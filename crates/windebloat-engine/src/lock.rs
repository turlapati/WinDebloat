use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConcurrencyError {
    #[error("Another WinDebloat instance is currently running (Global\\WinDebloat.Run mutex is held)")]
    AlreadyRunning,
    #[error("Failed to acquire run lock: {0}")]
    OsError(String),
}

/// Ensures only one WinDebloat run occurs at a time per machine (§4.3).
pub struct RunLockGuard {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
}

impl RunLockGuard {
    pub fn acquire() -> Result<Self, ConcurrencyError> {
        #[cfg(windows)]
        unsafe {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
            use windows::Win32::System::Threading::CreateMutexW;

            let global_name: Vec<u16> = "Global\\WinDebloat.Run\0".encode_utf16().collect();
            let local_name: Vec<u16> = "Local\\WinDebloat.Run\0".encode_utf16().collect();

            let handle = match CreateMutexW(None, true, PCWSTR(global_name.as_ptr())) {
                Ok(h) => h,
                Err(_) if GetLastError() == ERROR_ACCESS_DENIED => {
                    CreateMutexW(None, true, PCWSTR(local_name.as_ptr()))
                        .map_err(|e| ConcurrencyError::OsError(e.to_string()))?
                }
                Err(e) => return Err(ConcurrencyError::OsError(e.to_string())),
            };

            if GetLastError() == ERROR_ALREADY_EXISTS {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
                return Err(ConcurrencyError::AlreadyRunning);
            }

            Ok(Self { handle })
        }

        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }
}

#[cfg(windows)]
impl Drop for RunLockGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::System::Threading::ReleaseMutex(self.handle);
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}
