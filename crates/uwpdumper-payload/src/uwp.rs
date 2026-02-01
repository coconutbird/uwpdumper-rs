//! UWP Package information retrieval using Windows APIs

use std::path::PathBuf;
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::Storage::Packaging::Appx::{
    GetCurrentPackageFamilyName, GetCurrentPackageFullName, GetCurrentPackagePath,
};
use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{Error, PWSTR, Result};

/// Macro for Windows APIs that follow the "call once for size, call again for data" pattern.
/// Works with GetCurrentPackageFamilyName, GetCurrentPackageFullName, GetCurrentPackagePath, etc.
macro_rules! get_package_string {
    ($api_fn:ident) => {{
        // First call: get required buffer size
        let mut length = 0u32;
        let result = unsafe { $api_fn(&mut length, None) };

        // ERROR_INSUFFICIENT_BUFFER is expected - it means we got the size
        if result != ERROR_INSUFFICIENT_BUFFER && result.0 != 0 {
            Err(Error::from(windows::core::HRESULT::from_win32(result.0)))
        } else if length == 0 {
            Err(Error::from(windows::core::HRESULT::from_win32(result.0)))
        } else {
            // Second call: get the actual data
            let mut buffer: Vec<u16> = vec![0; length as usize];
            let result = unsafe { $api_fn(&mut length, Some(PWSTR(buffer.as_mut_ptr()))) };

            if result.0 != 0 {
                Err(Error::from(windows::core::HRESULT::from_win32(result.0)))
            } else {
                // Convert to String (exclude null terminator)
                Ok(String::from_utf16_lossy(&buffer[..length as usize - 1]))
            }
        }
    }};
}

/// Information about the current UWP package (the process we're injected into)
#[derive(Debug, Clone)]
pub struct CurrentPackage {
    pub family_name: String,
    pub full_name: String,
    pub package_path: PathBuf,
}

impl CurrentPackage {
    /// Get information about the current UWP package
    pub fn current() -> Result<Self> {
        Ok(Self {
            family_name: get_package_string!(GetCurrentPackageFamilyName)?,
            full_name: get_package_string!(GetCurrentPackageFullName)?,
            package_path: PathBuf::from(get_package_string!(GetCurrentPackagePath)?),
        })
    }
}

/// Get the TempState folder path for the current package
pub fn get_temp_state_path() -> Result<PathBuf> {
    let local_app_data = get_local_app_data_path()?;
    let family_name: String = get_package_string!(GetCurrentPackageFamilyName)?;

    let path = local_app_data
        .join("Packages")
        .join(&family_name)
        .join("TempState");

    Ok(path)
}

/// Get the LocalAppData folder path using Shell API
fn get_local_app_data_path() -> Result<PathBuf> {
    unsafe {
        let path_ptr = SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None)?;
        let path_str = path_ptr.to_string()?;
        windows::Win32::System::Com::CoTaskMemFree(Some(path_ptr.0 as *const _));
        Ok(PathBuf::from(path_str))
    }
}
