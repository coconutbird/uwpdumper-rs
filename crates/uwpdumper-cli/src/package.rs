//! UWP Package enumeration and launching

use std::process::Command;
use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::UI::Shell::{ACTIVATEOPTIONS, IApplicationActivationManager};
use windows::core::{GUID, HRESULT};

/// Error type for package operations
#[derive(Debug)]
pub enum PackageError {
    /// PowerShell is not available or failed to execute
    PowerShellUnavailable(String),
    /// PowerShell command failed with an error
    PowerShellFailed(String),
    /// Windows API error
    WindowsError(windows::core::Error),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageError::PowerShellUnavailable(msg) => {
                write!(
                    f,
                    "PowerShell unavailable: {}. Try running UWP processes manually and use --pid or --name instead.",
                    msg
                )
            }
            PackageError::PowerShellFailed(msg) => {
                write!(f, "PowerShell command failed: {}", msg)
            }
            PackageError::WindowsError(e) => write!(f, "Windows error: {}", e),
        }
    }
}

impl std::error::Error for PackageError {}

impl From<windows::core::Error> for PackageError {
    fn from(e: windows::core::Error) -> Self {
        PackageError::WindowsError(e)
    }
}

/// Information about an installed UWP package
#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub name: String,
    pub display_name: String,
    pub family_name: String,
    pub app_id: String, // The Application ID from manifest (e.g., "App" or "HaloWars2")
}

/// List all installed UWP packages
pub fn list_packages() -> Result<Vec<InstalledPackage>, PackageError> {
    // Use PowerShell to enumerate packages with display names and app IDs from manifest
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Get-AppxPackage | ForEach-Object {
                $manifest = Get-AppxPackageManifest -Package $_.PackageFullName -ErrorAction SilentlyContinue
                $displayName = if ($manifest) { $manifest.Package.Properties.DisplayName } else { $_.Name }
                # Resolve ms-resource: strings
                if ($displayName -like 'ms-resource:*') { $displayName = $_.Name }
                # Get the first Application ID from manifest
                $appId = if ($manifest) { $manifest.Package.Applications.Application.Id | Select-Object -First 1 } else { 'App' }
                if (-not $appId) { $appId = 'App' }
                $_.Name + '|' + $displayName + '|' + $_.PackageFamilyName + '|' + $appId
            }"#,
        ])
        .output()
        .map_err(|e| PackageError::PowerShellUnavailable(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("is not recognized") || stderr.contains("not found") {
            return Err(PackageError::PowerShellUnavailable(
                "PowerShell is not in PATH".to_string(),
            ));
        }
        return Err(PackageError::PowerShellFailed(stderr.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut packages = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 4 {
            packages.push(InstalledPackage {
                name: parts[0].to_string(),
                display_name: parts[1].to_string(),
                family_name: parts[2].to_string(),
                app_id: parts[3].to_string(),
            });
        }
    }

    Ok(packages)
}

/// Find a package by name (partial match, case-insensitive)
pub fn find_package(name: &str) -> Result<Option<InstalledPackage>, PackageError> {
    let packages = list_packages()?;
    let name_lower = name.to_lowercase();
    Ok(packages
        .into_iter()
        .find(|p| p.name.to_lowercase().contains(&name_lower)))
}

// CLSID for ApplicationActivationManager
const CLSID_APPLICATION_ACTIVATION_MANAGER: GUID =
    GUID::from_u128(0x45BA127D_10A8_46EA_8AB7_56EA9078943C);

/// Launch a UWP app and return its process ID
pub fn launch_package(pkg: &InstalledPackage) -> Result<u32, PackageError> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .map_err(|e| {
                PackageError::WindowsError(windows::core::Error::new(
                    HRESULT(e.code().0),
                    e.message(),
                ))
            })?;

        let aam: IApplicationActivationManager = CoCreateInstance(
            &CLSID_APPLICATION_ACTIVATION_MANAGER,
            None,
            CLSCTX_LOCAL_SERVER,
        )?;

        // App User Model ID is FamilyName!ApplicationId
        let aumid = format!("{}!{}", pkg.family_name, pkg.app_id);
        let aumid_wide: Vec<u16> = aumid.encode_utf16().chain(std::iter::once(0)).collect();

        let pid = aam.ActivateApplication(
            windows::core::PCWSTR(aumid_wide.as_ptr()),
            None,
            ACTIVATEOPTIONS(0),
        )?;

        Ok(pid)
    }
}
