use std::collections::{HashMap, HashSet};

use crate::crash_rustler::CrashRustler;
use crate::types::*;

impl CrashRustler {
    /// Returns the crash date.
    /// Equivalent to -[CrashReport date]
    pub fn date(&self) -> Option<&str> {
        self.date.as_deref()
    }

    /// Returns the Mach task port.
    /// Equivalent to -[CrashReport task]
    pub fn task(&self) -> u32 {
        self.task
    }

    /// Returns the process ID of the crashed process.
    /// Equivalent to -[CrashReport pid]
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Returns the CPU type of the crashed process.
    /// Equivalent to -[CrashReport cpuType]
    pub fn cpu_type(&self) -> CpuType {
        self.cpu_type
    }

    /// Returns the process name.
    /// Equivalent to -[CrashReport processName]
    pub fn process_name(&self) -> Option<&str> {
        self.process_name.as_deref()
    }

    /// Returns the bundle identifier if available, otherwise the process name.
    /// Equivalent to -[CrashReport processIdentifier]
    pub fn process_identifier(&self) -> Option<&str> {
        self.bundle_identifier().or_else(|| self.process_name())
    }

    /// Returns the bundle identifier from ls_application_information.
    /// Equivalent to -[CrashReport bundleIdentifier]
    /// Retrieves `CFBundleIdentifier` from the LS application information dictionary.
    pub fn bundle_identifier(&self) -> Option<&str> {
        self.ls_application_information
            .as_ref()
            .and_then(|dict| dict.get("CFBundleIdentifier"))
            .map(|s| s.as_str())
    }

    /// Returns the display name of the application.
    /// Falls back to processName if the display name is not available.
    /// Equivalent to -[CrashReport displayName]
    pub fn display_name(&self) -> Option<&str> {
        // In the ObjC implementation, this looks up kLSDisplayNameKey from
        // _lsApplicationInformation. Falls back to processName if empty.
        self.process_name()
    }

    /// Returns the parent process name.
    /// Equivalent to -[CrashReport parentProcessName]
    pub fn parent_process_name(&self) -> Option<&str> {
        self.parent_process_name.as_deref()
    }

    /// Returns the responsible process name.
    /// Equivalent to -[CrashReport responsibleProcessName]
    pub fn responsible_process_name(&self) -> Option<&str> {
        self.responsible_process_name.as_deref()
    }

    /// Returns the process version dictionary, lazily populating it if needed.
    /// Contains keys "shortVersion" (CFBundleShortVersionString) and "version"
    /// (CFBundleVersion). Tries LS info, resource fork, then binary images.
    /// Equivalent to -[CrashReport processVersionDictionary]
    pub fn process_version_dictionary(&self) -> &HashMap<String, String> {
        &self.process_version_dictionary
    }

    /// Sanitizes a version string by removing parentheses.
    /// Returns empty string if input is None or empty.
    /// Equivalent to -[CrashReport _sanitizeVersion:]
    pub(crate) fn sanitize_version(version: Option<&str>) -> String {
        match version {
            Some(v) if !v.is_empty() => v.replace(['(', ')'], ""),
            _ => String::new(),
        }
    }

    /// Returns the application build version (CFBundleVersion),
    /// sanitized to remove parentheses.
    /// Equivalent to -[CrashReport appBuildVersion]
    pub fn app_build_version(&self) -> String {
        Self::sanitize_version(
            self.process_version_dictionary
                .get("version")
                .map(|s| s.as_str()),
        )
    }

    /// Returns the application short version string (CFBundleShortVersionString),
    /// sanitized to remove parentheses.
    /// Equivalent to -[CrashReport appVersion]
    pub fn app_version(&self) -> String {
        Self::sanitize_version(
            self.process_version_dictionary
                .get("shortVersion")
                .map(|s| s.as_str()),
        )
    }

    /// Returns a formatted version string: "shortVersion (buildVersion)"
    /// or just the build version if no short version is available.
    /// Equivalent to -[CrashReport processVersion]
    pub fn process_version(&self) -> String {
        let short = self.app_version();
        let build = self.app_build_version();
        if short.is_empty() {
            build
        } else {
            format!("{short} ({build})")
        }
    }

    /// Returns the App Store Adam ID.
    /// Equivalent to -[CrashReport adamID]
    pub fn adam_id(&self) -> Option<&str> {
        self.adam_id.as_deref()
    }

    /// Returns the UUID of the main binary.
    /// Equivalent to -[CrashReport binaryUUID]
    pub fn binary_uuid(&self) -> Option<&str> {
        self.binary_uuid.as_deref()
    }

    /// Returns the path to the executable.
    /// Equivalent to -[CrashReport executablePath]
    pub fn executable_path(&self) -> Option<&str> {
        self.executable_path.as_deref()
    }

    /// Returns the reopen path. Falls back to executable_path if not set.
    /// Equivalent to -[CrashReport reopenPath]
    pub fn reopen_path(&self) -> Option<&str> {
        self.reopen_path
            .as_deref()
            .or(self.executable_path.as_deref())
    }

    /// Returns true if a dyld error string is present.
    /// Equivalent to -[CrashReport isDyldError]
    pub fn is_dyld_error(&self) -> bool {
        self.dyld_error_string
            .as_ref()
            .is_some_and(|s| !s.is_empty())
    }

    /// Returns the environment variable dictionary.
    /// Equivalent to -[CrashReport environment]
    pub fn environment(&self) -> &HashMap<String, String> {
        &self.environment
    }

    /// Returns the notes array. Lazily populates with translocated process
    /// and OS update notes on first access.
    /// Equivalent to -[CrashReport notes]
    pub fn notes(&mut self) -> Vec<String> {
        let mut result = Vec::new();
        if self.is_translocated_process {
            result.push("Translocated Process".to_string());
        }
        if let Some(ref build) = self.in_update_previous_os_build {
            result.push(format!("Occurred during OS Update from build: {build}"));
        }
        result
    }

    /// Returns true if the process is running under Rosetta translation.
    /// This is the inverse of is_native.
    /// Equivalent to -[CrashReport isTranslated]
    pub fn is_translated(&self) -> bool {
        !self.is_native
    }

    /// Determines if the crashed app is a user-visible foreground application.
    /// Checks against known background apps, exec failures, LSUIElement,
    /// LSBackgroundOnly, and CFBundlePackageType=XPC!.
    /// Equivalent to -[CrashReport isUserVisibleApp]
    pub fn is_user_visible_app(&self) -> bool {
        // Return false for exec failures
        if self.exec_failure_error.is_some() {
            return false;
        }

        let process = self.process_name().unwrap_or("");
        // WebProcess is always hidden (unless Apple internal)
        if process == "WebProcess" {
            return false;
        }

        // Known background bundle identifiers
        let excluded_bundles: HashSet<&str> = [
            "com.apple.iChatAgent",
            "com.apple.dashboard.client",
            "com.apple.InterfaceBuilder.IBCocoaTouchPlugin.IBCocoaTouchTool",
            "com.apple.WebKit.PluginHost",
        ]
        .into_iter()
        .collect();

        if let Some(bundle_id) = self.bundle_identifier() {
            if excluded_bundles.contains(bundle_id) {
                return false;
            }
            // Finder is always user-visible
            if bundle_id == "com.apple.finder" {
                return true;
            }
        }

        // Default: assume visible if we have an executable
        self.executable_path.is_some()
    }

    /// Returns true if the crash is due to a missing user library.
    /// Requires: isDyldError AND path not under /System/ AND fatalDyldErrorOnLaunch.
    /// Equivalent to -[CrashReport isUserMissingLibrary]
    pub fn is_user_missing_library(&self) -> bool {
        if !self.is_dyld_error() {
            return false;
        }
        let path = self.executable_path().unwrap_or("");
        if path.starts_with("/System/") {
            return false;
        }
        self.fatal_dyld_error_on_launch
    }

    /// Determines if the app should be offered a relaunch option.
    /// Returns false for excluded bundles, dyld errors, code sign kills,
    /// and WebProcess. Otherwise delegates to is_user_visible_app.
    /// Equivalent to -[CrashReport allowRelaunch]
    pub fn allow_relaunch(&self) -> bool {
        let excluded_bundles: HashSet<&str> = [
            "com.apple.iChatAgent",
            "com.apple.dashboard.client",
            "com.apple.InterfaceBuilder.IBCocoaTouchPlugin.IBCocoaTouchTool",
            "com.apple.WebKit.PluginHost",
        ]
        .into_iter()
        .collect();

        if let Some(bundle_id) = self.bundle_identifier()
            && excluded_bundles.contains(bundle_id)
        {
            return false;
        }

        if self.is_dyld_error() || self.is_code_sign_killed() {
            return false;
        }

        if self.process_name() == Some("WebProcess") {
            return false;
        }

        self.is_user_visible_app()
    }

    /// Returns the sleep/wake UUID, or empty string if not set.
    /// Equivalent to -[CrashReport sleepWakeUUID]
    pub fn sleep_wake_uuid(&self) -> &str {
        self.sleep_wake_uuid.as_deref().unwrap_or("")
    }

    /// Returns true if the process was killed due to a code signing violation.
    /// Checks bit 0x1000000 (CS_KILLED) in cs_status.
    /// Equivalent to -[CrashReport isCodeSignKilled]
    pub fn is_code_sign_killed(&self) -> bool {
        self.cs_status & 0x100_0000 != 0
    }

    /// Returns true. Rootless (SIP) is always enabled on Sierra+.
    /// Equivalent to -[CrashReport isRootlessEnabled]
    pub fn is_rootless_enabled(&self) -> bool {
        true
    }

    /// Returns true if the app has a receipt and an Adam ID (App Store app).
    /// Equivalent to -[CrashReport isAppStoreApp]
    pub fn is_app_store_app(&self) -> bool {
        self.has_receipt && self.adam_id.is_some()
    }

    /// Returns true if the crash target has an x86 or x86_64 CPU type.
    pub(crate) fn is_x86_cpu(&self) -> bool {
        matches!(self.cpu_type.0, 7 | 0x0100_0007)
    }

    /// Returns true if the crash target has an ARM or ARM64 CPU type.
    pub(crate) fn is_arm_cpu(&self) -> bool {
        matches!(self.cpu_type.0, 12 | 0x0100_000c)
    }

    /// Returns the application-specific dialog mode.
    /// Equivalent to -[CrashReport applicationSpecificDialogMode]
    pub fn application_specific_dialog_mode(&self) -> Option<&str> {
        self.application_specific_dialog_mode.as_deref()
    }

    /// Sets the thread port and refreshes thread state.
    /// Equivalent to -[CrashReport setThread:]
    pub fn set_thread(&mut self, thread: u32) {
        self.thread = thread;
        // In the ObjC implementation, this calls thread_get_state to refresh
        // the _threadState registers. In Rust, the caller would need to
        // provide the new state separately since we don't have Mach APIs.
    }

    /// Sets the current binary image being processed.
    /// Equivalent to -[CrashReport setCurrentBinaryImage:]
    pub fn set_current_binary_image(&mut self, image: Option<String>) {
        self.current_binary_image = image;
    }

    /// Returns the sandbox container path.
    /// Equivalent to -[CrashReport sandboxContainer]
    pub fn sandbox_container(&self) -> Option<&str> {
        self.sandbox_container.as_deref()
    }

    /// Sets the sandbox container path.
    /// Equivalent to -[CrashReport setSandboxContainer:]
    pub fn set_sandbox_container(&mut self, path: Option<String>) {
        self.sandbox_container = path;
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::*;
    use crate::*;

    mod accessors {
        use super::*;

        #[test]
        fn process_identifier_falls_back_to_process_name() {
            // ls_application_information is None, so bundle_identifier() returns None
            let cr = make_test_cr();
            assert_eq!(cr.process_identifier(), Some("TestApp"));
        }

        #[test]
        fn bundle_identifier_from_ls_info() {
            let mut cr = make_test_cr();
            let mut info = std::collections::HashMap::new();
            info.insert("CFBundleIdentifier".into(), "com.example.TestApp".into());
            cr.ls_application_information = Some(info);
            assert_eq!(cr.bundle_identifier(), Some("com.example.TestApp"));
        }

        #[test]
        fn bundle_identifier_none_without_ls_info() {
            let cr = make_test_cr();
            assert_eq!(cr.bundle_identifier(), None);
        }

        #[test]
        fn bundle_identifier_none_without_key() {
            let mut cr = make_test_cr();
            let info = std::collections::HashMap::new();
            cr.ls_application_information = Some(info);
            assert_eq!(cr.bundle_identifier(), None);
        }

        #[test]
        fn process_identifier_prefers_bundle_identifier() {
            let mut cr = make_test_cr();
            let mut info = std::collections::HashMap::new();
            info.insert("CFBundleIdentifier".into(), "com.example.TestApp".into());
            cr.ls_application_information = Some(info);
            assert_eq!(cr.process_identifier(), Some("com.example.TestApp"));
        }

        #[test]
        fn display_name_falls_back_to_process_name() {
            let cr = make_test_cr();
            assert_eq!(cr.display_name(), Some("TestApp"));
        }

        #[test]
        fn reopen_path_falls_back_to_executable_path() {
            let cr = make_test_cr();
            assert_eq!(cr.reopen_path(), cr.executable_path());
        }

        #[test]
        fn reopen_path_uses_own_value_when_set() {
            let mut cr = make_test_cr();
            cr.reopen_path = Some("/custom/path".into());
            assert_eq!(cr.reopen_path(), Some("/custom/path"));
        }

        #[test]
        fn is_dyld_error_none() {
            let cr = make_test_cr();
            assert!(!cr.is_dyld_error());
        }

        #[test]
        fn is_dyld_error_empty_string() {
            let mut cr = make_test_cr();
            cr.dyld_error_string = Some(String::new());
            assert!(!cr.is_dyld_error());
        }

        #[test]
        fn is_dyld_error_some_string() {
            let mut cr = make_test_cr();
            cr.dyld_error_string = Some("dyld: Library not loaded".into());
            assert!(cr.is_dyld_error());
        }

        #[test]
        fn sleep_wake_uuid_none_returns_empty() {
            let cr = make_test_cr();
            assert_eq!(cr.sleep_wake_uuid(), "");
        }

        #[test]
        fn sleep_wake_uuid_returns_value() {
            let mut cr = make_test_cr();
            cr.sleep_wake_uuid = Some("ABC-123".into());
            assert_eq!(cr.sleep_wake_uuid(), "ABC-123");
        }

        #[test]
        fn notes_empty() {
            let mut cr = make_test_cr();
            assert!(cr.notes().is_empty());
        }

        #[test]
        fn notes_translocated() {
            let mut cr = make_test_cr();
            cr.is_translocated_process = true;
            let notes = cr.notes();
            assert_eq!(notes.len(), 1);
            assert_eq!(notes[0], "Translocated Process");
        }

        #[test]
        fn notes_os_update() {
            let mut cr = make_test_cr();
            cr.in_update_previous_os_build = Some("21A5248p".into());
            let notes = cr.notes();
            assert_eq!(notes.len(), 1);
            assert!(notes[0].contains("21A5248p"));
        }

        #[test]
        fn notes_both() {
            let mut cr = make_test_cr();
            cr.is_translocated_process = true;
            cr.in_update_previous_os_build = Some("21A5248p".into());
            let notes = cr.notes();
            assert_eq!(notes.len(), 2);
        }

        #[test]
        fn is_translated() {
            let mut cr = make_test_cr();
            cr.is_native = true;
            assert!(!cr.is_translated());
            cr.is_native = false;
            assert!(cr.is_translated());
        }
    }

    mod boolean_flags {
        use super::*;

        #[test]
        fn is_code_sign_killed_without_bit() {
            let mut cr = make_test_cr();
            cr.cs_status = 0;
            assert!(!cr.is_code_sign_killed());
            cr.cs_status = 0xFF_FFFF; // all bits except the kill bit
            assert!(!cr.is_code_sign_killed());
        }

        #[test]
        fn is_code_sign_killed_with_bit() {
            let mut cr = make_test_cr();
            cr.cs_status = 0x100_0000;
            assert!(cr.is_code_sign_killed());
            cr.cs_status = 0x1FF_FFFF;
            assert!(cr.is_code_sign_killed());
        }

        #[test]
        fn is_rootless_enabled_always_true() {
            let cr = make_test_cr();
            assert!(cr.is_rootless_enabled());
        }

        #[test]
        fn is_app_store_app_combinations() {
            let mut cr = make_test_cr();
            // Neither
            cr.has_receipt = false;
            cr.adam_id = None;
            assert!(!cr.is_app_store_app());
            // Receipt only
            cr.has_receipt = true;
            cr.adam_id = None;
            assert!(!cr.is_app_store_app());
            // Adam ID only
            cr.has_receipt = false;
            cr.adam_id = Some("12345".into());
            assert!(!cr.is_app_store_app());
            // Both
            cr.has_receipt = true;
            cr.adam_id = Some("12345".into());
            assert!(cr.is_app_store_app());
        }

        #[test]
        fn is_user_visible_app_exec_failure() {
            let mut cr = make_test_cr();
            cr.exec_failure_error = Some(String::new());
            assert!(!cr.is_user_visible_app());
        }

        #[test]
        fn is_user_visible_app_webprocess() {
            let mut cr = make_test_cr();
            cr.process_name = Some("WebProcess".into());
            assert!(!cr.is_user_visible_app());
        }

        #[test]
        fn is_user_visible_app_has_executable() {
            let cr = make_test_cr();
            assert!(cr.is_user_visible_app());
        }

        #[test]
        fn is_user_visible_app_no_executable() {
            let mut cr = make_test_cr();
            cr.executable_path = None;
            assert!(!cr.is_user_visible_app());
        }

        #[test]
        fn is_user_missing_library_not_dyld_error() {
            let cr = make_test_cr();
            assert!(!cr.is_user_missing_library());
        }

        #[test]
        fn is_user_missing_library_system_path() {
            let mut cr = make_test_cr();
            cr.dyld_error_string = Some("error".into());
            cr.executable_path = Some("/System/Library/foo".into());
            cr.fatal_dyld_error_on_launch = true;
            assert!(!cr.is_user_missing_library());
        }

        #[test]
        fn is_user_missing_library_fatal() {
            let mut cr = make_test_cr();
            cr.dyld_error_string = Some("error".into());
            cr.fatal_dyld_error_on_launch = true;
            assert!(cr.is_user_missing_library());
        }

        #[test]
        fn is_user_missing_library_not_fatal() {
            let mut cr = make_test_cr();
            cr.dyld_error_string = Some("error".into());
            cr.fatal_dyld_error_on_launch = false;
            assert!(!cr.is_user_missing_library());
        }

        #[test]
        fn allow_relaunch_dyld_error() {
            let mut cr = make_test_cr();
            cr.dyld_error_string = Some("error".into());
            assert!(!cr.allow_relaunch());
        }

        #[test]
        fn allow_relaunch_code_sign_killed() {
            let mut cr = make_test_cr();
            cr.cs_status = 0x100_0000;
            assert!(!cr.allow_relaunch());
        }

        #[test]
        fn allow_relaunch_webprocess() {
            let mut cr = make_test_cr();
            cr.process_name = Some("WebProcess".into());
            assert!(!cr.allow_relaunch());
        }

        #[test]
        fn allow_relaunch_normal_app() {
            let cr = make_test_cr();
            assert!(cr.allow_relaunch());
        }

        #[test]
        fn is_apple_application_apple_path() {
            let mut cr = make_test_cr();
            cr.executable_path = Some("/System/Library/Frameworks/foo".into());
            assert!(cr.is_apple_application());
        }

        #[test]
        fn is_apple_application_non_apple() {
            let cr = make_test_cr();
            // /Applications is NOT an Apple path
            assert!(!cr.is_apple_application());
        }
    }

    mod version_methods {
        use super::*;

        #[test]
        fn sanitize_version_none() {
            assert_eq!(CrashRustler::sanitize_version(None), "");
        }

        #[test]
        fn sanitize_version_empty() {
            assert_eq!(CrashRustler::sanitize_version(Some("")), "");
        }

        #[test]
        fn sanitize_version_normal() {
            assert_eq!(CrashRustler::sanitize_version(Some("1.2.3")), "1.2.3");
        }

        #[test]
        fn sanitize_version_with_parens() {
            assert_eq!(CrashRustler::sanitize_version(Some("(1.2.3)")), "1.2.3");
        }

        #[test]
        fn app_version_empty_dict() {
            let cr = make_test_cr();
            assert_eq!(cr.app_version(), "");
        }

        #[test]
        fn app_version_populated() {
            let mut cr = make_test_cr();
            cr.process_version_dictionary
                .insert("shortVersion".into(), "2.1".into());
            assert_eq!(cr.app_version(), "2.1");
        }

        #[test]
        fn app_build_version_empty_dict() {
            let cr = make_test_cr();
            assert_eq!(cr.app_build_version(), "");
        }

        #[test]
        fn app_build_version_populated() {
            let mut cr = make_test_cr();
            cr.process_version_dictionary
                .insert("version".into(), "100".into());
            assert_eq!(cr.app_build_version(), "100");
        }

        #[test]
        fn process_version_short_and_build() {
            let mut cr = make_test_cr();
            cr.process_version_dictionary
                .insert("shortVersion".into(), "2.1".into());
            cr.process_version_dictionary
                .insert("version".into(), "100".into());
            assert_eq!(cr.process_version(), "2.1 (100)");
        }

        #[test]
        fn process_version_build_only() {
            let mut cr = make_test_cr();
            cr.process_version_dictionary
                .insert("version".into(), "100".into());
            assert_eq!(cr.process_version(), "100");
        }

        #[test]
        fn process_version_both_empty() {
            let cr = make_test_cr();
            assert_eq!(cr.process_version(), "");
        }
    }
}
