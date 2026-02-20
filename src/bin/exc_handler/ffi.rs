//! Consolidated FFI bindings for Mach kernel, POSIX process control, and memory access.
//!
//! All FFI is isolated in the binary crate — the library has zero FFI calls.

#![allow(dead_code)]

use std::ffi::{c_char, c_int, c_void};

// ============================================================================
// Mach types
// ============================================================================

pub type MachPortT = u32;
pub type KernReturnT = c_int;
pub type MachVmAddressT = u64;
pub type MachVmSizeT = u64;
pub type VmMapT = MachPortT;
pub type VmAddressT = usize;
pub type MachMsgTypeNumberT = u32;
pub type NaturalT = u32;
pub type MachMsgBitsT = u32;
pub type MachMsgSizeT = u32;
pub type MachMsgIdT = i32;

pub const KERN_SUCCESS: KernReturnT = 0;

/// Mach port rights
pub const MACH_PORT_RIGHT_RECEIVE: c_int = 1;
pub const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;

/// Special port index for bootstrap port
pub const TASK_BOOTSTRAP_PORT: c_int = 4;

/// Mach message options
pub const MACH_MSG_TIMEOUT_NONE: u32 = 0;
pub const MACH_SEND_MSG: c_int = 0x0000_0001;
pub const MACH_RCV_MSG: c_int = 0x0000_0002;
pub const MACH_RCV_LARGE: c_int = 0x0000_0004;
pub const MACH_RCV_TIMEOUT: c_int = 0x0000_0100;

/// mach_msg return code when MACH_RCV_TIMEOUT expires.
pub const MACH_RCV_TIMED_OUT: KernReturnT = 0x1000_4003;

/// Exception masks
pub const EXC_MASK_BAD_ACCESS: u32 = 1 << 1;
pub const EXC_MASK_BAD_INSTRUCTION: u32 = 1 << 2;
pub const EXC_MASK_ARITHMETIC: u32 = 1 << 3;
pub const EXC_MASK_BREAKPOINT: u32 = 1 << 6;
pub const EXC_MASK_SOFTWARE: u32 = 1 << 5;
pub const EXC_MASK_CRASH: u32 = 1 << 10;

/// Combined mask for all exceptions we handle
pub const EXC_MASK_ALL: u32 = EXC_MASK_BAD_ACCESS
    | EXC_MASK_BAD_INSTRUCTION
    | EXC_MASK_ARITHMETIC
    | EXC_MASK_BREAKPOINT
    | EXC_MASK_SOFTWARE
    | EXC_MASK_CRASH;

/// Exception behavior flags
pub const EXCEPTION_STATE_IDENTITY: c_int = 3;
pub const MACH_EXCEPTION_CODES: c_int = 0x80000000u32 as c_int;

/// Thread state flavors
#[cfg(target_arch = "x86_64")]
pub const THREAD_STATE_FLAVOR: c_int = 7; // x86_THREAD_STATE
#[cfg(target_arch = "aarch64")]
pub const THREAD_STATE_FLAVOR: c_int = 6; // ARM_THREAD_STATE64

#[cfg(target_arch = "x86_64")]
pub const EXCEPTION_STATE_FLAVOR: c_int = 9;
#[cfg(target_arch = "x86_64")]
pub const EXCEPTION_STATE_COUNT: MachMsgTypeNumberT = 6;

#[cfg(target_arch = "aarch64")]
pub const EXCEPTION_STATE_FLAVOR: c_int = 3; // ARM_EXCEPTION_STATE64
#[cfg(target_arch = "aarch64")]
pub const EXCEPTION_STATE_COUNT: MachMsgTypeNumberT = 4;

pub const THREAD_STATE_MAX: usize = 614;

/// task_info flavor for dyld image info
pub const TASK_DYLD_INFO: c_int = 17;

/// thread_info flavor for thread identifier
pub const THREAD_IDENTIFIER_INFO: c_int = 4;

// ============================================================================
// Mach message structures
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MachMsgHeaderT {
    pub msgh_bits: MachMsgBitsT,
    pub msgh_size: MachMsgSizeT,
    pub msgh_remote_port: MachPortT,
    pub msgh_local_port: MachPortT,
    pub msgh_voucher_port: MachPortT,
    pub msgh_id: MachMsgIdT,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MachMsgBodyT {
    pub msgh_descriptor_count: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MachMsgPortDescriptorT {
    pub name: MachPortT,
    pub pad1: u32,
    pub pad2: u16,
    pub disposition: u8,
    pub msg_type: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NDRRecordT {
    pub mig_vers: u8,
    pub if_vers: u8,
    pub reserved1: u8,
    pub mig_encoding: u8,
    pub int_rep: u8,
    pub char_rep: u8,
    pub float_rep: u8,
    pub reserved2: u8,
}

pub const NDR_RECORD: NDRRecordT = NDRRecordT {
    mig_vers: 0,
    if_vers: 0,
    reserved1: 0,
    mig_encoding: 0,
    int_rep: 1, // little-endian
    char_rep: 0,
    float_rep: 0,
    reserved2: 0,
};

#[repr(C)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

// ============================================================================
// POSIX types
// ============================================================================

pub const PROC_PIDTBSDINFO: c_int = 3;

#[repr(C)]
pub struct ProcBsdInfo {
    pub pbi_flags: u32,
    pub pbi_status: u32,
    pub pbi_xstatus: u32,
    pub pbi_pid: u32,
    pub pbi_ppid: u32,
    pub pbi_uid: u32,
    pub pbi_gid: u32,
    pub pbi_ruid: u32,
    pub pbi_rgid: u32,
    pub pbi_svuid: u32,
    pub pbi_svgid: u32,
    pub _reserved: u32,
    pub pbi_comm: [u8; 16],
    pub pbi_name: [u8; 32],
    pub pbi_nfiles: u32,
    pub pbi_pgid: u32,
    pub pbi_pjobc: u32,
    pub e_tdev: u32,
    pub e_tpgid: u32,
    pub pbi_nice: i16,
    pub pbi_start_tvsec: u64,
    pub pbi_start_tvusec: u64,
}

// ============================================================================
// Signal constants
// ============================================================================

pub const SIGUSR1: c_int = 30;
pub const SIGUSR2: c_int = 31;
pub const SIGTERM: c_int = 15;
pub const SIGKILL: c_int = 9;
pub const SIGCHLD: c_int = 20;
pub const SIG_IGN: usize = 1;

// ============================================================================
// FFI extern functions
// ============================================================================

unsafe extern "C" {
    // --- Mach port management ---
    pub fn mach_port_allocate(task: MachPortT, right: c_int, name: *mut MachPortT) -> KernReturnT;

    pub fn mach_port_insert_right(
        task: MachPortT,
        name: MachPortT,
        poly: MachPortT,
        poly_poly: u32,
    ) -> KernReturnT;

    pub fn mach_port_deallocate(task: MachPortT, name: MachPortT) -> KernReturnT;

    pub fn mach_port_destroy(task: MachPortT, name: MachPortT) -> KernReturnT;

    // --- Exception ports ---
    pub fn task_set_exception_ports(
        task: MachPortT,
        exception_mask: u32,
        new_port: MachPortT,
        behavior: c_int,
        new_flavor: c_int,
    ) -> KernReturnT;

    // task_get_bootstrap_port / task_set_bootstrap_port are macros in
    // <mach/task_special_ports.h> that expand to these with TASK_BOOTSTRAP_PORT.
    pub fn task_get_special_port(
        task: MachPortT,
        which_port: c_int,
        special_port: *mut MachPortT,
    ) -> KernReturnT;

    pub fn task_set_special_port(
        task: MachPortT,
        which_port: c_int,
        special_port: MachPortT,
    ) -> KernReturnT;

    // --- Messaging ---
    pub fn mach_msg(
        msg: *mut MachMsgHeaderT,
        option: c_int,
        send_size: MachMsgSizeT,
        rcv_size: MachMsgSizeT,
        rcv_name: MachPortT,
        timeout: u32,
        notify: MachPortT,
    ) -> KernReturnT;

    // --- Process memory ---
    pub fn mach_vm_read(
        target_task: VmMapT,
        address: MachVmAddressT,
        size: MachVmSizeT,
        data: *mut VmAddressT,
        data_cnt: *mut MachMsgTypeNumberT,
    ) -> KernReturnT;

    pub fn mach_vm_region_recurse(
        target_task: VmMapT,
        address: *mut MachVmAddressT,
        size: *mut MachVmSizeT,
        nesting_depth: *mut NaturalT,
        info: *mut c_int,
        info_cnt: *mut MachMsgTypeNumberT,
    ) -> KernReturnT;

    pub fn vm_deallocate(
        target_task: VmMapT,
        address: VmAddressT,
        size: MachVmSizeT,
    ) -> KernReturnT;

    pub fn mach_task_self() -> MachPortT;

    pub static vm_page_size: MachVmSizeT;

    // --- Process info ---
    pub fn pid_for_task(task: MachPortT, pid: *mut i32) -> KernReturnT;

    pub fn task_for_pid(target_tport: MachPortT, pid: i32, task: *mut MachPortT) -> KernReturnT;

    pub fn thread_get_state(
        target_act: MachPortT,
        flavor: c_int,
        old_state: *mut u32,
        old_state_count: *mut MachMsgTypeNumberT,
    ) -> KernReturnT;

    pub fn task_threads(
        target_task: MachPortT,
        act_list: *mut *mut MachPortT,
        act_list_cnt: *mut MachMsgTypeNumberT,
    ) -> KernReturnT;

    pub fn task_info(
        target_task: MachPortT,
        flavor: c_int,
        task_info_out: *mut c_int,
        task_info_out_cnt: *mut MachMsgTypeNumberT,
    ) -> KernReturnT;

    pub fn thread_info(
        target_act: MachPortT,
        flavor: c_int,
        thread_info_out: *mut c_int,
        thread_info_out_cnt: *mut MachMsgTypeNumberT,
    ) -> KernReturnT;

    pub fn mach_absolute_time() -> u64;
    pub fn mach_timebase_info(info: *mut MachTimebaseInfo) -> KernReturnT;

    // --- Bootstrap server ---
    pub fn bootstrap_check_in(
        bootstrap_port: MachPortT,
        service_name: *const c_char,
        service_port: *mut MachPortT,
    ) -> KernReturnT;

    // --- POSIX ---
    pub fn sysctl(
        name: *mut c_int,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;

    pub fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;

    pub fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    pub fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;

    pub fn responsibility_get_pid_responsible_for_pid(pid: i32) -> i32;

    // --- POSIX process control ---
    pub fn fork() -> i32;
    pub fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
    pub fn waitpid(pid: i32, stat_loc: *mut c_int, options: c_int) -> i32;
    pub fn kill(pid: i32, sig: c_int) -> c_int;
    pub fn signal(sig: c_int, handler: usize) -> usize;
    pub fn getpid() -> i32;
    pub fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    pub fn unsetenv(name: *const c_char) -> c_int;
    pub fn unlink(pathname: *const c_char) -> c_int;
    pub fn atexit(function: extern "C" fn()) -> c_int;
}

// ============================================================================
// Helper functions
// ============================================================================

/// Wrapper for the `task_get_bootstrap_port` macro.
/// # Safety
/// Calls Mach kernel function.
pub unsafe fn task_get_bootstrap_port(task: MachPortT, port: *mut MachPortT) -> KernReturnT {
    unsafe { task_get_special_port(task, TASK_BOOTSTRAP_PORT, port) }
}

/// Wrapper for the `task_set_bootstrap_port` macro.
/// # Safety
/// Calls Mach kernel function.
pub unsafe fn task_set_bootstrap_port(task: MachPortT, port: MachPortT) -> KernReturnT {
    unsafe { task_set_special_port(task, TASK_BOOTSTRAP_PORT, port) }
}

/// Computes the awake system uptime in seconds from mach_absolute_time.
pub fn compute_awake_uptime() -> u64 {
    unsafe {
        let abs_time = mach_absolute_time();
        let mut timebase = MachTimebaseInfo { numer: 0, denom: 0 };
        if mach_timebase_info(&mut timebase) == KERN_SUCCESS && timebase.denom != 0 {
            let nanos = (abs_time as f64) * (timebase.numer as f64) / (timebase.denom as f64);
            (nanos / 1e9) as u64
        } else {
            0
        }
    }
}

/// Resolves PID from a Mach task port.
pub fn pid_from_task(task: MachPortT) -> Option<i32> {
    unsafe {
        let mut pid: i32 = 0;
        if pid_for_task(task, &mut pid) == KERN_SUCCESS {
            Some(pid)
        } else {
            None
        }
    }
}

/// Gets the Mach task port for a PID.
pub fn task_from_pid(pid: i32) -> Option<MachPortT> {
    unsafe {
        let mut task: MachPortT = 0;
        if task_for_pid(mach_task_self(), pid, &mut task) == KERN_SUCCESS {
            Some(task)
        } else {
            None
        }
    }
}

/// Queries proc_pidinfo for process info (ppid, is64bit, uid).
pub fn query_proc_info(pid: i32) -> Option<(i32, bool, u32)> {
    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = std::mem::size_of::<ProcBsdInfo>() as i32;
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut c_void,
            size,
        )
    };
    if ret >= size {
        let info = unsafe { info.assume_init() };
        let ppid = info.pbi_ppid as i32;
        let is_64_bit = info.pbi_flags & 0x10 != 0;
        let uid = info.pbi_uid;
        Some((ppid, is_64_bit, uid))
    } else {
        None
    }
}

/// Resolves executable path and process name from PID.
pub fn resolve_process_identity(pid: i32) -> (Option<String>, Option<String>) {
    let mut buf = [0u8; 4096];
    let ret = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if ret > 0 {
        let path = std::str::from_utf8(&buf[..ret as usize])
            .unwrap_or("")
            .to_string();
        let name = path.rsplit('/').next().map(|s| s.to_string());
        (Some(path), name)
    } else {
        (None, None)
    }
}

/// Resolves the full command line of a process by PID via `sysctl(KERN_PROCARGS2)`.
/// Returns the argv entries joined with spaces, with shell-metacharacter arguments
/// quoted. Returns None if the process arguments cannot be read.
pub fn resolve_command_line(pid: i32) -> Option<String> {
    // CTL_KERN = 1, KERN_PROCARGS2 = 49
    let mut mib: [c_int; 3] = [1, 49, pid];

    // First call: query buffer size
    let mut size: usize = 0;
    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return None;
    }

    // Second call: read the data
    let mut buf = vec![0u8; size];
    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    buf.truncate(size);

    parse_procargs2(&buf)
}

/// Parses a KERN_PROCARGS2 buffer into a shell-escaped command line string.
///
/// Buffer format:
///   [4 bytes: argc as i32]
///   [executable path, NUL-terminated]
///   [optional NUL padding]
///   [argv[0], NUL] [argv[1], NUL] ... [argv[argc-1], NUL]
fn parse_procargs2(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if argc == 0 {
        return None;
    }

    // Skip past argc (4 bytes) and the executable path
    let rest = &buf[4..];
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut pos = exec_end + 1;

    // Skip NUL padding between executable path and argv[0]
    while pos < rest.len() && rest[pos] == 0 {
        pos += 1;
    }

    // Extract argc arguments
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if pos >= rest.len() {
            break;
        }
        let arg_end = rest[pos..].iter().position(|&b| b == 0)?;
        let arg = std::str::from_utf8(&rest[pos..pos + arg_end]).ok()?;
        args.push(arg.to_string());
        pos += arg_end + 1;
    }

    if args.is_empty() {
        return None;
    }

    // Shell-escape and join
    let escaped: Vec<String> = args.iter().map(|a| shell_escape_arg(a)).collect();
    Some(escaped.join(" "))
}

/// Escapes a string for shell display: wraps in single quotes if it contains
/// shell metacharacters, otherwise returns as-is.
fn shell_escape_arg(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.contains(|c: char| c.is_ascii_whitespace() || "\"'\\$`!#&|;(){}[]<>?*~".contains(c)) {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

/// Registers a service name with the Mach bootstrap server and returns
/// a receive right for the service port.
pub fn bootstrap_register_service(service_name: &str) -> Option<MachPortT> {
    let c_name = std::ffi::CString::new(service_name).ok()?;
    unsafe {
        let mut bootstrap: MachPortT = 0;
        if task_get_bootstrap_port(mach_task_self(), &mut bootstrap) != KERN_SUCCESS {
            return None;
        }
        let mut service_port: MachPortT = 0;
        if bootstrap_check_in(bootstrap, c_name.as_ptr(), &mut service_port) != KERN_SUCCESS {
            return None;
        }
        Some(service_port)
    }
}

/// Gets exception state from a thread.
pub fn get_exception_state(thread: MachPortT) -> Option<(Vec<u32>, u32)> {
    unsafe {
        let mut state = [0u32; 6]; // max of x86 (6) and ARM64 (4)
        let mut count = EXCEPTION_STATE_COUNT;
        let kr = thread_get_state(
            thread,
            EXCEPTION_STATE_FLAVOR,
            state.as_mut_ptr(),
            &mut count,
        );
        if kr == KERN_SUCCESS {
            Some((state[..count as usize].to_vec(), count))
        } else {
            None
        }
    }
}

/// Gets the responsible process PID.
pub fn get_responsible_pid(pid: i32) -> i32 {
    unsafe { responsibility_get_pid_responsible_for_pid(pid) }
}

/// Queries a sysctl integer value by name.
pub fn sysctl_int(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let c_name = CString::new(name).ok()?;
    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>();
    let ret = unsafe {
        sysctlbyname(
            c_name.as_ptr(),
            &mut value as *mut u32 as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret == 0 { Some(value) } else { None }
}

/// Reads data from the target process memory at the given address.
/// Returns None if no data could be read.
pub fn read_process_memory(task: MachPortT, address: u64, size: u64) -> Option<Vec<u8>> {
    unsafe {
        let page_size = vm_page_size;
        let aligned_start = address & !(page_size - 1);
        let aligned_end = (address + size - 1 + page_size) & !(page_size - 1);

        let mut data_ptr: usize = 0;
        let mut data_count: u32 = 0;
        let kr = mach_vm_read(
            task,
            aligned_start,
            aligned_end - aligned_start,
            &mut data_ptr,
            &mut data_count,
        );

        if kr != KERN_SUCCESS {
            return None;
        }

        let offset = (address - aligned_start) as usize;
        let chunk = std::slice::from_raw_parts((data_ptr + offset) as *const u8, size as usize);
        let result = chunk.to_vec();

        vm_deallocate(mach_task_self(), data_ptr, data_count as u64);

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // shell_escape_arg tests
    // ========================================================================

    #[test]
    fn shell_escape_empty_string() {
        assert_eq!(shell_escape_arg(""), "''");
    }

    #[test]
    fn shell_escape_no_special_chars() {
        assert_eq!(shell_escape_arg("hello"), "hello");
        assert_eq!(shell_escape_arg("/usr/bin/test"), "/usr/bin/test");
        assert_eq!(shell_escape_arg("--flag=value"), "--flag=value");
    }

    #[test]
    fn shell_escape_whitespace() {
        assert_eq!(shell_escape_arg("hello world"), "'hello world'");
        assert_eq!(shell_escape_arg("a\tb"), "'a\tb'");
    }

    #[test]
    fn shell_escape_metacharacters() {
        assert_eq!(shell_escape_arg("$HOME"), "'$HOME'");
        assert_eq!(shell_escape_arg("a&b"), "'a&b'");
        assert_eq!(shell_escape_arg("a;b"), "'a;b'");
        assert_eq!(shell_escape_arg("*.txt"), "'*.txt'");
    }

    #[test]
    fn shell_escape_single_quotes() {
        assert_eq!(shell_escape_arg("it's"), "'it'\\''s'");
    }

    // ========================================================================
    // parse_procargs2 tests
    // ========================================================================

    /// Builds a KERN_PROCARGS2 buffer from components.
    fn make_procargs2(argc: i32, exec_path: &str, padding: usize, args: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&argc.to_ne_bytes());
        buf.extend_from_slice(exec_path.as_bytes());
        buf.push(0); // NUL-terminate exec path
        buf.extend(std::iter::repeat(0).take(padding)); // NUL padding
        for arg in args {
            buf.extend_from_slice(arg.as_bytes());
            buf.push(0);
        }
        buf
    }

    #[test]
    fn parse_procargs2_basic() {
        let buf = make_procargs2(2, "/usr/bin/test", 3, &["/usr/bin/test", "arg1"]);
        assert_eq!(
            parse_procargs2(&buf),
            Some("/usr/bin/test arg1".to_string())
        );
    }

    #[test]
    fn parse_procargs2_single_arg() {
        let buf = make_procargs2(1, "/bin/ls", 1, &["/bin/ls"]);
        assert_eq!(parse_procargs2(&buf), Some("/bin/ls".to_string()));
    }

    #[test]
    fn parse_procargs2_args_with_spaces() {
        let buf = make_procargs2(2, "/usr/bin/echo", 1, &["/usr/bin/echo", "hello world"]);
        assert_eq!(
            parse_procargs2(&buf),
            Some("/usr/bin/echo 'hello world'".to_string())
        );
    }

    #[test]
    fn parse_procargs2_zero_argc() {
        let buf = make_procargs2(0, "/bin/test", 1, &[]);
        assert_eq!(parse_procargs2(&buf), None);
    }

    #[test]
    fn parse_procargs2_too_short() {
        assert_eq!(parse_procargs2(&[]), None);
        assert_eq!(parse_procargs2(&[1, 0, 0]), None);
    }

    #[test]
    fn parse_procargs2_no_padding() {
        // Zero padding between exec path and argv
        let buf = make_procargs2(1, "/bin/sh", 0, &["/bin/sh"]);
        assert_eq!(parse_procargs2(&buf), Some("/bin/sh".to_string()));
    }

    #[test]
    fn parse_procargs2_large_padding() {
        let buf = make_procargs2(1, "/bin/sh", 64, &["/bin/sh"]);
        assert_eq!(parse_procargs2(&buf), Some("/bin/sh".to_string()));
    }

    #[test]
    fn parse_procargs2_argc_exceeds_actual_args() {
        // argc says 3, but only 1 arg present — returns the args found
        // (loop breaks when pos >= rest.len())
        let buf = make_procargs2(3, "/bin/sh", 1, &["/bin/sh"]);
        assert_eq!(parse_procargs2(&buf), Some("/bin/sh".to_string()));
    }
}
