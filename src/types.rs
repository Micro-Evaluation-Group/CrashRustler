use std::collections::{BTreeMap, HashMap};

/// Exploitability classification of a crash.
/// Matches CrashWrangler's exit code semantics:
/// signal = not exploitable, signal+100 = exploitable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExploitabilityRating {
    /// Crash is not exploitable (exit code = signal number).
    NotExploitable,
    /// Crash is exploitable (exit code = signal + 100).
    Exploitable,
    /// Exploitability could not be determined.
    Unknown,
}

/// Memory access type for the crashing instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// Reading from memory.
    Read,
    /// Writing to memory.
    Write,
    /// Executing code.
    Exec,
    /// Stack recursion (>300 frames).
    Recursion,
    /// Access type could not be determined.
    Unknown,
}

/// Pre-gathered crash data passed to `CrashRustler::new()`.
/// The binary (exc_handler) is responsible for all Mach/system calls;
/// this struct carries the results to the library's pure-data constructor.
#[derive(Debug, Clone)]
pub struct CrashParams {
    /// Mach task port for the crashed process.
    pub task: u32,
    /// Process ID.
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// User ID.
    pub uid: u32,
    /// Whether the process is 64-bit.
    pub is_64_bit: bool,
    /// Mach thread port of the crashing thread.
    pub thread: u32,
    /// Mach exception type (raw i32).
    pub exception_type: i32,
    /// Mach exception codes.
    pub exception_codes: Vec<i64>,
    /// Thread state (register values + flavor).
    pub thread_state: ThreadState,
    /// Exception state from the faulting thread.
    pub exception_state: ExceptionState,
    /// Process name (from proc_pidpath last component).
    pub process_name: Option<String>,
    /// Full executable path.
    pub executable_path: Option<String>,
    /// Responsible process PID.
    pub r_process_pid: i32,
    /// Crash date as a formatted string.
    pub date: Option<String>,
    /// System uptime (awake time) at crash, in seconds.
    pub awake_system_uptime: u64,
    /// CPU type of the crashed process.
    pub cpu_type: CpuType,
}

/// Mach exception types mirroring mach/exception_types.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExceptionType {
    BadAccess = 1,
    BadInstruction = 2,
    Arithmetic = 3,
    Emulation = 4,
    Software = 5,
    Breakpoint = 6,
    Syscall = 7,
    MachSyscall = 8,
    RpcAlert = 9,
    Crash = 10,
    Resource = 11,
    Guard = 12,
    CorpseNotify = 13,
}

impl ExceptionType {
    /// Converts a raw `i32` value to an `ExceptionType`, if valid.
    ///
    /// Returns `None` for values outside the range 1..=13.
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::ExceptionType;
    ///
    /// let exc = ExceptionType::from_raw(1).unwrap();
    /// assert_eq!(exc, ExceptionType::BadAccess);
    /// assert_eq!(exc.raw(), 1);
    ///
    /// assert!(ExceptionType::from_raw(0).is_none());
    /// assert!(ExceptionType::from_raw(99).is_none());
    /// ```
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            1 => Some(Self::BadAccess),
            2 => Some(Self::BadInstruction),
            3 => Some(Self::Arithmetic),
            4 => Some(Self::Emulation),
            5 => Some(Self::Software),
            6 => Some(Self::Breakpoint),
            7 => Some(Self::Syscall),
            8 => Some(Self::MachSyscall),
            9 => Some(Self::RpcAlert),
            10 => Some(Self::Crash),
            11 => Some(Self::Resource),
            12 => Some(Self::Guard),
            13 => Some(Self::CorpseNotify),
            _ => None,
        }
    }

    /// Returns the raw `i32` value of this exception type.
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::ExceptionType;
    ///
    /// assert_eq!(ExceptionType::BadAccess.raw(), 1);
    /// assert_eq!(ExceptionType::Breakpoint.raw(), 6);
    /// ```
    pub fn raw(&self) -> i32 {
        *self as i32
    }
}

/// CPU type constants mirroring mach/machine.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuType(pub i32);

impl CpuType {
    /// 32-bit Intel x86.
    pub const X86: Self = Self(7);
    /// 64-bit Intel x86_64.
    pub const X86_64: Self = Self(0x0100_0007);
    /// 32-bit ARM.
    pub const ARM: Self = Self(12);
    /// 64-bit ARM (Apple Silicon).
    pub const ARM64: Self = Self(0x0100_000c);
    /// 32-bit PowerPC.
    pub const POWERPC: Self = Self(18);
    /// 64-bit PowerPC.
    pub const POWERPC64: Self = Self(0x0100_0012);

    /// Returns `true` if this CPU type has the 64-bit flag set (bit 24).
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CpuType;
    ///
    /// assert!(CpuType::X86_64.is_64_bit());
    /// assert!(CpuType::ARM64.is_64_bit());
    /// assert!(!CpuType::X86.is_64_bit());
    /// assert!(!CpuType::ARM.is_64_bit());
    /// ```
    pub fn is_64_bit(&self) -> bool {
        self.0 & 0x0100_0000 != 0
    }

    /// Returns a new `CpuType` with the 64-bit flag (bit 24) set.
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CpuType;
    ///
    /// let cpu64 = CpuType::X86.with_64_bit();
    /// assert_eq!(cpu64, CpuType::X86_64);
    /// assert!(cpu64.is_64_bit());
    /// ```
    pub fn with_64_bit(self) -> Self {
        Self(self.0 | 0x0100_0000)
    }
}

/// Represents a binary image loaded in the crashed process.
#[derive(Debug, Clone)]
pub struct BinaryImage {
    /// Short name of the binary (e.g., `"libsystem_kernel.dylib"`).
    pub name: String,
    /// Full filesystem path to the binary image.
    pub path: String,
    /// UUID of the binary image for symbolication.
    pub uuid: Option<String>,
    /// Load address (start) of the binary image in virtual memory.
    pub base_address: u64,
    /// End address (exclusive) of the binary image in virtual memory.
    pub end_address: u64,
    /// Architecture string (e.g., `"x86_64"`, `"arm64"`).
    pub arch: Option<String>,
    /// Bundle identifier or derived name used for crash report formatting.
    pub identifier: Option<String>,
    /// Bundle version string (CFBundleVersion).
    pub version: Option<String>,
}

/// Represents a single frame in a backtrace.
#[derive(Debug, Clone)]
pub struct BacktraceFrame {
    /// Zero-based index of this frame in the backtrace.
    pub frame_number: u32,
    /// Name of the binary image containing this frame's address.
    pub image_name: String,
    /// Virtual memory address of this frame.
    pub address: u64,
    /// Symbolicated function name, if available.
    pub symbol_name: Option<String>,
    /// Byte offset from the start of the symbol.
    pub symbol_offset: u64,
    /// Source file path, if debug info is available.
    pub source_file: Option<String>,
    /// Source line number, if debug info is available.
    pub source_line: Option<u32>,
}

/// Represents the backtrace of a single thread.
#[derive(Debug, Clone)]
pub struct ThreadBacktrace {
    /// Index of this thread in the process.
    pub thread_number: u32,
    /// Dispatch queue name or pthread name, if set.
    pub thread_name: Option<String>,
    /// Mach thread ID (`thread_identifier_info`).
    pub thread_id: Option<u64>,
    /// Whether this thread triggered the crash.
    pub is_crashed: bool,
    /// Stack frames for this thread, ordered from top (most recent) to bottom.
    pub frames: Vec<BacktraceFrame>,
}

/// Thread state register values.
#[derive(Debug, Clone)]
pub struct ThreadState {
    /// Mach thread state flavor (e.g., `x86_THREAD_STATE = 7`, `ARM_THREAD_STATE64 = 6`).
    pub flavor: u32,
    /// Raw register values as 32-bit words. 64-bit registers span two consecutive words.
    pub registers: Vec<u32>,
}

/// Exception state from the faulting thread.
#[derive(Debug, Clone)]
pub struct ExceptionState {
    /// Raw exception state register values (e.g., `trapno`, `cpu`, `err`, `faultvaddr`).
    pub state: Vec<u32>,
    /// Number of valid words in `state`.
    pub count: u32,
}

/// VM region information for the crash report.
#[derive(Debug, Clone)]
pub struct VmRegion {
    /// Start address of the VM region.
    pub address: u64,
    /// Size of the VM region in bytes.
    pub size: u64,
    /// User tag name for the region (e.g., `"MALLOC_TINY"`, `"__TEXT"`).
    pub name: Option<String>,
    /// Protection flags as a human-readable string (e.g., `"r-x/rwx"`).
    pub protection: String,
}

/// External modification information.
#[derive(Debug, Clone)]
pub struct ExternalModInfo {
    /// Human-readable description of external modifications.
    pub description: Option<String>,
    /// Warning messages about external modifications.
    pub warnings: Option<String>,
    /// Key-value pairs of external modification metadata.
    pub dictionary: HashMap<String, String>,
}

/// Work queue limits extracted from the process.
#[derive(Debug, Clone)]
pub struct WorkQueueLimits {
    /// Constrained thread limit (`kern.wq_max_constrained_threads`).
    pub min_threads: Option<u32>,
    /// Total thread limit (`kern.wq_max_threads`).
    pub max_threads: Option<u32>,
}

/// Heterogeneous plist value type for dictionary/plist output methods.
/// Mirrors the NSObject types used in CrashReport's NSDictionary outputs.
#[derive(Debug, Clone)]
pub enum PlistValue {
    /// A string value.
    String(String),
    /// A signed 64-bit integer value.
    Int(i64),
    /// A boolean value.
    Bool(bool),
    /// An array of dictionaries (maps to NSArray of NSDictionary).
    Array(Vec<BTreeMap<String, PlistValue>>),
    /// A nested dictionary (maps to NSDictionary).
    Dict(BTreeMap<String, PlistValue>),
}

/// Represents a mapped region of process memory for pointer reads.
/// Used by `_readAddressFromMemory:atAddress:` to read pointer-sized values
/// from a pre-mapped buffer without additional Mach VM calls.
#[derive(Debug, Clone)]
pub struct MappedMemory {
    /// Raw bytes of the mapped memory region.
    pub data: Vec<u8>,
    /// Virtual address corresponding to `data[0]`.
    pub base_address: u64,
}

impl MappedMemory {
    /// Reads a pointer-sized value from the mapped memory at the given virtual address.
    /// Reads 8 bytes for 64-bit processes, 4 bytes for 32-bit.
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::MappedMemory;
    ///
    /// let mem = MappedMemory {
    ///     data: vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE],
    ///     base_address: 0x1000,
    /// };
    ///
    /// // 64-bit read: all 8 bytes as little-endian u64
    /// assert_eq!(mem.read_pointer(0x1000, true), Some(0xDEADBEEF_12345678));
    ///
    /// // 32-bit read: first 4 bytes as little-endian u32
    /// assert_eq!(mem.read_pointer(0x1000, false), Some(0x12345678));
    ///
    /// // Out of range
    /// assert_eq!(mem.read_pointer(0x2000, true), None);
    /// ```
    pub fn read_pointer(&self, address: u64, is_64_bit: bool) -> Option<u64> {
        let offset = address.checked_sub(self.base_address)? as usize;
        if is_64_bit {
            if offset + 8 > self.data.len() {
                return None;
            }
            let bytes: [u8; 8] = self.data[offset..offset + 8].try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        } else {
            if offset + 4 > self.data.len() {
                return None;
            }
            let bytes: [u8; 4] = self.data[offset..offset + 4].try_into().ok()?;
            Some(u32::from_le_bytes(bytes) as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    mod types {
        use super::*;

        #[test]
        fn exception_type_from_raw_all_valid() {
            let cases = [
                (1, ExceptionType::BadAccess),
                (2, ExceptionType::BadInstruction),
                (3, ExceptionType::Arithmetic),
                (4, ExceptionType::Emulation),
                (5, ExceptionType::Software),
                (6, ExceptionType::Breakpoint),
                (7, ExceptionType::Syscall),
                (8, ExceptionType::MachSyscall),
                (9, ExceptionType::RpcAlert),
                (10, ExceptionType::Crash),
                (11, ExceptionType::Resource),
                (12, ExceptionType::Guard),
                (13, ExceptionType::CorpseNotify),
            ];
            for (raw, expected) in cases {
                assert_eq!(ExceptionType::from_raw(raw), Some(expected), "raw={raw}");
            }
        }

        #[test]
        fn exception_type_from_raw_invalid() {
            assert_eq!(ExceptionType::from_raw(0), None);
            assert_eq!(ExceptionType::from_raw(14), None);
            assert_eq!(ExceptionType::from_raw(-1), None);
            assert_eq!(ExceptionType::from_raw(i32::MAX), None);
        }

        #[test]
        fn exception_type_raw_round_trip() {
            for val in 1..=13 {
                let et = ExceptionType::from_raw(val).unwrap();
                assert_eq!(et.raw(), val);
            }
        }

        #[test]
        fn cpu_type_is_64_bit() {
            assert!(!CpuType::X86.is_64_bit());
            assert!(CpuType::X86_64.is_64_bit());
            assert!(!CpuType::ARM.is_64_bit());
            assert!(CpuType::ARM64.is_64_bit());
            assert!(!CpuType::POWERPC.is_64_bit());
            assert!(CpuType::POWERPC64.is_64_bit());
        }

        #[test]
        fn cpu_type_with_64_bit() {
            assert_eq!(CpuType::X86.with_64_bit(), CpuType::X86_64);
            assert_eq!(CpuType::ARM.with_64_bit(), CpuType::ARM64);
            assert_eq!(CpuType::POWERPC.with_64_bit(), CpuType::POWERPC64);
            // Already 64-bit stays the same
            assert_eq!(CpuType::X86_64.with_64_bit(), CpuType::X86_64);
        }

        #[test]
        fn mapped_memory_read_pointer_64bit() {
            let data = 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes().to_vec();
            let mem = MappedMemory {
                data,
                base_address: 0x1000,
            };
            assert_eq!(mem.read_pointer(0x1000, true), Some(0xDEAD_BEEF_CAFE_BABE));
        }

        #[test]
        fn mapped_memory_read_pointer_32bit() {
            let data = 0xCAFE_BABEu32.to_le_bytes().to_vec();
            let mem = MappedMemory {
                data,
                base_address: 0x1000,
            };
            assert_eq!(mem.read_pointer(0x1000, false), Some(0xCAFE_BABE));
        }

        #[test]
        fn mapped_memory_read_pointer_out_of_bounds() {
            let mem = MappedMemory {
                data: vec![0u8; 4],
                base_address: 0x1000,
            };
            // 64-bit read needs 8 bytes but only 4 available
            assert_eq!(mem.read_pointer(0x1000, true), None);
            // Address past end
            assert_eq!(mem.read_pointer(0x1008, false), None);
        }

        #[test]
        fn mapped_memory_read_pointer_address_below_base() {
            let mem = MappedMemory {
                data: vec![0u8; 8],
                base_address: 0x2000,
            };
            assert_eq!(mem.read_pointer(0x1000, true), None);
        }

        #[test]
        fn mapped_memory_read_pointer_exact_boundary() {
            // Exactly 8 bytes from offset 0 — should succeed for 64-bit
            let mem = MappedMemory {
                data: vec![0xFF; 8],
                base_address: 0x1000,
            };
            assert!(mem.read_pointer(0x1000, true).is_some());
            // One byte past — should fail
            assert_eq!(mem.read_pointer(0x1001, true), None);
        }
    }
}
