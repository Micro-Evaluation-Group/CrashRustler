//! Remote memory reader for target process memory access via Mach VM.
//!
//! Implements the library's `MemoryReader` trait using `mach_vm_read()`
//! so the unwinder can read the target process's address space.

use crashrustler::unwind::MemoryReader;

use crate::ffi;

/// Reads memory from a remote process via `mach_vm_read()`.
pub struct RemoteMemoryReader {
    pub task: ffi::MachPortT,
}

impl MemoryReader for RemoteMemoryReader {
    fn read_memory(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        ffi::read_process_memory(self.task, address, size as u64)
    }
}
