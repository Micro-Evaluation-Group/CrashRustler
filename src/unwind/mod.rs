//! Stack unwinding infrastructure for macOS crash reports.
//!
//! Provides DWARF CFI, Apple Compact Unwind, and frame pointer walking
//! to generate accurate thread backtraces. All unwinding algorithms live
//! in the library crate — no FFI. A [`MemoryReader`] trait abstracts
//! memory access so the binary crate can provide `mach_vm_read()`.

pub mod arch;
pub mod compact_unwind;
pub mod cursor;
pub mod dwarf_cfi;
pub mod dwarf_expr;
pub mod frame_pointer;
pub mod macho;
pub mod registers;

use crate::types::{CpuType, ThreadState};
use registers::RegisterContext;

/// Errors that can occur during stack unwinding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindError {
    /// Memory read failed at the given address.
    MemoryReadFailed(u64),
    /// No unwind info found for the given PC.
    NoUnwindInfo(u64),
    /// Invalid DWARF CFI data.
    InvalidDwarf(String),
    /// Invalid compact unwind encoding.
    InvalidCompactUnwind(u32),
    /// Maximum unwind depth exceeded.
    MaxDepthExceeded(u32),
    /// PC landed in null page (normal termination).
    NullPC,
    /// Frame pointer chain broken.
    BrokenFrameChain,
}

/// Trait for reading memory from a target process.
///
/// The library crate contains all unwinding algorithms but needs to read
/// target process memory. The binary crate implements this trait using
/// `mach_vm_read()`.
pub trait MemoryReader {
    /// Reads `size` bytes from the given virtual address.
    /// Returns `None` if the read fails.
    fn read_memory(&self, address: u64, size: usize) -> Option<Vec<u8>>;

    /// Reads a single byte.
    fn read_u8(&self, address: u64) -> Option<u8> {
        self.read_memory(address, 1).map(|b| b[0])
    }

    /// Reads a little-endian u16.
    fn read_u16(&self, address: u64) -> Option<u16> {
        let b = self.read_memory(address, 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads a little-endian u32.
    fn read_u32(&self, address: u64) -> Option<u32> {
        let b = self.read_memory(address, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a little-endian u64.
    fn read_u64(&self, address: u64) -> Option<u64> {
        let b = self.read_memory(address, 8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a little-endian i32.
    fn read_i32(&self, address: u64) -> Option<i32> {
        self.read_u32(address).map(|v| v as i32)
    }

    /// Reads a little-endian i64.
    fn read_i64(&self, address: u64) -> Option<i64> {
        self.read_u64(address).map(|v| v as i64)
    }

    /// Reads a pointer-sized value (4 or 8 bytes depending on `is_64_bit`).
    fn read_pointer(&self, address: u64, is_64_bit: bool) -> Option<u64> {
        if is_64_bit {
            self.read_u64(address)
        } else {
            self.read_u32(address).map(|v| v as u64)
        }
    }
}

/// Location of a Mach-O section in virtual memory.
#[derive(Debug, Clone, Copy)]
pub struct SectionRef {
    /// Virtual address of the section.
    pub vm_addr: u64,
    /// Size of the section in bytes.
    pub size: u64,
}

/// Information about a loaded binary image, with cached section locations.
#[derive(Debug, Clone)]
pub struct BinaryImageInfo {
    /// Short name or path of the binary.
    pub name: String,
    /// Load address (start of __TEXT segment) in virtual memory.
    pub load_address: u64,
    /// End address (exclusive) in virtual memory.
    pub end_address: u64,
    /// Whether this is a 64-bit binary.
    pub is_64_bit: bool,
    /// UUID of the binary (for symbolication).
    pub uuid: Option<[u8; 16]>,
    /// Cached location of __TEXT,__unwind_info.
    pub unwind_info: Option<SectionRef>,
    /// Cached location of __TEXT,__eh_frame.
    pub eh_frame: Option<SectionRef>,
    /// Cached location of __TEXT,__text.
    pub text_section: Option<SectionRef>,
    /// Whether section locations have been resolved.
    pub sections_resolved: bool,
}

impl BinaryImageInfo {
    /// Returns true if the given address falls within this image.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.load_address && address < self.end_address
    }

    /// Resolves section locations from the Mach-O header using the given reader.
    pub fn resolve_sections(&mut self, reader: &dyn MemoryReader) {
        if self.sections_resolved {
            return;
        }
        self.sections_resolved = true;

        let sections = macho::find_sections(reader, self.load_address, self.is_64_bit);
        self.unwind_info = sections.unwind_info;
        self.eh_frame = sections.eh_frame;
        self.text_section = sections.text;
    }
}

/// Unwinds a single thread, producing a list of (PC, register context) pairs
/// from top of stack to bottom.
///
/// # Arguments
/// * `reader` — Memory reader for the target process.
/// * `initial_state` — Register state of the thread.
/// * `cpu_type` — CPU type of the process.
/// * `images` — Binary images loaded in the process (sections resolved lazily).
pub fn unwind_thread(
    reader: &dyn MemoryReader,
    initial_state: &ThreadState,
    cpu_type: CpuType,
    images: &mut [BinaryImageInfo],
) -> Vec<(u64, RegisterContext)> {
    let is_64_bit = cpu_type.is_64_bit();
    let Some(regs) = RegisterContext::from_thread_state(initial_state, cpu_type) else {
        return Vec::new();
    };

    let mut frame_cursor = cursor::FrameCursor::new(reader, regs, images, is_64_bit);
    let mut frames = Vec::new();

    // Record initial frame
    if let Some(pc) = frame_cursor.pc() {
        frames.push((pc, frame_cursor.registers().clone()));
    }

    // Step through frames
    while let Ok(true) = frame_cursor.step() {
        if let Some(pc) = frame_cursor.pc() {
            frames.push((pc, frame_cursor.registers().clone()));
        } else {
            break;
        }
    }

    frames
}

/// MemoryReader implementation for MappedMemory (for testing).
impl MemoryReader for crate::MappedMemory {
    fn read_memory(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        let offset = address.checked_sub(self.base_address)? as usize;
        if offset + size > self.data.len() {
            return None;
        }
        Some(self.data[offset..offset + size].to_vec())
    }
}

/// A simple in-memory reader backed by a byte buffer at a given base address.
/// Useful for tests.
#[derive(Debug, Clone)]
pub struct SliceMemoryReader {
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Virtual address of `data[0]`.
    pub base_address: u64,
}

impl MemoryReader for SliceMemoryReader {
    fn read_memory(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        let offset = address.checked_sub(self.base_address)? as usize;
        if offset + size > self.data.len() {
            return None;
        }
        Some(self.data[offset..offset + size].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_memory_reader_basic() {
        let reader = SliceMemoryReader {
            data: vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE],
            base_address: 0x1000,
        };
        assert_eq!(reader.read_u32(0x1000), Some(0x12345678));
        assert_eq!(reader.read_u64(0x1000), Some(0xDEADBEEF_12345678));
        assert_eq!(reader.read_u8(0x1000), Some(0x78));
        assert_eq!(reader.read_u16(0x1000), Some(0x5678));
    }

    #[test]
    fn slice_memory_reader_out_of_bounds() {
        let reader = SliceMemoryReader {
            data: vec![0u8; 4],
            base_address: 0x1000,
        };
        assert!(reader.read_u64(0x1000).is_none());
        assert!(reader.read_u32(0x1001).is_none());
        assert!(reader.read_memory(0x0FFF, 1).is_none());
    }

    #[test]
    fn slice_memory_reader_pointer() {
        let reader = SliceMemoryReader {
            data: 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes().to_vec(),
            base_address: 0x2000,
        };
        assert_eq!(
            reader.read_pointer(0x2000, true),
            Some(0xDEAD_BEEF_CAFE_BABE)
        );
        assert_eq!(reader.read_pointer(0x2000, false), Some(0xCAFE_BABE));
    }
}
