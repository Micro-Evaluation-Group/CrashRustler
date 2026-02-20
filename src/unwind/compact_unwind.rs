//! Apple Compact Unwind (`__unwind_info`) parser and register restoration.
//!
//! Parses the `__unwind_info` section to find compact unwind encodings for
//! a given PC, decodes the encoding, and applies it to restore registers.

use crate::types::CpuType;

use super::arch::{arm64_compact, x86_64_compact};
use super::registers::RegisterContext;
use super::{MemoryReader, SectionRef, UnwindError};

// ==========================================================================
// Compact unwind entry types
// ==========================================================================

/// Decoded compact unwind entry.
#[derive(Debug, Clone)]
pub enum CompactEntry {
    /// Frame-based: saved registers at FP+offset.
    FrameBased {
        saved_regs: Vec<(u16, i16)>, // (dwarf_reg, offset_from_fp)
    },
    /// Frameless with immediate stack size.
    FramelessImmediate {
        stack_size: u64,
        saved_regs: Vec<u16>,
        /// Register holding the return address (e.g. LR on ARM64).
        /// None means the return address is on the stack (x86_64).
        return_address_register: Option<u16>,
    },
    /// Frameless with indirect stack size (read from function body, x86_64 only).
    FramelessIndirect {
        sub_offset: u32,
        stack_adjust: u32,
        saved_regs: Vec<u16>,
    },
    /// Encoding says to use DWARF .eh_frame instead.
    Dwarf { fde_offset: u32 },
    /// No unwind info (leaf function or error).
    None,
}

// ==========================================================================
// __unwind_info section layout constants
//
// Header: unwind_info_section_header (28 bytes)
//   u32 version                              offset 0
//   u32 commonEncodingsArraySectionOffset    offset 4
//   u32 commonEncodingsArrayCount            offset 8
//   u32 personalityArraySectionOffset        offset 12
//   u32 personalityArrayCount                offset 16
//   u32 indexSectionOffset                   offset 20
//   u32 indexCount                           offset 24
//
// First-level index entry (12 bytes):
//   u32 functionOffset                       offset 0
//   u32 secondLevelPagesSectionOffset        offset 4
//   u32 lsdaIndexArraySectionOffset          offset 8
//
// Regular second-level page header (8 bytes):
//   u32 kind                                 offset 0
//   u16 entryPageOffset                      offset 4
//   u16 entryCount                           offset 6
//
// Compressed second-level page header (12 bytes):
//   u32 kind                                 offset 0
//   u16 entryPageOffset                      offset 4
//   u16 entryCount                           offset 6
//   u16 encodingsPageOffset                  offset 8
//   u16 encodingsCount                       offset 10
// ==========================================================================

// Header offsets (28-byte unwind_info_section_header)
const HEADER_VERSION: u64 = 0;
const HEADER_COMMON_ENC_OFFSET: u64 = 4;
const HEADER_COMMON_ENC_COUNT: u64 = 8;
// personalityArraySectionOffset at 12 (unused)
// personalityArrayCount at 16 (unused)
const HEADER_INDEX_OFFSET: u64 = 20;
const HEADER_INDEX_COUNT: u64 = 24;

// First-level index entry: 12 bytes
const FL_ENTRY_SIZE: u64 = 12;
const FL_FUNC_OFFSET: u64 = 0;
const FL_SECOND_LEVEL: u64 = 4;

// Second-level page types
const SL_REGULAR: u32 = 2;
const SL_COMPRESSED: u32 = 3;

// Regular second-level page header field offsets (u16 fields)
const REG_ENTRY_PAGE_OFFSET: u64 = 4;
const REG_ENTRY_COUNT: u64 = 6;
const REG_ENTRY_SIZE: u64 = 8; // each regular entry is 8 bytes (funcOffset u32 + encoding u32)

// Compressed second-level page header field offsets (u16 fields)
const COMP_ENTRY_PAGE_OFFSET: u64 = 4;
const COMP_ENTRY_COUNT: u64 = 6;
const COMP_ENC_PAGE_OFFSET: u64 = 8;
const COMP_ENC_COUNT: u64 = 10;

// ==========================================================================
// Lookup
// ==========================================================================

/// Looks up the compact unwind encoding for a given PC.
///
/// Returns `(encoding, func_base)` where `func_base` is the image-relative
/// offset of the function start (needed for `FramelessIndirect` entries).
pub fn lookup_encoding(
    reader: &dyn MemoryReader,
    unwind_info: &SectionRef,
    pc: u64,
    image_base: u64,
) -> Option<(u32, u32)> {
    let base = unwind_info.vm_addr;

    // Validate header
    let version = reader.read_u32(base + HEADER_VERSION)?;
    if version != 1 {
        return None;
    }

    let common_enc_offset = reader.read_u32(base + HEADER_COMMON_ENC_OFFSET)? as u64;
    let common_enc_count = reader.read_u32(base + HEADER_COMMON_ENC_COUNT)?;
    let index_offset = reader.read_u32(base + HEADER_INDEX_OFFSET)? as u64;
    let index_count = reader.read_u32(base + HEADER_INDEX_COUNT)?;

    // Exclude sentinel entry (always added by ld64 as the last entry)
    let index_count = index_count.checked_sub(1)?;
    if index_count == 0 {
        return None;
    }

    // Function offset relative to image base
    let func_offset = pc.checked_sub(image_base)? as u32;

    // Binary search in first-level index
    let fl_base = base + index_offset;
    let idx = first_level_binary_search(reader, fl_base, index_count, func_offset)?;

    // Read the matching first-level entry
    let entry_addr = fl_base + idx as u64 * FL_ENTRY_SIZE;
    let fl_func_offset = reader.read_u32(entry_addr + FL_FUNC_OFFSET)?;
    let sl_offset = reader.read_u32(entry_addr + FL_SECOND_LEVEL)? as u64;

    if sl_offset == 0 {
        return None;
    }

    let sl_base = base + sl_offset;
    let page_kind = reader.read_u32(sl_base)?;

    match page_kind {
        SL_REGULAR => lookup_regular_page(reader, sl_base, func_offset),
        SL_COMPRESSED => lookup_compressed_page(
            reader,
            sl_base,
            func_offset,
            fl_func_offset,
            base + common_enc_offset,
            common_enc_count,
        ),
        _ => None,
    }
}

fn first_level_binary_search(
    reader: &dyn MemoryReader,
    base: u64,
    count: u32,
    func_offset: u32,
) -> Option<u32> {
    if count == 0 {
        return None;
    }

    // Find the last entry where func_offset_start <= func_offset
    let mut lo = 0u32;
    let mut hi = count - 1;
    let mut result = 0u32;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let entry_func = reader.read_u32(base + mid as u64 * FL_ENTRY_SIZE + FL_FUNC_OFFSET)?;

        if entry_func <= func_offset {
            result = mid;
            if mid == hi {
                break;
            }
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    Some(result)
}

/// Looks up encoding in a regular second-level page.
/// Returns `(encoding, func_base)`.
fn lookup_regular_page(
    reader: &dyn MemoryReader,
    page_base: u64,
    func_offset: u32,
) -> Option<(u32, u32)> {
    let entry_page_offset = reader.read_u16(page_base + REG_ENTRY_PAGE_OFFSET)? as u64;
    let entry_count = reader.read_u16(page_base + REG_ENTRY_COUNT)? as u32;

    if entry_count == 0 {
        return None;
    }

    let entries_base = page_base + entry_page_offset;

    // Binary search in regular entries (8 bytes each: func_offset u32 + encoding u32)
    let mut lo = 0u32;
    let mut hi = entry_count - 1;
    let mut best: Option<(u32, u32)> = None;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let entry_addr = entries_base + mid as u64 * REG_ENTRY_SIZE;
        let entry_func = reader.read_u32(entry_addr)?;

        if entry_func <= func_offset {
            let encoding = reader.read_u32(entry_addr + 4)?;
            best = Some((encoding, entry_func));
            if mid == hi {
                break;
            }
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    best
}

/// Looks up encoding in a compressed second-level page.
/// Returns `(encoding, func_base)`.
fn lookup_compressed_page(
    reader: &dyn MemoryReader,
    page_base: u64,
    func_offset: u32,
    fl_func_offset: u32,
    common_enc_base: u64,
    common_enc_count: u32,
) -> Option<(u32, u32)> {
    let entry_page_offset = reader.read_u16(page_base + COMP_ENTRY_PAGE_OFFSET)? as u64;
    let entry_count = reader.read_u16(page_base + COMP_ENTRY_COUNT)? as u32;
    let enc_page_offset = reader.read_u16(page_base + COMP_ENC_PAGE_OFFSET)? as u64;
    let enc_count = reader.read_u16(page_base + COMP_ENC_COUNT)? as u32;

    if entry_count == 0 {
        return None;
    }

    let entries_base = page_base + entry_page_offset;

    // Each compressed entry is 4 bytes:
    //   bits 31-24: encoding index (8 bits)
    //   bits 23-0:  func_offset delta relative to first-level entry's functionOffset (24 bits)
    let mut lo = 0u32;
    let mut hi = entry_count - 1;
    let mut best_idx: Option<u32> = None;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let entry = reader.read_u32(entries_base + mid as u64 * 4)?;
        let entry_func = fl_func_offset + (entry & 0x00FF_FFFF);

        if entry_func <= func_offset {
            best_idx = Some(mid);
            if mid == hi {
                break;
            }
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    let idx = best_idx?;
    let entry = reader.read_u32(entries_base + idx as u64 * 4)?;
    let encoding_index = (entry >> 24) & 0xFF;
    let entry_func_base = fl_func_offset + (entry & 0x00FF_FFFF);

    // Resolve encoding: common table first, then page-local table
    let encoding = if encoding_index < common_enc_count {
        reader.read_u32(common_enc_base + encoding_index as u64 * 4)?
    } else {
        let local_idx = encoding_index - common_enc_count;
        if local_idx < enc_count {
            let page_enc_base = page_base + enc_page_offset;
            reader.read_u32(page_enc_base + local_idx as u64 * 4)?
        } else {
            return None;
        }
    };

    Some((encoding, entry_func_base))
}

// ==========================================================================
// Decoding
// ==========================================================================

/// Decodes a compact unwind encoding into a CompactEntry for the given CPU type.
pub fn decode_encoding(encoding: u32, cpu_type: CpuType) -> CompactEntry {
    if encoding == 0 {
        return CompactEntry::None;
    }
    if cpu_type == CpuType::ARM64 || cpu_type == CpuType::ARM {
        decode_arm64(encoding)
    } else {
        decode_x86_64(encoding)
    }
}

pub fn decode_arm64(encoding: u32) -> CompactEntry {
    let mode = encoding & arm64_compact::MODE_MASK;

    match mode {
        arm64_compact::MODE_FRAME => {
            // Frame-based: saved register pairs at FP-offset
            let mut saved_regs = Vec::new();
            let mut offset: i16 = -16; // first pair at FP-16

            for (bit, &(r1, r2)) in arm64_compact::FRAME_REG_PAIRS.iter().enumerate() {
                if encoding & (1 << bit) != 0 {
                    saved_regs.push((r1, offset));
                    saved_regs.push((r2, offset + 8));
                    offset -= 16;
                }
            }

            // FP and LR are always saved in frame-based mode
            // FP at [FP+0], LR at [FP+8] (stored by STP x29, x30, [sp, #-16]!)
            CompactEntry::FrameBased { saved_regs }
        }
        arm64_compact::MODE_FRAMELESS => {
            let stack_size = ((encoding & arm64_compact::FRAMELESS_STACK_SIZE_MASK)
                >> arm64_compact::FRAMELESS_STACK_SIZE_SHIFT) as u64
                * 16;
            CompactEntry::FramelessImmediate {
                stack_size,
                saved_regs: Vec::new(),
                return_address_register: Some(super::registers::arm64::LR),
            }
        }
        arm64_compact::MODE_DWARF => {
            let fde_offset = encoding & arm64_compact::DWARF_FDE_OFFSET_MASK;
            CompactEntry::Dwarf { fde_offset }
        }
        _ => CompactEntry::None,
    }
}

pub fn decode_x86_64(encoding: u32) -> CompactEntry {
    let mode = encoding & x86_64_compact::MODE_MASK;

    match mode {
        x86_64_compact::MODE_FRAME => {
            // Frame-based: saved registers encoded in bits 14-0
            let reg_bits = encoding & x86_64_compact::FRAME_REG_MASK;
            let frame_offset = ((encoding & x86_64_compact::FRAME_OFFSET_MASK)
                >> x86_64_compact::FRAME_OFFSET_SHIFT) as i16;
            let mut saved_regs = Vec::new();
            let mut offset: i16 = -(frame_offset * 8);

            for i in 0..5 {
                let reg_enc = ((reg_bits >> (i * 3)) & 0x7) as usize;
                if reg_enc != 0 && reg_enc < x86_64_compact::FRAME_REG_MAP.len() {
                    let dwarf_reg = x86_64_compact::FRAME_REG_MAP[reg_enc];
                    saved_regs.push((dwarf_reg, offset));
                    offset -= 8;
                }
            }

            CompactEntry::FrameBased { saved_regs }
        }
        x86_64_compact::MODE_FRAMELESS_IMMEDIATE => {
            let stack_size = ((encoding & x86_64_compact::FRAMELESS_STACK_SIZE_MASK)
                >> x86_64_compact::FRAMELESS_STACK_SIZE_SHIFT) as u64
                * 8;
            let saved_regs = super::arch::x86_64_decode_permutation(encoding);
            CompactEntry::FramelessImmediate {
                stack_size,
                saved_regs,
                return_address_register: None,
            }
        }
        x86_64_compact::MODE_FRAMELESS_INDIRECT => {
            let sub_offset = (encoding & x86_64_compact::INDIRECT_STACK_OFFSET_MASK)
                >> x86_64_compact::INDIRECT_STACK_OFFSET_SHIFT;
            let stack_adjust = (encoding & x86_64_compact::INDIRECT_STACK_ADJUST_MASK)
                >> x86_64_compact::INDIRECT_STACK_ADJUST_SHIFT;
            let saved_regs = super::arch::x86_64_decode_permutation(encoding);
            CompactEntry::FramelessIndirect {
                sub_offset,
                stack_adjust,
                saved_regs,
            }
        }
        x86_64_compact::MODE_DWARF => {
            let fde_offset = encoding & x86_64_compact::DWARF_FDE_OFFSET_MASK;
            CompactEntry::Dwarf { fde_offset }
        }
        _ => CompactEntry::None,
    }
}

// ==========================================================================
// Application: restore registers from stack
// ==========================================================================

/// Applies a compact unwind entry to restore the previous register context.
pub fn apply_entry(
    entry: &CompactEntry,
    regs: &mut RegisterContext,
    reader: &dyn MemoryReader,
    func_start: u64,
    is_64_bit: bool,
) -> Result<bool, UnwindError> {
    match entry {
        CompactEntry::FrameBased { saved_regs } => {
            let fp = regs.fp().ok_or(UnwindError::BrokenFrameChain)?;

            // Read saved FP and LR/return address from frame
            let ptr_size = if is_64_bit { 8u64 } else { 4u64 };
            let prev_fp = reader
                .read_pointer(fp, is_64_bit)
                .ok_or(UnwindError::MemoryReadFailed(fp))?;
            let return_addr = reader
                .read_pointer(fp + ptr_size, is_64_bit)
                .ok_or(UnwindError::MemoryReadFailed(fp + ptr_size))?;

            // Restore additional saved registers
            for &(dwarf_reg, offset) in saved_regs {
                let addr = (fp as i64 + offset as i64) as u64;
                if let Some(val) = reader.read_pointer(addr, is_64_bit) {
                    regs.set(dwarf_reg, val);
                }
            }

            regs.clear_volatile();
            regs.set_fp(prev_fp);
            regs.set_sp(fp + 2 * ptr_size);
            regs.set_pc(return_addr);

            Ok(true)
        }
        CompactEntry::FramelessImmediate {
            stack_size,
            saved_regs,
            return_address_register,
        } => {
            let sp = regs.sp().ok_or(UnwindError::BrokenFrameChain)?;
            let ptr_size = if is_64_bit { 8u64 } else { 4u64 };

            let (return_addr, mut reg_addr) = if let Some(ra_reg) = return_address_register {
                // Return address is in a register (ARM64: LR)
                let ra = regs.get(*ra_reg).ok_or(UnwindError::BrokenFrameChain)?;
                // Saved regs occupy the top of the allocated frame
                (ra, sp + stack_size - ptr_size)
            } else {
                // Return address is on the stack (x86_64: pushed by CALL)
                let ra = reader
                    .read_pointer(sp + stack_size - ptr_size, is_64_bit)
                    .ok_or(UnwindError::MemoryReadFailed(sp + stack_size - ptr_size))?;
                // Saved regs are below the return address
                (ra, sp + stack_size - 2 * ptr_size)
            };

            for &dwarf_reg in saved_regs {
                if let Some(val) = reader.read_pointer(reg_addr, is_64_bit) {
                    regs.set(dwarf_reg, val);
                }
                reg_addr -= ptr_size;
            }

            regs.clear_volatile();
            regs.set_sp(sp + stack_size);
            regs.set_pc(return_addr);

            Ok(true)
        }
        CompactEntry::FramelessIndirect {
            sub_offset,
            stack_adjust,
            saved_regs,
        } => {
            let sp = regs.sp().ok_or(UnwindError::BrokenFrameChain)?;
            let ptr_size = if is_64_bit { 8u64 } else { 4u64 };

            // Read stack size from the SUB instruction in the function prologue
            let sub_addr = func_start + *sub_offset as u64;
            let sub_imm = reader
                .read_u32(sub_addr)
                .ok_or(UnwindError::MemoryReadFailed(sub_addr))?;
            let stack_size = sub_imm as u64 + (*stack_adjust as u64 * ptr_size);

            let return_addr = reader
                .read_pointer(sp + stack_size - ptr_size, is_64_bit)
                .ok_or(UnwindError::MemoryReadFailed(sp + stack_size - ptr_size))?;

            let mut reg_addr = sp + stack_size - 2 * ptr_size;
            for &dwarf_reg in saved_regs {
                if let Some(val) = reader.read_pointer(reg_addr, is_64_bit) {
                    regs.set(dwarf_reg, val);
                }
                reg_addr -= ptr_size;
            }

            regs.clear_volatile();
            regs.set_sp(sp + stack_size);
            regs.set_pc(return_addr);

            Ok(true)
        }
        CompactEntry::Dwarf { .. } => {
            // Caller should handle DWARF fallback
            Ok(false)
        }
        CompactEntry::None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CpuType;
    use crate::unwind::SliceMemoryReader;

    // ======================================================================
    // Decoding tests
    // ======================================================================

    #[test]
    fn decode_arm64_frame_based() {
        // MODE_FRAME (0x0400_0000) with bits 0,1 set = X19/X20 and X21/X22 pairs
        let encoding = arm64_compact::MODE_FRAME | 0x03;
        let entry = decode_arm64(encoding);
        match entry {
            CompactEntry::FrameBased { saved_regs } => {
                // Should have X19, X20, X21, X22
                let reg_nums: Vec<u16> = saved_regs.iter().map(|(r, _)| *r).collect();
                assert!(reg_nums.contains(&19));
                assert!(reg_nums.contains(&20));
                assert!(reg_nums.contains(&21));
                assert!(reg_nums.contains(&22));
            }
            _ => panic!("expected FrameBased"),
        }
    }

    #[test]
    fn decode_arm64_frameless() {
        // MODE_FRAMELESS with stack_size = 3 (48 bytes = 3 * 16)
        let encoding =
            arm64_compact::MODE_FRAMELESS | (3 << arm64_compact::FRAMELESS_STACK_SIZE_SHIFT);
        let entry = decode_arm64(encoding);
        match entry {
            CompactEntry::FramelessImmediate {
                stack_size,
                return_address_register,
                ..
            } => {
                assert_eq!(stack_size, 48);
                assert_eq!(
                    return_address_register,
                    Some(super::super::registers::arm64::LR)
                );
            }
            _ => panic!("expected FramelessImmediate"),
        }
    }

    #[test]
    fn decode_arm64_dwarf() {
        let encoding = arm64_compact::MODE_DWARF | 0x42;
        let entry = decode_arm64(encoding);
        match entry {
            CompactEntry::Dwarf { fde_offset } => {
                assert_eq!(fde_offset, 0x42);
            }
            _ => panic!("expected Dwarf"),
        }
    }

    #[test]
    fn decode_x86_64_frame_based() {
        // MODE_FRAME with frame_offset=1 and one saved register (RBX = encoding 1 in slot 0)
        let encoding = x86_64_compact::MODE_FRAME | (1 << x86_64_compact::FRAME_OFFSET_SHIFT) | 1;
        let entry = decode_x86_64(encoding);
        match entry {
            CompactEntry::FrameBased { saved_regs } => {
                assert_eq!(saved_regs.len(), 1);
                assert_eq!(saved_regs[0].0, super::super::registers::x86_64::RBX);
                assert_eq!(saved_regs[0].1, -8);
            }
            _ => panic!("expected FrameBased"),
        }
    }

    #[test]
    fn decode_x86_64_frame_offset() {
        // MODE_FRAME with frame_offset=3 (regs start at RBP-24) and RBX in slot 0
        let encoding = x86_64_compact::MODE_FRAME | (3 << x86_64_compact::FRAME_OFFSET_SHIFT) | 1;
        let entry = decode_x86_64(encoding);
        match entry {
            CompactEntry::FrameBased { saved_regs } => {
                assert_eq!(saved_regs.len(), 1);
                assert_eq!(saved_regs[0].0, super::super::registers::x86_64::RBX);
                assert_eq!(saved_regs[0].1, -24); // 3 * 8
            }
            _ => panic!("expected FrameBased"),
        }
    }

    #[test]
    fn decode_x86_64_frameless_immediate() {
        // MODE_FRAMELESS_IMMEDIATE with stack_size=4 (32 bytes), 0 regs
        let encoding = x86_64_compact::MODE_FRAMELESS_IMMEDIATE
            | (4 << x86_64_compact::FRAMELESS_STACK_SIZE_SHIFT);
        let entry = decode_x86_64(encoding);
        match entry {
            CompactEntry::FramelessImmediate {
                stack_size,
                return_address_register,
                ..
            } => {
                assert_eq!(stack_size, 32);
                assert_eq!(return_address_register, None);
            }
            _ => panic!("expected FramelessImmediate"),
        }
    }

    #[test]
    fn decode_x86_64_dwarf() {
        let encoding = x86_64_compact::MODE_DWARF | 0x100;
        let entry = decode_x86_64(encoding);
        match entry {
            CompactEntry::Dwarf { fde_offset } => {
                assert_eq!(fde_offset, 0x100);
            }
            _ => panic!("expected Dwarf"),
        }
    }

    #[test]
    fn decode_zero_encoding() {
        assert!(matches!(decode_arm64(0), CompactEntry::None));
        assert!(matches!(decode_x86_64(0), CompactEntry::None));
    }

    // ======================================================================
    // Apply tests
    // ======================================================================

    #[test]
    fn apply_frame_based_arm64() {
        let base = 0x5000u64;
        let mut data = vec![0u8; 0x2000];

        // Frame at FP=0x5800:
        //   [FP+0]  = prev_fp = 0x5900
        //   [FP+8]  = return_addr = 0xDEAD_CAFE
        //   [FP-16] = saved X19 = 0x1919
        //   [FP-8]  = saved X20 = 0x2020
        let fp_off = 0x800usize;
        data[fp_off..fp_off + 8].copy_from_slice(&(base + 0x900).to_le_bytes());
        data[fp_off + 8..fp_off + 16].copy_from_slice(&0xDEAD_CAFEu64.to_le_bytes());
        data[fp_off - 16..fp_off - 8].copy_from_slice(&0x1919u64.to_le_bytes());
        data[fp_off - 8..fp_off].copy_from_slice(&0x2020u64.to_le_bytes());

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };

        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_fp(base + fp_off as u64);
        regs.set_sp(base + fp_off as u64 - 32);
        regs.set_pc(0xAAAA);

        let entry = CompactEntry::FrameBased {
            saved_regs: vec![(19, -16), (20, -8)],
        };

        assert!(apply_entry(&entry, &mut regs, &reader, 0x1000, true).unwrap());
        assert_eq!(regs.fp(), Some(base + 0x900));
        assert_eq!(regs.pc(), Some(0xDEAD_CAFE));
        assert_eq!(regs.get(19), Some(0x1919));
        assert_eq!(regs.get(20), Some(0x2020));
    }

    #[test]
    fn apply_frameless_immediate_x86_64() {
        let base = 0x3000u64;
        let mut data = vec![0u8; 0x200];
        let stack_size = 32u64;

        // SP=0x3080, stack_size=32
        // Return addr at SP+32-8=SP+24=0x3098 (offset 0x98)
        data[0x98..0xA0].copy_from_slice(&0xBEEF_0001u64.to_le_bytes());

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };

        let mut regs = RegisterContext::new(CpuType::X86_64);
        regs.set_sp(base + 0x80);
        regs.set_pc(0xAAAA);

        let entry = CompactEntry::FramelessImmediate {
            stack_size,
            saved_regs: Vec::new(),
            return_address_register: None,
        };

        assert!(apply_entry(&entry, &mut regs, &reader, 0x1000, true).unwrap());
        assert_eq!(regs.pc(), Some(0xBEEF_0001));
        assert_eq!(regs.sp(), Some(base + 0x80 + stack_size));
    }

    #[test]
    fn apply_frameless_immediate_arm64_lr() {
        let base = 0x3000u64;
        let data = vec![0u8; 0x200];
        let stack_size = 32u64;

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };

        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_sp(base + 0x80);
        regs.set_pc(0xAAAA);
        regs.set(super::super::registers::arm64::LR, 0xCAFE_BABE);

        let entry = CompactEntry::FramelessImmediate {
            stack_size,
            saved_regs: Vec::new(),
            return_address_register: Some(super::super::registers::arm64::LR),
        };

        assert!(apply_entry(&entry, &mut regs, &reader, 0x1000, true).unwrap());
        // Return address comes from LR, not from stack
        assert_eq!(regs.pc(), Some(0xCAFE_BABE));
        assert_eq!(regs.sp(), Some(base + 0x80 + stack_size));
    }

    // ======================================================================
    // Lookup tests with synthetic __unwind_info
    // ======================================================================

    /// Builds a synthetic __unwind_info section with both regular and compressed
    /// second-level pages, suitable for testing the full lookup path.
    ///
    /// Layout (image_base relative offsets as func_offsets):
    ///   First-level entry 0: covers funcs 0x0000..0x0FFF (regular page)
    ///     Regular entry 0: func=0x0000, encoding=0x0400_0001 (ARM64 frame, X19/X20)
    ///     Regular entry 1: func=0x0100, encoding=0x0200_2000 (ARM64 frameless, stack=32)
    ///   First-level entry 1: covers funcs 0x1000..0xFFFE (compressed page)
    ///     Compressed entry 0: func=0x1000+0x000=0x1000, encoding=common[0]
    ///     Compressed entry 1: func=0x1000+0x200=0x1200, encoding=local[0]
    ///   Sentinel: func=0xFFFF
    fn build_synthetic_unwind_info() -> (SliceMemoryReader, SectionRef) {
        let base = 0x10_0000u64;
        let mut data = vec![0u8; 256];

        let w32 = |d: &mut Vec<u8>, off: usize, val: u32| {
            d[off..off + 4].copy_from_slice(&val.to_le_bytes());
        };
        let w16 = |d: &mut Vec<u8>, off: usize, val: u16| {
            d[off..off + 2].copy_from_slice(&val.to_le_bytes());
        };

        // === Header (28 bytes at offset 0) ===
        w32(&mut data, 0, 1); // version
        w32(&mut data, 4, 28); // commonEncodingsArraySectionOffset
        w32(&mut data, 8, 2); // commonEncodingsArrayCount
        w32(&mut data, 12, 36); // personalityArraySectionOffset (unused, points past common enc)
        w32(&mut data, 16, 0); // personalityArrayCount
        w32(&mut data, 20, 36); // indexSectionOffset
        w32(&mut data, 24, 3); // indexCount (2 real + 1 sentinel)

        // === Common encodings (8 bytes at offset 28) ===
        w32(&mut data, 28, 0x0400_0001); // ARM64 frame, X19/X20
        w32(&mut data, 32, 0x0200_2000); // ARM64 frameless, stack=32

        // === First-level index (36 bytes at offset 36) ===
        // entry[0]
        w32(&mut data, 36, 0x0000); // functionOffset
        w32(&mut data, 40, 72); // secondLevelPagesSectionOffset
        w32(&mut data, 44, 0); // lsda
        // entry[1]
        w32(&mut data, 48, 0x1000); // functionOffset
        w32(&mut data, 52, 104); // secondLevelPagesSectionOffset
        w32(&mut data, 56, 0); // lsda
        // entry[2] (sentinel)
        w32(&mut data, 60, 0xFFFF); // functionOffset
        w32(&mut data, 64, 0); // secondLevelPagesSectionOffset = 0
        w32(&mut data, 68, 0); // lsda

        // === Regular second-level page (at offset 72) ===
        w32(&mut data, 72, 2); // kind = REGULAR
        w16(&mut data, 76, 8); // entryPageOffset (entries at 72+8=80)
        w16(&mut data, 78, 2); // entryCount
        // entries at offset 80
        w32(&mut data, 80, 0x0000); // funcOffset
        w32(&mut data, 84, 0x0400_0001); // encoding (same as common[0])
        w32(&mut data, 88, 0x0100); // funcOffset
        w32(&mut data, 92, 0x0200_2000); // encoding (same as common[1])

        // === Compressed second-level page (at offset 104) ===
        w32(&mut data, 104, 3); // kind = COMPRESSED
        w16(&mut data, 108, 12); // entryPageOffset (entries at 104+12=116)
        w16(&mut data, 110, 2); // entryCount
        w16(&mut data, 112, 20); // encodingsPageOffset (encodings at 104+20=124)
        w16(&mut data, 114, 1); // encodingsCount (1 page-local encoding)
        // compressed entries at offset 116
        // entry[0]: encoding_index=0 (common[0]), func_delta=0x000
        w32(&mut data, 116, (0u32 << 24) | 0x000000);
        // entry[1]: encoding_index=2 (local[0]), func_delta=0x200
        w32(&mut data, 120, (2u32 << 24) | 0x000200);
        // page-local encodings at offset 124
        w32(&mut data, 124, 0x0300_0042); // ARM64 DWARF, fde_offset=0x42

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };
        let section = SectionRef {
            vm_addr: base,
            size: 256,
        };

        (reader, section)
    }

    #[test]
    fn lookup_regular_page_first_entry() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // PC in first function (offset 0x0050)
        let result = lookup_encoding(&reader, &section, base + 0x0050, base);
        assert_eq!(result, Some((0x0400_0001, 0x0000)));
    }

    #[test]
    fn lookup_regular_page_second_entry() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // PC in second function (offset 0x0150)
        let result = lookup_encoding(&reader, &section, base + 0x0150, base);
        assert_eq!(result, Some((0x0200_2000, 0x0100)));
    }

    #[test]
    fn lookup_compressed_page_first_entry() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // PC in first compressed entry (offset 0x1050, func_base=0x1000)
        let result = lookup_encoding(&reader, &section, base + 0x1050, base);
        assert_eq!(result, Some((0x0400_0001, 0x1000)));
    }

    #[test]
    fn lookup_compressed_page_second_entry() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // PC in second compressed entry (offset 0x1300, func_base=0x1200)
        // encoding_index=2 → local[0] = 0x0300_0042
        let result = lookup_encoding(&reader, &section, base + 0x1300, base);
        assert_eq!(result, Some((0x0300_0042, 0x1200)));
    }

    #[test]
    fn lookup_compressed_page_local_encoding() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // Verify the page-local encoding (DWARF with fde_offset=0x42)
        let result = lookup_encoding(&reader, &section, base + 0x1200, base);
        let (encoding, func_base) = result.unwrap();
        assert_eq!(func_base, 0x1200);
        // The synthetic data uses ARM64 encodings
        let entry = decode_arm64(encoding);
        match entry {
            CompactEntry::Dwarf { fde_offset } => assert_eq!(fde_offset, 0x42),
            _ => panic!("expected Dwarf, got {:?}", entry),
        }
    }

    #[test]
    fn lookup_pc_before_image_returns_none() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // PC before image base
        let result = lookup_encoding(&reader, &section, base - 1, base);
        assert!(result.is_none());
    }

    #[test]
    fn lookup_func_start_from_regular_page() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // Verify that func_base accurately identifies the function start
        // PC at offset 0x01FF (still within second regular entry's range)
        let result = lookup_encoding(&reader, &section, base + 0x01FF, base);
        let (_, func_base) = result.unwrap();
        assert_eq!(func_base, 0x0100);

        // The actual function start address in memory:
        let func_start = base + func_base as u64;
        assert_eq!(func_start, base + 0x0100);
    }

    #[test]
    fn lookup_func_start_from_compressed_page() {
        let (reader, section) = build_synthetic_unwind_info();
        let base = reader.base_address;

        // PC deep into the second compressed entry
        let result = lookup_encoding(&reader, &section, base + 0x13FF, base);
        let (_, func_base) = result.unwrap();
        assert_eq!(func_base, 0x1200);

        let func_start = base + func_base as u64;
        assert_eq!(func_start, base + 0x1200);
    }
}
