//! Frame cursor: drives the compact → DWARF → FP fallback chain.
//!
//! Orchestrates the unwinding process for each frame, trying compact unwind
//! first, then DWARF CFI, then frame pointer walking as a last resort.

use super::compact_unwind::{self, CompactEntry};
use super::dwarf_cfi;
use super::frame_pointer;
use super::registers::RegisterContext;
use super::{BinaryImageInfo, MemoryReader, UnwindError};

/// Maximum unwind depth to prevent infinite loops.
const DEFAULT_MAX_DEPTH: u32 = 512;

/// ARM64 PAC mask: strip pointer authentication bits (39-bit VA space).
const ARM64_PAC_MASK: u64 = 0x0000_007F_FFFF_FFFF;

/// Frame cursor that walks the stack frame by frame.
pub struct FrameCursor<'a> {
    reader: &'a dyn MemoryReader,
    regs: RegisterContext,
    images: &'a mut [BinaryImageInfo],
    is_64_bit: bool,
    depth: u32,
    max_depth: u32,
}

impl<'a> FrameCursor<'a> {
    /// Creates a new frame cursor.
    pub fn new(
        reader: &'a dyn MemoryReader,
        regs: RegisterContext,
        images: &'a mut [BinaryImageInfo],
        is_64_bit: bool,
    ) -> Self {
        Self {
            reader,
            regs,
            images,
            is_64_bit,
            depth: 0,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    /// Returns the current PC.
    pub fn pc(&self) -> Option<u64> {
        self.regs.pc()
    }

    /// Returns the current register context.
    pub fn registers(&self) -> &RegisterContext {
        &self.regs
    }

    /// Steps one frame. Returns `Ok(true)` if a frame was found,
    /// `Ok(false)` if at the bottom of the stack.
    pub fn step(&mut self) -> Result<bool, UnwindError> {
        self.depth += 1;
        if self.depth >= self.max_depth {
            return Err(UnwindError::MaxDepthExceeded(self.max_depth));
        }

        let pc = self.regs.pc().ok_or(UnwindError::NullPC)?;

        // Strip PAC bits on ARM64 targets (regardless of host architecture)
        let pc = if self.regs.cpu_type == crate::types::CpuType::ARM64 {
            pc & ARM64_PAC_MASK
        } else {
            pc
        };

        // Null PC = bottom of stack
        if pc == 0 || (self.is_64_bit && pc < 0x1000) || (!self.is_64_bit && pc < 0x100) {
            return Ok(false);
        }

        // Find containing binary image
        let image_idx = self.find_image(pc);

        if let Some(idx) = image_idx {
            // Ensure sections are resolved
            self.images[idx].resolve_sections(self.reader);
            let image = &self.images[idx];

            // Try compact unwind first
            if let Some(ref unwind_info) = image.unwind_info
                && let Some((encoding, func_base)) = compact_unwind::lookup_encoding(
                    self.reader,
                    unwind_info,
                    pc,
                    image.load_address,
                )
            {
                let entry = compact_unwind::decode_encoding(encoding, self.regs.cpu_type);

                match &entry {
                    CompactEntry::Dwarf { fde_offset } => {
                        // Compact says use DWARF
                        if let Some(ref eh_frame) = self.images[idx].eh_frame {
                            let target_addr = eh_frame.vm_addr + *fde_offset as u64;
                            if let Some(fde) = dwarf_cfi::find_fde(
                                self.reader,
                                eh_frame,
                                target_addr,
                                self.is_64_bit,
                            ) {
                                let new_regs = dwarf_cfi::apply_dwarf_unwind(
                                    &fde,
                                    pc,
                                    &self.regs,
                                    self.reader,
                                    self.is_64_bit,
                                )?;
                                self.regs = new_regs;
                                return Ok(true);
                            }
                        }
                        // DWARF lookup failed, try FP
                    }
                    CompactEntry::None => {
                        // No unwind info, try DWARF then FP
                    }
                    _ => {
                        // Apply compact unwind with actual function start address
                        let func_start = self.images[idx].load_address + func_base as u64;
                        if compact_unwind::apply_entry(
                            &entry,
                            &mut self.regs,
                            self.reader,
                            func_start,
                            self.is_64_bit,
                        )? {
                            return Ok(true);
                        }
                    }
                }
            }

            // Try DWARF .eh_frame
            if let Some(ref eh_frame) = self.images[idx].eh_frame
                && let Some(fde) = dwarf_cfi::find_fde(self.reader, eh_frame, pc, self.is_64_bit)
            {
                let result = dwarf_cfi::apply_dwarf_unwind(
                    &fde,
                    pc,
                    &self.regs,
                    self.reader,
                    self.is_64_bit,
                );
                if let Ok(new_regs) = result {
                    self.regs = new_regs;
                    return Ok(true);
                }
                // DWARF failed, fall through to FP
            }
        }

        // Fallback: frame pointer walking
        frame_pointer::step_frame_pointer(self.reader, &mut self.regs, self.is_64_bit)
    }

    fn find_image(&self, pc: u64) -> Option<usize> {
        self.images.iter().position(|img| img.contains(pc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CpuType;
    use crate::unwind::SliceMemoryReader;

    /// Builds a test setup with a synthetic FP chain (no compact unwind or DWARF).
    fn build_fp_chain_test() -> (SliceMemoryReader, RegisterContext, Vec<BinaryImageInfo>) {
        let base = 0x1_0000_0000u64;
        let mut data = vec![0u8; 0x10000];

        // Frame 0 at FP=base+0x8000
        let f0 = 0x8000usize;
        data[f0..f0 + 8].copy_from_slice(&(base + 0x9000u64).to_le_bytes()); // prev FP
        data[f0 + 8..f0 + 16].copy_from_slice(&(base + 0x2000u64).to_le_bytes()); // return addr

        // Frame 1 at FP=base+0x9000
        let f1 = 0x9000usize;
        data[f1..f1 + 8].copy_from_slice(&(base + 0xA000u64).to_le_bytes()); // prev FP
        data[f1 + 8..f1 + 16].copy_from_slice(&(base + 0x3000u64).to_le_bytes()); // return addr

        // Frame 2 at FP=base+0xA000 (bottom)
        let f2 = 0xA000usize;
        data[f2..f2 + 8].copy_from_slice(&0u64.to_le_bytes()); // null FP = bottom
        data[f2 + 8..f2 + 16].copy_from_slice(&(base + 0x4000u64).to_le_bytes());

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };

        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_fp(base + f0 as u64);
        regs.set_sp(base + f0 as u64 - 16);
        regs.set_pc(base + 0x1000); // initial PC

        let images = vec![BinaryImageInfo {
            name: "test".into(),
            load_address: base,
            end_address: base + 0x10000,
            is_64_bit: true,
            uuid: None,
            unwind_info: None,
            eh_frame: None,
            text_section: None,
            sections_resolved: true,
        }];

        (reader, regs, images)
    }

    #[test]
    fn fp_fallback_walk() {
        let (reader, regs, mut images) = build_fp_chain_test();
        let base = 0x1_0000_0000u64;

        let mut cursor = FrameCursor::new(&reader, regs, &mut images, true);

        // Initial PC
        assert_eq!(cursor.pc(), Some(base + 0x1000));

        // Step 1
        assert!(cursor.step().unwrap());
        assert_eq!(cursor.pc(), Some(base + 0x2000));

        // Step 2
        assert!(cursor.step().unwrap());
        assert_eq!(cursor.pc(), Some(base + 0x3000));

        // Step 3 - reads prev_fp=0 and return_addr, sets FP=0
        assert!(cursor.step().unwrap());
        assert_eq!(cursor.pc(), Some(base + 0x4000));

        // Step 4 - FP=0, bottom of stack
        assert!(!cursor.step().unwrap());
    }

    #[test]
    fn max_depth_exceeded() {
        let (reader, regs, mut images) = build_fp_chain_test();

        let mut cursor = FrameCursor::new(&reader, regs, &mut images, true);
        cursor.max_depth = 2;

        // Step 1 OK
        assert!(cursor.step().unwrap());
        // Step 2 hits max depth
        assert!(matches!(
            cursor.step(),
            Err(UnwindError::MaxDepthExceeded(2))
        ));
    }

    #[test]
    fn null_pc_stops() {
        let reader = SliceMemoryReader {
            data: vec![0u8; 0x100],
            base_address: 0x1000,
        };

        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_pc(0); // null PC
        regs.set_fp(0x1080);
        regs.set_sp(0x1070);

        let mut images: Vec<BinaryImageInfo> = vec![];
        let mut cursor = FrameCursor::new(&reader, regs, &mut images, true);

        assert!(!cursor.step().unwrap());
    }
}
