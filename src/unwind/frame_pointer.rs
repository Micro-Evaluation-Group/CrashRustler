//! Frame pointer chain walking (fallback unwinder).
//!
//! When neither compact unwind nor DWARF CFI data is available,
//! falls back to walking the frame pointer chain.

use super::registers::RegisterContext;
use super::{MemoryReader, UnwindError};

/// Attempts to unwind one frame by following the frame pointer chain.
///
/// On both ARM64 and x86_64:
/// - `[FP+0]` → previous frame pointer
/// - `[FP+8]` → return address
///
/// Updates `regs` in place with the new FP, SP, and PC.
/// Clears volatile registers.
///
/// Returns `Ok(true)` if a frame was found, `Ok(false)` if at the bottom.
pub fn step_frame_pointer(
    reader: &dyn MemoryReader,
    regs: &mut RegisterContext,
    is_64_bit: bool,
) -> Result<bool, UnwindError> {
    let fp = regs.fp().ok_or(UnwindError::BrokenFrameChain)?;

    if fp == 0 {
        return Ok(false);
    }

    // Validate alignment
    if is_64_bit && fp % 8 != 0 {
        return Err(UnwindError::BrokenFrameChain);
    }

    let ptr_size = if is_64_bit { 8 } else { 4 };

    // Read previous FP and return address
    let prev_fp = reader
        .read_pointer(fp, is_64_bit)
        .ok_or(UnwindError::MemoryReadFailed(fp))?;
    let return_addr = reader
        .read_pointer(fp + ptr_size, is_64_bit)
        .ok_or(UnwindError::MemoryReadFailed(fp + ptr_size))?;

    // Validate: FP should grow (stack grows down, so new FP > old FP for caller)
    // Exception: FP=0 means bottom of stack
    if prev_fp != 0 && prev_fp <= fp {
        return Err(UnwindError::BrokenFrameChain);
    }

    if return_addr == 0 {
        return Ok(false);
    }

    // Clear volatile registers
    regs.clear_volatile();

    // Update registers
    regs.set_fp(prev_fp);
    regs.set_sp(fp + 2 * ptr_size); // SP was FP + 2 pointers (FP + return addr)
    regs.set_pc(return_addr);

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CpuType;
    use crate::unwind::SliceMemoryReader;

    /// Builds a synthetic stack with chained FP/LR frames for ARM64.
    /// Frame layout: [prev_fp, return_addr] at each frame pointer.
    fn build_arm64_stack() -> (SliceMemoryReader, RegisterContext) {
        let base = 0x7000_0000u64;
        let mut data = vec![0u8; 0x1000];

        // Frame 0 at offset 0x800: FP=base+0x800
        //   [FP+0] = prev_fp (base+0x900)
        //   [FP+8] = return_addr (0xDEAD_0001)
        let frame0_off = 0x800usize;
        data[frame0_off..frame0_off + 8].copy_from_slice(&(base + 0x900).to_le_bytes());
        data[frame0_off + 8..frame0_off + 16].copy_from_slice(&0xDEAD_0001u64.to_le_bytes());

        // Frame 1 at offset 0x900: FP=base+0x900
        //   [FP+0] = prev_fp (base+0xA00)
        //   [FP+8] = return_addr (0xDEAD_0002)
        let frame1_off = 0x900usize;
        data[frame1_off..frame1_off + 8].copy_from_slice(&(base + 0xA00).to_le_bytes());
        data[frame1_off + 8..frame1_off + 16].copy_from_slice(&0xDEAD_0002u64.to_le_bytes());

        // Frame 2 at offset 0xA00: FP=base+0xA00 (bottom)
        //   [FP+0] = 0 (no more frames)
        //   [FP+8] = 0xDEAD_0003
        let frame2_off = 0xA00usize;
        data[frame2_off..frame2_off + 8].copy_from_slice(&0u64.to_le_bytes());
        data[frame2_off + 8..frame2_off + 16].copy_from_slice(&0xDEAD_0003u64.to_le_bytes());

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };

        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_fp(base + frame0_off as u64);
        regs.set_sp(base + frame0_off as u64 - 16);
        regs.set_pc(0xCAFE_0000);

        (reader, regs)
    }

    #[test]
    fn walk_three_frames() {
        let (reader, mut regs) = build_arm64_stack();
        let base = 0x7000_0000u64;

        // Step 1: frame 0 → frame 1
        assert!(step_frame_pointer(&reader, &mut regs, true).unwrap());
        assert_eq!(regs.fp(), Some(base + 0x900));
        assert_eq!(regs.pc(), Some(0xDEAD_0001));

        // Step 2: frame 1 → frame 2
        assert!(step_frame_pointer(&reader, &mut regs, true).unwrap());
        assert_eq!(regs.fp(), Some(base + 0xA00));
        assert_eq!(regs.pc(), Some(0xDEAD_0002));

        // Step 3: frame 2 → sets FP=0, PC=0xDEAD_0003 (prev_fp=0 is bottom marker)
        assert!(step_frame_pointer(&reader, &mut regs, true).unwrap());
        assert_eq!(regs.pc(), Some(0xDEAD_0003));
        assert_eq!(regs.fp(), Some(0));

        // Step 4: FP=0, so we're at the bottom
        assert!(!step_frame_pointer(&reader, &mut regs, true).unwrap());
    }

    #[test]
    fn zero_fp_returns_false() {
        let reader = SliceMemoryReader {
            data: vec![0u8; 64],
            base_address: 0x1000,
        };
        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_fp(0);
        regs.set_pc(0x1234);

        assert!(!step_frame_pointer(&reader, &mut regs, true).unwrap());
    }

    #[test]
    fn misaligned_fp_returns_error() {
        let reader = SliceMemoryReader {
            data: vec![0u8; 64],
            base_address: 0x1000,
        };
        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_fp(0x1003); // misaligned

        assert_eq!(
            step_frame_pointer(&reader, &mut regs, true),
            Err(UnwindError::BrokenFrameChain)
        );
    }

    #[test]
    fn fp_not_growing_returns_error() {
        let base = 0x2000u64;
        let mut data = vec![0u8; 0x100];
        // FP at 0x2080 points to prev_fp=0x2040 (going backward = error)
        data[0x80..0x88].copy_from_slice(&(base + 0x40).to_le_bytes());
        data[0x88..0x90].copy_from_slice(&0xAAAAu64.to_le_bytes());

        let reader = SliceMemoryReader {
            data,
            base_address: base,
        };
        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set_fp(base + 0x80);

        assert_eq!(
            step_frame_pointer(&reader, &mut regs, true),
            Err(UnwindError::BrokenFrameChain)
        );
    }

    #[test]
    fn volatile_regs_cleared_after_step() {
        let (reader, mut regs) = build_arm64_stack();
        regs.set(0, 0x1111); // x0 — volatile

        assert!(step_frame_pointer(&reader, &mut regs, true).unwrap());
        assert!(regs.get(0).is_none()); // volatile cleared
    }
}
