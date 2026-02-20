//! Architecture-specific DWARF register maps and compact unwind encoding decoders.

use super::registers::{arm64, x86_64};

// ==========================================================================
// DWARF register number to name (for debugging)
// ==========================================================================

/// Returns the register name for an ARM64 DWARF register number.
pub fn arm64_reg_name(dwarf_reg: u16) -> &'static str {
    match dwarf_reg {
        0..=28 => {
            const NAMES: [&str; 29] = [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                "x25", "x26", "x27", "x28",
            ];
            NAMES[dwarf_reg as usize]
        }
        29 => "fp",
        30 => "lr",
        31 => "sp",
        32 => "pc",
        _ => "?",
    }
}

/// Returns the register name for an x86_64 DWARF register number.
pub fn x86_64_reg_name(dwarf_reg: u16) -> &'static str {
    match dwarf_reg {
        0 => "rax",
        1 => "rdx",
        2 => "rcx",
        3 => "rbx",
        4 => "rsi",
        5 => "rdi",
        6 => "rbp",
        7 => "rsp",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        15 => "r15",
        16 => "rip",
        49 => "rflags",
        _ => "?",
    }
}

// ==========================================================================
// Compact unwind encoding constants
// ==========================================================================

/// ARM64 compact unwind mode (bits 27-24).
pub mod arm64_compact {
    pub const MODE_MASK: u32 = 0x0F00_0000;
    pub const MODE_FRAMELESS: u32 = 0x0200_0000;
    pub const MODE_DWARF: u32 = 0x0300_0000;
    pub const MODE_FRAME: u32 = 0x0400_0000;

    /// Saved register pair bit positions for frame-based unwinding.
    /// Bits 12-0 encode which register pairs are saved at FP-offset.
    /// Each pair of registers is: (X19,X20), (X21,X22), ..., (X27,X28), (D8,D9), ..., (D14,D15)
    pub const FRAME_REG_PAIRS: &[(u16, u16)] = &[
        (19, 20), // bit 0
        (21, 22), // bit 1
        (23, 24), // bit 2
        (25, 26), // bit 3
        (27, 28), // bit 4
                  // bits 5-8 are D8-D15 pairs (FP registers, not tracked)
    ];

    /// Frameless: stack size in 16-byte units from bits 23-12.
    pub const FRAMELESS_STACK_SIZE_MASK: u32 = 0x00FF_F000;
    pub const FRAMELESS_STACK_SIZE_SHIFT: u32 = 12;

    /// DWARF: FDE offset in bits 23-0.
    pub const DWARF_FDE_OFFSET_MASK: u32 = 0x00FF_FFFF;
}

/// x86_64 compact unwind mode (bits 27-24).
pub mod x86_64_compact {
    pub const MODE_MASK: u32 = 0x0F00_0000;
    pub const MODE_FRAME: u32 = 0x0100_0000;
    pub const MODE_FRAMELESS_IMMEDIATE: u32 = 0x0200_0000;
    pub const MODE_FRAMELESS_INDIRECT: u32 = 0x0300_0000;
    pub const MODE_DWARF: u32 = 0x0400_0000;

    /// Frame-based: offset from RBP to first saved register, in 8-byte units (bits 23-16).
    pub const FRAME_OFFSET_MASK: u32 = 0x00FF_0000;
    pub const FRAME_OFFSET_SHIFT: u32 = 16;

    /// Frame-based: saved register bits 14-0.
    /// Each 3-bit field encodes which register is saved at that slot.
    pub const FRAME_REG_MASK: u32 = 0x0000_7FFF;

    /// Frameless immediate: stack size in 8-byte units from bits 23-16.
    pub const FRAMELESS_STACK_SIZE_MASK: u32 = 0x00FF_0000;
    pub const FRAMELESS_STACK_SIZE_SHIFT: u32 = 16;
    /// Register count from bits 15-10.
    pub const FRAMELESS_REG_COUNT_MASK: u32 = 0x0000_FC00;
    pub const FRAMELESS_REG_COUNT_SHIFT: u32 = 10;
    /// Permutation encoding from bits 9-0.
    pub const FRAMELESS_PERMUTATION_MASK: u32 = 0x0000_03FF;

    /// Frameless indirect: offset to stack size in function body from bits 23-16.
    pub const INDIRECT_STACK_OFFSET_MASK: u32 = 0x00FF_0000;
    pub const INDIRECT_STACK_OFFSET_SHIFT: u32 = 16;
    /// Stack adjust from bits 15-13.
    pub const INDIRECT_STACK_ADJUST_MASK: u32 = 0x0000_E000;
    pub const INDIRECT_STACK_ADJUST_SHIFT: u32 = 13;

    /// DWARF: FDE offset in bits 23-0.
    pub const DWARF_FDE_OFFSET_MASK: u32 = 0x00FF_FFFF;

    /// Register encoding for x86_64 frame-based save slots.
    /// 3-bit value → DWARF register number.
    pub const FRAME_REG_MAP: [u16; 7] = [
        0, // 0 = none
        super::x86_64::RBX,
        super::x86_64::R12,
        super::x86_64::R13,
        super::x86_64::R14,
        super::x86_64::R15,
        super::x86_64::RBP,
    ];
}

// ==========================================================================
// Compact unwind decoding helpers
// ==========================================================================

/// Decodes ARM64 frameless permutation encoding.
/// Returns the DWARF register numbers of saved register pairs.
pub fn arm64_decode_frameless_regs(encoding: u32) -> Vec<u16> {
    // Bits 19-12: register permutation encoding
    // This encodes up to 5 register pairs using a factorial numbering system
    let _stack_size = ((encoding & arm64_compact::FRAMELESS_STACK_SIZE_MASK)
        >> arm64_compact::FRAMELESS_STACK_SIZE_SHIFT) as u64
        * 16;
    // For ARM64 frameless, the permutation encoding is simpler:
    // it's a bitmask of which register pairs to save, same as frame-based
    let mut regs = Vec::new();
    for (bit, &(r1, r2)) in arm64_compact::FRAME_REG_PAIRS.iter().enumerate() {
        if encoding & (1 << bit) != 0 {
            regs.push(r1);
            regs.push(r2);
        }
    }
    regs
}

/// Decodes x86_64 permutation encoding for frameless functions.
/// Returns the DWARF register numbers in stack order (bottom to top).
pub fn x86_64_decode_permutation(encoding: u32) -> Vec<u16> {
    let reg_count = ((encoding & x86_64_compact::FRAMELESS_REG_COUNT_MASK)
        >> x86_64_compact::FRAMELESS_REG_COUNT_SHIFT) as usize;
    let permutation = (encoding & x86_64_compact::FRAMELESS_PERMUTATION_MASK) as usize;

    if reg_count == 0 || reg_count > 6 {
        return Vec::new();
    }

    // The permutation encoding uses a factorial numbering system.
    // Possible registers: RBX, R12, R13, R14, R15, RBP (DWARF 3, 12, 13, 14, 15, 6)
    let all_regs: [u16; 6] = [
        x86_64::RBX,
        x86_64::R12,
        x86_64::R13,
        x86_64::R14,
        x86_64::R15,
        x86_64::RBP,
    ];

    let mut available: Vec<u16> = all_regs[..reg_count].to_vec();
    let mut result = Vec::with_capacity(reg_count);
    let mut perm = permutation;

    for i in (1..=reg_count).rev() {
        let idx = perm / factorial(i - 1);
        perm %= factorial(i - 1);
        if idx < available.len() {
            result.push(available.remove(idx));
        }
    }

    result
}

fn factorial(n: usize) -> usize {
    match n {
        0 | 1 => 1,
        2 => 2,
        3 => 6,
        4 => 24,
        5 => 120,
        _ => 720,
    }
}

/// Returns the return address register for the given CPU type.
pub fn return_address_register(is_arm: bool) -> u16 {
    if is_arm { arm64::LR } else { x86_64::RIP }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_reg_names() {
        assert_eq!(arm64_reg_name(0), "x0");
        assert_eq!(arm64_reg_name(28), "x28");
        assert_eq!(arm64_reg_name(29), "fp");
        assert_eq!(arm64_reg_name(30), "lr");
        assert_eq!(arm64_reg_name(31), "sp");
        assert_eq!(arm64_reg_name(32), "pc");
        assert_eq!(arm64_reg_name(99), "?");
    }

    #[test]
    fn x86_64_reg_names() {
        assert_eq!(x86_64_reg_name(0), "rax");
        assert_eq!(x86_64_reg_name(6), "rbp");
        assert_eq!(x86_64_reg_name(7), "rsp");
        assert_eq!(x86_64_reg_name(16), "rip");
        assert_eq!(x86_64_reg_name(49), "rflags");
        assert_eq!(x86_64_reg_name(99), "?");
    }

    #[test]
    fn x86_64_decode_permutation_empty() {
        // reg_count = 0
        let encoding = 0u32;
        assert!(x86_64_decode_permutation(encoding).is_empty());
    }

    #[test]
    fn x86_64_decode_permutation_single() {
        // reg_count = 1, permutation = 0 → RBX
        let encoding = (1 << x86_64_compact::FRAMELESS_REG_COUNT_SHIFT) | 0;
        let regs = x86_64_decode_permutation(encoding);
        assert_eq!(regs, vec![x86_64::RBX]);
    }

    #[test]
    fn return_address_register_arm64() {
        assert_eq!(return_address_register(true), arm64::LR);
    }

    #[test]
    fn return_address_register_x86_64() {
        assert_eq!(return_address_register(false), x86_64::RIP);
    }
}
