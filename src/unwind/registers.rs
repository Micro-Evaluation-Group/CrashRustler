//! Architecture-abstracted register context indexed by DWARF register number.

use crate::types::{CpuType, ThreadState};

/// Maximum number of DWARF registers we track.
const MAX_REGS: usize = 96;

/// Register context holding register values indexed by DWARF register number.
///
/// Supports ARM64 and x86_64 DWARF register maps.
#[derive(Debug, Clone)]
pub struct RegisterContext {
    regs: [Option<u64>; MAX_REGS],
    pub cpu_type: CpuType,
    pub is_64_bit: bool,
}

// ARM64 DWARF register numbers
pub mod arm64 {
    // X0-X28 = DWARF 0-28
    pub const FP: u16 = 29; // X29
    pub const LR: u16 = 30; // X30
    pub const SP: u16 = 31;
    pub const PC: u16 = 32; // not a real DWARF reg, we use it internally

    /// Non-volatile registers: X19-X28, FP, LR
    pub const NON_VOLATILE: &[u16] = &[19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
}

// x86_64 DWARF register numbers
pub mod x86_64 {
    pub const RAX: u16 = 0;
    pub const RDX: u16 = 1;
    pub const RCX: u16 = 2;
    pub const RBX: u16 = 3;
    pub const RSI: u16 = 4;
    pub const RDI: u16 = 5;
    pub const RBP: u16 = 6;
    pub const RSP: u16 = 7;
    pub const R8: u16 = 8;
    pub const R9: u16 = 9;
    pub const R10: u16 = 10;
    pub const R11: u16 = 11;
    pub const R12: u16 = 12;
    pub const R13: u16 = 13;
    pub const R14: u16 = 14;
    pub const R15: u16 = 15;
    pub const RIP: u16 = 16;
    // DWARF 49 = RFLAGS (used by some producers)
    pub const RFLAGS: u16 = 49;

    /// Non-volatile registers: RBX, RBP, R12-R15
    pub const NON_VOLATILE: &[u16] = &[3, 6, 12, 13, 14, 15];
}

impl RegisterContext {
    /// Creates a new empty register context.
    pub fn new(cpu_type: CpuType) -> Self {
        Self {
            regs: [None; MAX_REGS],
            cpu_type,
            is_64_bit: cpu_type.is_64_bit(),
        }
    }

    /// Gets the program counter.
    pub fn pc(&self) -> Option<u64> {
        if self.is_arm() {
            // Try internal PC slot first, then LR
            self.regs[arm64::PC as usize].or(self.regs[arm64::LR as usize])
        } else {
            self.regs[x86_64::RIP as usize]
        }
    }

    /// Gets the stack pointer.
    pub fn sp(&self) -> Option<u64> {
        if self.is_arm() {
            self.regs[arm64::SP as usize]
        } else {
            self.regs[x86_64::RSP as usize]
        }
    }

    /// Gets the frame pointer.
    pub fn fp(&self) -> Option<u64> {
        if self.is_arm() {
            self.regs[arm64::FP as usize]
        } else {
            self.regs[x86_64::RBP as usize]
        }
    }

    /// Gets the link register (ARM64 only, returns None for x86_64).
    pub fn lr(&self) -> Option<u64> {
        if self.is_arm() {
            self.regs[arm64::LR as usize]
        } else {
            None
        }
    }

    /// Gets a register by DWARF number.
    pub fn get(&self, dwarf_reg: u16) -> Option<u64> {
        if (dwarf_reg as usize) < MAX_REGS {
            self.regs[dwarf_reg as usize]
        } else {
            None
        }
    }

    /// Sets a register by DWARF number.
    pub fn set(&mut self, dwarf_reg: u16, value: u64) {
        if (dwarf_reg as usize) < MAX_REGS {
            self.regs[dwarf_reg as usize] = Some(value);
        }
    }

    /// Clears a register by DWARF number.
    pub fn clear(&mut self, dwarf_reg: u16) {
        if (dwarf_reg as usize) < MAX_REGS {
            self.regs[dwarf_reg as usize] = None;
        }
    }

    /// Sets the program counter.
    pub fn set_pc(&mut self, value: u64) {
        if self.is_arm() {
            self.regs[arm64::PC as usize] = Some(value);
        } else {
            self.regs[x86_64::RIP as usize] = Some(value);
        }
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, value: u64) {
        if self.is_arm() {
            self.regs[arm64::SP as usize] = Some(value);
        } else {
            self.regs[x86_64::RSP as usize] = Some(value);
        }
    }

    /// Sets the frame pointer.
    pub fn set_fp(&mut self, value: u64) {
        if self.is_arm() {
            self.regs[arm64::FP as usize] = Some(value);
        } else {
            self.regs[x86_64::RBP as usize] = Some(value);
        }
    }

    /// Clears all volatile registers, keeping only non-volatile ones + SP + PC.
    pub fn clear_volatile(&mut self) {
        let non_volatile = if self.is_arm() {
            arm64::NON_VOLATILE
        } else {
            x86_64::NON_VOLATILE
        };

        let saved: Vec<(u16, Option<u64>)> =
            non_volatile.iter().map(|&r| (r, self.get(r))).collect();
        let sp = self.sp();
        let pc = self.pc();

        self.regs = [None; MAX_REGS];

        for (r, v) in saved {
            if let Some(val) = v {
                self.set(r, val);
            }
        }
        if let Some(v) = sp {
            self.set_sp(v);
        }
        if let Some(v) = pc {
            self.set_pc(v);
        }
    }

    /// Converts from the existing `ThreadState` type used by CrashRustler.
    pub fn from_thread_state(state: &ThreadState, cpu_type: CpuType) -> Option<Self> {
        let mut ctx = Self::new(cpu_type);
        let regs = &state.registers;
        let flavor = state.flavor;

        if cpu_type == CpuType::ARM64 || cpu_type == CpuType::ARM {
            ctx.populate_from_arm_thread_state(flavor, regs)?;
        } else if cpu_type == CpuType::X86_64 || cpu_type == CpuType::X86 {
            ctx.populate_from_x86_thread_state(flavor, regs)?;
        } else {
            return None;
        }

        Some(ctx)
    }

    fn populate_from_arm_thread_state(&mut self, flavor: u32, regs: &[u32]) -> Option<()> {
        match flavor {
            6 if regs.len() >= 68 => {
                // ARM_THREAD_STATE64: 33 registers * 2 u32s + cpsr + pad
                self.read_arm64_regs(regs, 0);
                Some(())
            }
            1 if !regs.is_empty() => {
                let sub_flavor = regs[0];
                if sub_flavor == 2 && regs.len() >= 70 {
                    // ARM_THREAD_STATE, sub_flavor=2 (ARM64)
                    self.read_arm64_regs(regs, 2);
                    Some(())
                } else {
                    None // ARM32 not supported for unwinding
                }
            }
            _ => None,
        }
    }

    fn read_arm64_regs(&mut self, regs: &[u32], offset: usize) {
        let r64 = |idx: usize| -> u64 {
            let base = offset + idx * 2;
            (regs[base] as u64) | ((regs[base + 1] as u64) << 32)
        };

        // X0-X28
        for i in 0..29 {
            self.set(i as u16, r64(i));
        }
        // FP (X29)
        self.set(arm64::FP, r64(29));
        // LR (X30)
        self.set(arm64::LR, r64(30));
        // SP
        self.set(arm64::SP, r64(31));
        // PC
        self.set(arm64::PC, r64(32));
    }

    fn populate_from_x86_thread_state(&mut self, flavor: u32, regs: &[u32]) -> Option<()> {
        match flavor {
            7 if !regs.is_empty() => {
                let sub_flavor = regs[0];
                if sub_flavor == 1 && regs.len() >= 18 {
                    // 32-bit x86 — not supported for unwinding
                    return None;
                }
                if regs.len() >= 44 {
                    // 64-bit x86
                    self.read_x86_64_regs(regs, 2);
                    return Some(());
                }
                None
            }
            _ => None,
        }
    }

    fn read_x86_64_regs(&mut self, regs: &[u32], offset: usize) {
        let r64 = |idx: usize| -> u64 {
            let base = offset + idx * 2;
            (regs[base] as u64) | ((regs[base + 1] as u64) << 32)
        };

        // x86_THREAD_STATE64 layout: rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp,
        // r8, r9, r10, r11, r12, r13, r14, r15, rip, rflags, cs, fs, gs
        self.set(x86_64::RAX, r64(0));
        self.set(x86_64::RBX, r64(1));
        self.set(x86_64::RCX, r64(2));
        self.set(x86_64::RDX, r64(3));
        self.set(x86_64::RDI, r64(4));
        self.set(x86_64::RSI, r64(5));
        self.set(x86_64::RBP, r64(6));
        self.set(x86_64::RSP, r64(7));
        self.set(x86_64::R8, r64(8));
        self.set(x86_64::R9, r64(9));
        self.set(x86_64::R10, r64(10));
        self.set(x86_64::R11, r64(11));
        self.set(x86_64::R12, r64(12));
        self.set(x86_64::R13, r64(13));
        self.set(x86_64::R14, r64(14));
        self.set(x86_64::R15, r64(15));
        self.set(x86_64::RIP, r64(16));
        self.set(x86_64::RFLAGS, r64(17));
    }

    fn is_arm(&self) -> bool {
        self.cpu_type == CpuType::ARM64 || self.cpu_type == CpuType::ARM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_context_is_empty() {
        let ctx = RegisterContext::new(CpuType::ARM64);
        assert!(ctx.pc().is_none());
        assert!(ctx.sp().is_none());
        assert!(ctx.fp().is_none());
        assert!(ctx.lr().is_none());
    }

    #[test]
    fn arm64_set_get_registers() {
        let mut ctx = RegisterContext::new(CpuType::ARM64);
        ctx.set(0, 0xAAAA);
        ctx.set(arm64::FP, 0xBBBB);
        ctx.set(arm64::LR, 0xCCCC);
        ctx.set(arm64::SP, 0xDDDD);
        ctx.set(arm64::PC, 0xEEEE);

        assert_eq!(ctx.get(0), Some(0xAAAA));
        assert_eq!(ctx.fp(), Some(0xBBBB));
        assert_eq!(ctx.lr(), Some(0xCCCC));
        assert_eq!(ctx.sp(), Some(0xDDDD));
        assert_eq!(ctx.pc(), Some(0xEEEE));
    }

    #[test]
    fn x86_64_set_get_registers() {
        let mut ctx = RegisterContext::new(CpuType::X86_64);
        ctx.set(x86_64::RAX, 0x1111);
        ctx.set(x86_64::RBP, 0x2222);
        ctx.set(x86_64::RSP, 0x3333);
        ctx.set(x86_64::RIP, 0x4444);

        assert_eq!(ctx.get(x86_64::RAX), Some(0x1111));
        assert_eq!(ctx.fp(), Some(0x2222));
        assert_eq!(ctx.sp(), Some(0x3333));
        assert_eq!(ctx.pc(), Some(0x4444));
        // x86_64 has no LR
        assert!(ctx.lr().is_none());
    }

    #[test]
    fn from_thread_state_arm64_flavor6() {
        let mut regs = vec![0u32; 68];
        regs[0] = 0xCAFE_BABE; // x0 low
        regs[1] = 0x0000_0001; // x0 high
        regs[58] = 0x1111_0000; // FP low (index 29*2)
        regs[59] = 0x0000_AAAA; // FP high
        regs[60] = 0x2222_0000; // LR low (index 30*2)
        regs[61] = 0x0000_BBBB; // LR high
        regs[62] = 0x3333_0000; // SP low (index 31*2)
        regs[63] = 0x0000_CCCC; // SP high
        regs[64] = 0x4444_0000; // PC low (index 32*2)
        regs[65] = 0x0000_DDDD; // PC high

        let state = ThreadState {
            flavor: 6,
            registers: regs,
        };
        let ctx = RegisterContext::from_thread_state(&state, CpuType::ARM64).unwrap();
        assert_eq!(ctx.get(0), Some(0x0000_0001_CAFE_BABE));
        assert_eq!(ctx.fp(), Some(0x0000_AAAA_1111_0000));
        assert_eq!(ctx.lr(), Some(0x0000_BBBB_2222_0000));
        assert_eq!(ctx.sp(), Some(0x0000_CCCC_3333_0000));
        assert_eq!(ctx.pc(), Some(0x0000_DDDD_4444_0000));
    }

    #[test]
    fn from_thread_state_x86_64_flavor7() {
        let mut regs = vec![0u32; 44];
        regs[0] = 4; // sub_flavor (64-bit)
        regs[1] = 0;
        // rax at offset 2 (index 0)
        regs[2] = 0xDEAD_BEEF;
        regs[3] = 0x0000_0001;
        // rbp at offset 2+6*2=14 (index 6)
        regs[14] = 0xAAAA_0000;
        regs[15] = 0x0000_FFFF;
        // rsp at offset 2+7*2=16 (index 7)
        regs[16] = 0xBBBB_0000;
        regs[17] = 0x0000_EEEE;
        // rip at offset 2+16*2=34 (index 16)
        regs[34] = 0xCCCC_0000;
        regs[35] = 0x0000_DDDD;

        let state = ThreadState {
            flavor: 7,
            registers: regs,
        };
        let ctx = RegisterContext::from_thread_state(&state, CpuType::X86_64).unwrap();
        assert_eq!(ctx.get(x86_64::RAX), Some(0x0000_0001_DEAD_BEEF));
        assert_eq!(ctx.fp(), Some(0x0000_FFFF_AAAA_0000));
        assert_eq!(ctx.sp(), Some(0x0000_EEEE_BBBB_0000));
        assert_eq!(ctx.pc(), Some(0x0000_DDDD_CCCC_0000));
    }

    #[test]
    fn clear_volatile_arm64() {
        let mut ctx = RegisterContext::new(CpuType::ARM64);
        // Set volatile (x0) and non-volatile (x19, fp, lr)
        ctx.set(0, 0x1111); // x0 - volatile
        ctx.set(19, 0x2222); // x19 - non-volatile
        ctx.set(arm64::FP, 0x3333);
        ctx.set(arm64::LR, 0x4444);
        ctx.set(arm64::SP, 0x5555);
        ctx.set(arm64::PC, 0x6666);

        ctx.clear_volatile();

        assert!(ctx.get(0).is_none()); // x0 cleared
        assert_eq!(ctx.get(19), Some(0x2222)); // x19 preserved
        assert_eq!(ctx.fp(), Some(0x3333));
        // LR is non-volatile on ARM64
        assert_eq!(ctx.lr(), Some(0x4444));
        assert_eq!(ctx.sp(), Some(0x5555));
        assert_eq!(ctx.pc(), Some(0x6666));
    }

    #[test]
    fn clear_volatile_x86_64() {
        let mut ctx = RegisterContext::new(CpuType::X86_64);
        ctx.set(x86_64::RAX, 0x1111); // volatile
        ctx.set(x86_64::RBX, 0x2222); // non-volatile
        ctx.set(x86_64::RBP, 0x3333); // non-volatile
        ctx.set(x86_64::RSP, 0x4444);
        ctx.set(x86_64::RIP, 0x5555);
        ctx.set(x86_64::R12, 0x6666); // non-volatile

        ctx.clear_volatile();

        assert!(ctx.get(x86_64::RAX).is_none()); // cleared
        assert_eq!(ctx.get(x86_64::RBX), Some(0x2222));
        assert_eq!(ctx.fp(), Some(0x3333));
        assert_eq!(ctx.sp(), Some(0x4444));
        assert_eq!(ctx.pc(), Some(0x5555));
        assert_eq!(ctx.get(x86_64::R12), Some(0x6666));
    }

    #[test]
    fn from_thread_state_unsupported_cpu() {
        let state = ThreadState {
            flavor: 0,
            registers: vec![],
        };
        assert!(RegisterContext::from_thread_state(&state, CpuType::POWERPC).is_none());
    }
}
