//! DWARF expression evaluator (stack machine).
//!
//! Evaluates DWARF expressions used in CFI register rules and CFA definitions.
//! Supports the standard opcodes needed for macOS unwinding.

use super::registers::RegisterContext;
use super::{MemoryReader, UnwindError};

/// DW_OP constants
mod op {
    pub const ADDR: u8 = 0x03;
    pub const DEREF: u8 = 0x06;
    pub const CONST1U: u8 = 0x08;
    pub const CONST1S: u8 = 0x09;
    pub const CONST2U: u8 = 0x0A;
    pub const CONST2S: u8 = 0x0B;
    pub const CONST4U: u8 = 0x0C;
    pub const CONST4S: u8 = 0x0D;
    pub const CONST8U: u8 = 0x0E;
    pub const CONST8S: u8 = 0x0F;
    pub const CONSTU: u8 = 0x10;
    pub const CONSTS: u8 = 0x11;
    pub const DUP: u8 = 0x12;
    pub const DROP: u8 = 0x13;
    pub const OVER: u8 = 0x14;
    pub const PICK: u8 = 0x15;
    pub const SWAP: u8 = 0x16;
    pub const ROT: u8 = 0x17;
    pub const ABS: u8 = 0x19;
    pub const AND: u8 = 0x1A;
    pub const DIV: u8 = 0x1B;
    pub const MINUS: u8 = 0x1C;
    pub const MOD: u8 = 0x1D;
    pub const MUL: u8 = 0x1E;
    pub const NEG: u8 = 0x1F;
    pub const NOT: u8 = 0x20;
    pub const OR: u8 = 0x21;
    pub const PLUS: u8 = 0x22;
    pub const PLUS_UCONST: u8 = 0x23;
    pub const SHL: u8 = 0x24;
    pub const SHR: u8 = 0x25;
    pub const SHRA: u8 = 0x26;
    pub const XOR: u8 = 0x27;
    pub const LIT0: u8 = 0x30; // 0x30 - 0x4F = lit0-lit31
    pub const REG0: u8 = 0x50; // 0x50 - 0x6F = reg0-reg31
    pub const BREG0: u8 = 0x70; // 0x70 - 0x8F = breg0-breg31
    pub const REGX: u8 = 0x90;
    pub const FBREG: u8 = 0x91;
    pub const BREGX: u8 = 0x92;
    pub const DEREF_SIZE: u8 = 0x94;
    pub const NOP: u8 = 0x96;
}

/// Evaluates a DWARF expression and returns the resulting value.
///
/// # Arguments
/// * `expr` — The DWARF expression bytecode.
/// * `regs` — Current register context.
/// * `reader` — Memory reader for DW_OP_deref operations.
/// * `is_64_bit` — Whether addresses are 64-bit.
pub fn evaluate(
    expr: &[u8],
    regs: &RegisterContext,
    reader: &dyn MemoryReader,
    is_64_bit: bool,
) -> Result<u64, UnwindError> {
    let mut stack: Vec<u64> = Vec::new();
    let mut cursor = ExprCursor::new(expr);

    while cursor.remaining() > 0 {
        let opcode = cursor.read_u8()?;

        match opcode {
            // Literal encodings: DW_OP_lit0 through DW_OP_lit31
            op::LIT0..=0x4F => {
                stack.push((opcode - op::LIT0) as u64);
            }

            // Register: DW_OP_reg0 through DW_OP_reg31
            op::REG0..=0x6F => {
                let reg = (opcode - op::REG0) as u16;
                let val = regs
                    .get(reg)
                    .ok_or_else(|| UnwindError::InvalidDwarf(format!("reg{reg} not set")))?;
                stack.push(val);
            }

            // Base register + offset: DW_OP_breg0 through DW_OP_breg31
            op::BREG0..=0x8F => {
                let reg = (opcode - op::BREG0) as u16;
                let offset = cursor.read_sleb128()?;
                let val = regs
                    .get(reg)
                    .ok_or_else(|| UnwindError::InvalidDwarf(format!("breg{reg} not set")))?;
                stack.push(val.wrapping_add(offset as u64));
            }

            op::ADDR => {
                let addr = if is_64_bit {
                    cursor.read_u64()?
                } else {
                    cursor.read_u32()? as u64
                };
                stack.push(addr);
            }

            op::CONST1U => {
                let val = cursor.read_u8()? as u64;
                stack.push(val);
            }
            op::CONST1S => {
                let val = cursor.read_u8()? as i8 as i64 as u64;
                stack.push(val);
            }
            op::CONST2U => {
                let val = cursor.read_u16()? as u64;
                stack.push(val);
            }
            op::CONST2S => {
                let val = cursor.read_u16()? as i16 as i64 as u64;
                stack.push(val);
            }
            op::CONST4U => {
                let val = cursor.read_u32()? as u64;
                stack.push(val);
            }
            op::CONST4S => {
                let val = cursor.read_u32()? as i32 as i64 as u64;
                stack.push(val);
            }
            op::CONST8U => {
                let val = cursor.read_u64()?;
                stack.push(val);
            }
            op::CONST8S => {
                let val = cursor.read_u64()?;
                stack.push(val);
            }
            op::CONSTU => {
                let val = cursor.read_uleb128()?;
                stack.push(val);
            }
            op::CONSTS => {
                let val = cursor.read_sleb128()? as u64;
                stack.push(val);
            }

            // Stack operations
            op::DUP => {
                let val = *stack
                    .last()
                    .ok_or(UnwindError::InvalidDwarf("DUP on empty stack".into()))?;
                stack.push(val);
            }
            op::DROP => {
                stack
                    .pop()
                    .ok_or(UnwindError::InvalidDwarf("DROP on empty stack".into()))?;
            }
            op::OVER => {
                if stack.len() < 2 {
                    return Err(UnwindError::InvalidDwarf("OVER needs 2 values".into()));
                }
                let val = stack[stack.len() - 2];
                stack.push(val);
            }
            op::PICK => {
                let idx = cursor.read_u8()? as usize;
                if idx >= stack.len() {
                    return Err(UnwindError::InvalidDwarf("PICK index out of range".into()));
                }
                let val = stack[stack.len() - 1 - idx];
                stack.push(val);
            }
            op::SWAP => {
                if stack.len() < 2 {
                    return Err(UnwindError::InvalidDwarf("SWAP needs 2 values".into()));
                }
                let len = stack.len();
                stack.swap(len - 1, len - 2);
            }
            op::ROT => {
                if stack.len() < 3 {
                    return Err(UnwindError::InvalidDwarf("ROT needs 3 values".into()));
                }
                let len = stack.len();
                let top = stack[len - 1];
                stack[len - 1] = stack[len - 2];
                stack[len - 2] = stack[len - 3];
                stack[len - 3] = top;
            }

            // Memory operations
            op::DEREF => {
                let addr = stack
                    .pop()
                    .ok_or(UnwindError::InvalidDwarf("DEREF on empty stack".into()))?;
                let val = reader
                    .read_pointer(addr, is_64_bit)
                    .ok_or(UnwindError::MemoryReadFailed(addr))?;
                stack.push(val);
            }
            op::DEREF_SIZE => {
                let size = cursor.read_u8()?;
                let addr = stack.pop().ok_or(UnwindError::InvalidDwarf(
                    "DEREF_SIZE on empty stack".into(),
                ))?;
                let val = match size {
                    1 => reader.read_u8(addr).map(|v| v as u64),
                    2 => reader.read_u16(addr).map(|v| v as u64),
                    4 => reader.read_u32(addr).map(|v| v as u64),
                    8 => reader.read_u64(addr),
                    _ => None,
                }
                .ok_or(UnwindError::MemoryReadFailed(addr))?;
                stack.push(val);
            }

            // Arithmetic
            op::ABS => {
                let val = stack
                    .pop()
                    .ok_or(UnwindError::InvalidDwarf("ABS on empty stack".into()))?;
                stack.push((val as i64).unsigned_abs());
            }
            op::AND => {
                let (b, a) = pop_two(&mut stack, "AND")?;
                stack.push(a & b);
            }
            op::DIV => {
                let (b, a) = pop_two(&mut stack, "DIV")?;
                if b == 0 {
                    return Err(UnwindError::InvalidDwarf("DIV by zero".into()));
                }
                stack.push(((a as i64) / (b as i64)) as u64);
            }
            op::MINUS => {
                let (b, a) = pop_two(&mut stack, "MINUS")?;
                stack.push(a.wrapping_sub(b));
            }
            op::MOD => {
                let (b, a) = pop_two(&mut stack, "MOD")?;
                if b == 0 {
                    return Err(UnwindError::InvalidDwarf("MOD by zero".into()));
                }
                stack.push(a % b);
            }
            op::MUL => {
                let (b, a) = pop_two(&mut stack, "MUL")?;
                stack.push(a.wrapping_mul(b));
            }
            op::NEG => {
                let val = stack
                    .pop()
                    .ok_or(UnwindError::InvalidDwarf("NEG on empty stack".into()))?;
                stack.push((-(val as i64)) as u64);
            }
            op::NOT => {
                let val = stack
                    .pop()
                    .ok_or(UnwindError::InvalidDwarf("NOT on empty stack".into()))?;
                stack.push(!val);
            }
            op::OR => {
                let (b, a) = pop_two(&mut stack, "OR")?;
                stack.push(a | b);
            }
            op::PLUS => {
                let (b, a) = pop_two(&mut stack, "PLUS")?;
                stack.push(a.wrapping_add(b));
            }
            op::PLUS_UCONST => {
                let val = stack.pop().ok_or(UnwindError::InvalidDwarf(
                    "PLUS_UCONST on empty stack".into(),
                ))?;
                let addend = cursor.read_uleb128()?;
                stack.push(val.wrapping_add(addend));
            }
            op::SHL => {
                let (b, a) = pop_two(&mut stack, "SHL")?;
                stack.push(a.wrapping_shl(b as u32));
            }
            op::SHR => {
                let (b, a) = pop_two(&mut stack, "SHR")?;
                stack.push(a.wrapping_shr(b as u32));
            }
            op::SHRA => {
                let (b, a) = pop_two(&mut stack, "SHRA")?;
                stack.push(((a as i64).wrapping_shr(b as u32)) as u64);
            }
            op::XOR => {
                let (b, a) = pop_two(&mut stack, "XOR")?;
                stack.push(a ^ b);
            }

            // Register indirect
            op::REGX => {
                let reg = cursor.read_uleb128()? as u16;
                let val = regs
                    .get(reg)
                    .ok_or_else(|| UnwindError::InvalidDwarf(format!("regx({reg}) not set")))?;
                stack.push(val);
            }
            op::BREGX => {
                let reg = cursor.read_uleb128()? as u16;
                let offset = cursor.read_sleb128()?;
                let val = regs
                    .get(reg)
                    .ok_or_else(|| UnwindError::InvalidDwarf(format!("bregx({reg}) not set")))?;
                stack.push(val.wrapping_add(offset as u64));
            }
            op::FBREG => {
                // Frame base register — use FP as the frame base
                let offset = cursor.read_sleb128()?;
                let fp = regs
                    .fp()
                    .ok_or_else(|| UnwindError::InvalidDwarf("fbreg: no FP".into()))?;
                stack.push(fp.wrapping_add(offset as u64));
            }

            op::NOP => {}

            _ => {
                return Err(UnwindError::InvalidDwarf(format!(
                    "unsupported DW_OP 0x{opcode:02x}"
                )));
            }
        }
    }

    stack
        .last()
        .copied()
        .ok_or_else(|| UnwindError::InvalidDwarf("expression produced empty stack".into()))
}

fn pop_two(stack: &mut Vec<u64>, op_name: &str) -> Result<(u64, u64), UnwindError> {
    if stack.len() < 2 {
        return Err(UnwindError::InvalidDwarf(format!(
            "{op_name} needs 2 values"
        )));
    }
    let b = stack.pop().unwrap();
    let a = stack.pop().unwrap();
    Ok((b, a))
}

/// Cursor for reading bytes from a DWARF expression.
struct ExprCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ExprCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8, UnwindError> {
        if self.pos >= self.data.len() {
            return Err(UnwindError::InvalidDwarf(
                "unexpected end of expression".into(),
            ));
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16, UnwindError> {
        if self.pos + 2 > self.data.len() {
            return Err(UnwindError::InvalidDwarf(
                "unexpected end of expression".into(),
            ));
        }
        let val = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, UnwindError> {
        if self.pos + 4 > self.data.len() {
            return Err(UnwindError::InvalidDwarf(
                "unexpected end of expression".into(),
            ));
        }
        let val = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    fn read_u64(&mut self) -> Result<u64, UnwindError> {
        if self.pos + 8 > self.data.len() {
            return Err(UnwindError::InvalidDwarf(
                "unexpected end of expression".into(),
            ));
        }
        let val = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(val)
    }

    fn read_uleb128(&mut self) -> Result<u64, UnwindError> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(UnwindError::InvalidDwarf("ULEB128 overflow".into()));
            }
        }
    }

    fn read_sleb128(&mut self) -> Result<i64, UnwindError> {
        let mut result = 0i64;
        let mut shift = 0;
        let mut byte;
        loop {
            byte = self.read_u8()?;
            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(UnwindError::InvalidDwarf("SLEB128 overflow".into()));
            }
        }
        // Sign extend
        if shift < 64 && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        Ok(result)
    }
}

// Also export LEB128 readers for use in dwarf_cfi
pub fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u64, UnwindError> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return Err(UnwindError::InvalidDwarf("ULEB128 past end".into()));
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(UnwindError::InvalidDwarf("ULEB128 overflow".into()));
        }
    }
}

pub fn read_sleb128(data: &[u8], pos: &mut usize) -> Result<i64, UnwindError> {
    let mut result = 0i64;
    let mut shift = 0;
    let mut byte;
    loop {
        if *pos >= data.len() {
            return Err(UnwindError::InvalidDwarf("SLEB128 past end".into()));
        }
        byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(UnwindError::InvalidDwarf("SLEB128 overflow".into()));
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CpuType;
    use crate::unwind::SliceMemoryReader;

    fn make_reader() -> SliceMemoryReader {
        let mut data = vec![0u8; 256];
        // Put a known value at address 0x1080
        data[0x80..0x88].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        SliceMemoryReader {
            data,
            base_address: 0x1000,
        }
    }

    fn make_regs() -> RegisterContext {
        let mut regs = RegisterContext::new(CpuType::ARM64);
        regs.set(0, 100); // x0
        regs.set(29, 0x1080); // fp
        regs.set(31, 0x2000); // sp
        regs
    }

    #[test]
    fn lit_values() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_lit5
        assert_eq!(evaluate(&[0x35], &regs, &reader, true).unwrap(), 5);
        // DW_OP_lit0
        assert_eq!(evaluate(&[0x30], &regs, &reader, true).unwrap(), 0);
        // DW_OP_lit31
        assert_eq!(evaluate(&[0x4F], &regs, &reader, true).unwrap(), 31);
    }

    #[test]
    fn const_u_s() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_const1u 42
        assert_eq!(evaluate(&[0x08, 42], &regs, &reader, true).unwrap(), 42);
        // DW_OP_const1s -1 (0xFF)
        assert_eq!(
            evaluate(&[0x09, 0xFF], &regs, &reader, true).unwrap(),
            (-1i64) as u64
        );
    }

    #[test]
    fn breg_fp_offset() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_breg29(0) = FP value = 0x1080
        // breg29 = 0x70 + 29 = 0x8D, offset 0 as SLEB128
        assert_eq!(
            evaluate(&[0x8D, 0x00], &regs, &reader, true).unwrap(),
            0x1080
        );
    }

    #[test]
    fn deref() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_breg29(0), DW_OP_deref = read 8 bytes from FP (0x1080)
        assert_eq!(
            evaluate(&[0x8D, 0x00, op::DEREF], &regs, &reader, true).unwrap(),
            0xDEAD_BEEF_CAFE_BABE
        );
    }

    #[test]
    fn arithmetic_plus() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_lit5, DW_OP_lit3, DW_OP_plus = 8
        assert_eq!(
            evaluate(&[0x35, 0x33, op::PLUS], &regs, &reader, true).unwrap(),
            8
        );
    }

    #[test]
    fn plus_uconst() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_lit10, DW_OP_plus_uconst 20 = 30
        assert_eq!(
            evaluate(&[0x3A, op::PLUS_UCONST, 20], &regs, &reader, true).unwrap(),
            30
        );
    }

    #[test]
    fn stack_operations() {
        let reader = make_reader();
        let regs = make_regs();
        // DW_OP_lit1, DW_OP_lit2, DW_OP_swap, result = 1 (was top after swap)
        // Stack: [1, 2] → swap → [2, 1], top = 1
        assert_eq!(
            evaluate(&[0x31, 0x32, op::SWAP], &regs, &reader, true).unwrap(),
            1
        );
    }

    #[test]
    fn uleb128_encoding() {
        // Test multi-byte ULEB128
        let mut pos = 0;
        let data = [0x80, 0x01]; // 128
        assert_eq!(read_uleb128(&data, &mut pos).unwrap(), 128);
        assert_eq!(pos, 2);
    }

    #[test]
    fn sleb128_encoding() {
        // Test negative SLEB128
        let mut pos = 0;
        let data = [0x7F]; // -1
        assert_eq!(read_sleb128(&data, &mut pos).unwrap(), -1);
    }

    #[test]
    fn empty_expression_error() {
        let reader = make_reader();
        let regs = make_regs();
        assert!(evaluate(&[], &regs, &reader, true).is_err());
    }
}
