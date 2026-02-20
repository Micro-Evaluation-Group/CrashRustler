//! Binary image enumeration from the target process via dyld_all_image_infos.
//!
//! Reads the dyld shared image list from the remote process to discover
//! all loaded Mach-O binaries, their load addresses, extents, and UUIDs.

use crashrustler::unwind::{BinaryImageInfo, MemoryReader};

use crate::ffi;

/// Reference to a Mach-O symbol table in remote process memory.
pub struct SymtabRef {
    /// In-memory address of the nlist array.
    pub symtab_addr: u64,
    /// Number of nlist entries.
    pub nsyms: u32,
    /// In-memory address of the string table.
    pub strtab_addr: u64,
    /// Size of the string table in bytes.
    pub strsize: u32,
    /// Preferred __TEXT vmaddr from the binary (needed to compute ASLR slide).
    pub text_vmaddr: u64,
}

/// A loaded binary image with metadata for both unwinding and crash reporting.
pub struct LoadedImage {
    /// Image info for the unwinder (contains load address, extent, section refs).
    pub info: BinaryImageInfo,
    /// Full filesystem path of the image.
    pub path: String,
    /// Symbol table reference for symbol resolution, if available.
    pub symtab: Option<SymtabRef>,
    /// In-memory address of the `__DATA,__crash_info` section, if present.
    /// Contains a `crashreporter_annotations_t` struct with crash reporter messages.
    pub crash_info_addr: Option<u64>,
}

/// Enumerates all loaded binary images in the target process.
pub fn enumerate_binary_images(
    task: ffi::MachPortT,
    reader: &dyn MemoryReader,
    is_64_bit: bool,
) -> Vec<LoadedImage> {
    let Some(all_image_info_addr) = get_dyld_info_addr(task) else {
        return Vec::new();
    };

    // dyld_all_image_infos layout:
    //   version:        u32 (offset 0)
    //   infoArrayCount: u32 (offset 4)
    //   infoArray:      pointer (offset 8)
    let Some(version) = reader.read_u32(all_image_info_addr) else {
        return Vec::new();
    };
    if version < 1 {
        return Vec::new();
    }

    let Some(info_array_count) = reader.read_u32(all_image_info_addr + 4) else {
        return Vec::new();
    };

    let info_array_addr = if is_64_bit {
        match reader.read_u64(all_image_info_addr + 8) {
            Some(a) if a != 0 => a,
            _ => return Vec::new(),
        }
    } else {
        match reader.read_u32(all_image_info_addr + 8) {
            Some(a) if a != 0 => a as u64,
            _ => return Vec::new(),
        }
    };

    let mut images = Vec::new();

    // dyld_image_info entry size: 64-bit = 3*8 = 24, 32-bit = 3*4 = 12
    let entry_size: u64 = if is_64_bit { 24 } else { 12 };
    let ptr_size: u64 = if is_64_bit { 8 } else { 4 };

    // Cap iteration to prevent runaway reads from corrupted data
    let count = info_array_count.min(4096) as u64;

    for i in 0..count {
        let entry_addr = info_array_addr + i * entry_size;

        // dyld_image_info layout:
        //   imageLoadAddress: pointer (offset 0)
        //   imageFilePath:    pointer (offset ptr_size)
        //   imageFileModDate: pointer (offset 2*ptr_size)
        let Some(load_addr) = reader.read_pointer(entry_addr, is_64_bit) else {
            continue;
        };
        if load_addr == 0 {
            continue;
        }

        let Some(path_ptr) = reader.read_pointer(entry_addr + ptr_size, is_64_bit) else {
            continue;
        };

        let path = read_c_string(reader, path_ptr).unwrap_or_default();
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();

        // Parse Mach-O header for segment extent, LC_UUID, symbol table, and __crash_info
        let (end_addr, uuid, symtab, crash_info) = parse_image_extent(reader, load_addr, is_64_bit);

        images.push(LoadedImage {
            info: BinaryImageInfo {
                name,
                load_address: load_addr,
                end_address: end_addr,
                is_64_bit,
                uuid,
                unwind_info: None,
                eh_frame: None,
                text_section: None,
                sections_resolved: false,
            },
            path,
            symtab,
            crash_info_addr: crash_info,
        });
    }

    images
}

/// Gets the dyld_all_image_infos address via `task_info(TASK_DYLD_INFO)`.
fn get_dyld_info_addr(task: ffi::MachPortT) -> Option<u64> {
    unsafe {
        // task_dyld_info layout:
        //   all_image_info_addr: u64 (offset 0)
        //   all_image_info_size: u64 (offset 8)
        //   all_image_info_format: i32 (offset 16)
        // Total: 20 bytes = 5 natural_t, padded to 6
        let mut info = [0i32; 6];
        let mut count: ffi::MachMsgTypeNumberT = 6;
        let kr = ffi::task_info(task, ffi::TASK_DYLD_INFO, info.as_mut_ptr(), &mut count);
        if kr != ffi::KERN_SUCCESS || count < 5 {
            return None;
        }
        // all_image_info_addr is the first u64 (two i32s, little-endian)
        let addr = (info[0] as u32 as u64) | ((info[1] as u32 as u64) << 32);
        if addr == 0 { None } else { Some(addr) }
    }
}

/// Reads a null-terminated C string from remote process memory.
/// Reads up to 4 KB, suitable for symbol names and file paths.
fn read_c_string(reader: &dyn MemoryReader, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut result = Vec::new();
    let chunk_size = 256usize;
    for chunk_idx in 0..16u64 {
        let bytes = reader.read_memory(addr + chunk_idx * chunk_size as u64, chunk_size)?;
        if let Some(null_pos) = bytes.iter().position(|&b| b == 0) {
            result.extend_from_slice(&bytes[..null_pos]);
            return String::from_utf8(result).ok();
        }
        result.extend_from_slice(&bytes);
    }
    String::from_utf8(result).ok()
}

// Mach-O constants
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_MAGIC: u32 = 0xFEED_FACE;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x01;
const LC_UUID: u32 = 0x1B;
const LC_SYMTAB: u32 = 0x02;

/// Parses a Mach-O header at `load_address` to determine the image extent, UUID,
/// and symbol table reference.
///
/// Walks all load commands to find:
/// - LC_SEGMENT(_64): maximum virtual address range and __LINKEDIT/__TEXT vmaddr/fileoff
/// - LC_UUID: binary UUID
/// - LC_SYMTAB: symbol table and string table offsets
///
/// Computes the ASLR slide from __TEXT, then derives in-memory addresses for the
/// symbol table and string table via __LINKEDIT.
fn parse_image_extent(
    reader: &dyn MemoryReader,
    load_address: u64,
    is_64_bit: bool,
) -> (u64, Option<[u8; 16]>, Option<SymtabRef>, Option<u64>) {
    let default_end = load_address + 0x1000;

    let Some(magic) = reader.read_u32(load_address) else {
        return (default_end, None, None, None);
    };

    let (header_size, expected_magic, lc_segment) = if is_64_bit {
        (32u64, MH_MAGIC_64, LC_SEGMENT_64)
    } else {
        (28u64, MH_MAGIC, LC_SEGMENT)
    };

    if magic != expected_magic {
        return (default_end, None, None, None);
    }

    let Some(ncmds) = reader.read_u32(load_address + 16) else {
        return (default_end, None, None, None);
    };

    let mut text_vmaddr: u64 = 0;
    let mut text_vmsize: u64 = 0;
    let mut found_text = false;
    let mut uuid: Option<[u8; 16]> = None;

    // LC_SYMTAB fields
    let mut symoff: u32 = 0;
    let mut nsyms: u32 = 0;
    let mut stroff: u32 = 0;
    let mut strsize: u32 = 0;
    let mut found_symtab = false;

    // __LINKEDIT segment fields
    let mut linkedit_vmaddr: u64 = 0;
    let mut linkedit_fileoff: u64 = 0;
    let mut found_linkedit = false;

    // __DATA,__crash_info section address
    let mut crash_info_addr: Option<u64> = None;

    let mut offset = header_size;
    for _ in 0..ncmds {
        let Some(cmd) = reader.read_u32(load_address + offset) else {
            break;
        };
        let Some(cmd_size) = reader.read_u32(load_address + offset + 4) else {
            break;
        };
        if cmd_size < 8 {
            break; // Malformed load command
        }
        let cmd_size = cmd_size as u64;

        if cmd == lc_segment {
            if let Some(seg_name_bytes) = reader.read_memory(load_address + offset + 8, 16) {
                let name_end = seg_name_bytes.iter().position(|&b| b == 0).unwrap_or(16);

                let (vmaddr, vmsize, fileoff) = if is_64_bit {
                    // segment_command_64: vmaddr at +24, vmsize at +32, fileoff at +40
                    let va = reader.read_u64(load_address + offset + 24).unwrap_or(0);
                    let vs = reader.read_u64(load_address + offset + 32).unwrap_or(0);
                    let fo = reader.read_u64(load_address + offset + 40).unwrap_or(0);
                    (va, vs, fo)
                } else {
                    // segment_command: vmaddr at +24, vmsize at +28, fileoff at +32
                    let va = reader.read_u32(load_address + offset + 24).unwrap_or(0) as u64;
                    let vs = reader.read_u32(load_address + offset + 28).unwrap_or(0) as u64;
                    let fo = reader.read_u32(load_address + offset + 32).unwrap_or(0) as u64;
                    (va, vs, fo)
                };

                if &seg_name_bytes[..name_end] == b"__TEXT" {
                    text_vmaddr = vmaddr;
                    text_vmsize = vmsize;
                    found_text = true;
                } else if &seg_name_bytes[..name_end] == b"__LINKEDIT" {
                    linkedit_vmaddr = vmaddr;
                    linkedit_fileoff = fileoff;
                    found_linkedit = true;
                } else if &seg_name_bytes[..name_end] == b"__DATA" {
                    // Scan sections within __DATA for __crash_info
                    let (seg_hdr_size, sect_size) = if is_64_bit {
                        (72u64, 80u64) // segment_command_64 + section_64
                    } else {
                        (56u64, 68u64) // segment_command + section
                    };
                    let nsects = reader
                        .read_u32(load_address + offset + if is_64_bit { 64 } else { 48 })
                        .unwrap_or(0);
                    for s in 0..nsects as u64 {
                        let sect_off = load_address + offset + seg_hdr_size + s * sect_size;
                        if let Some(sect_name) = reader.read_memory(sect_off, 16) {
                            let sn_end = sect_name.iter().position(|&b| b == 0).unwrap_or(16);
                            if &sect_name[..sn_end] == b"__crash_info" {
                                // section(_64): addr at offset +32
                                let sect_addr = if is_64_bit {
                                    reader.read_u64(sect_off + 32).unwrap_or(0)
                                } else {
                                    reader.read_u32(sect_off + 32).unwrap_or(0) as u64
                                };
                                if sect_addr != 0 {
                                    // Apply ASLR slide: in-memory = slide + file vmaddr
                                    // slide = load_address - text_vmaddr (computed later)
                                    // Store the raw vmaddr; we'll adjust after finding __TEXT
                                    crash_info_addr = Some(sect_addr);
                                }
                            }
                        }
                    }
                }
            }
        } else if cmd == LC_UUID
            && cmd_size >= 24
            && let Some(uuid_bytes) = reader.read_memory(load_address + offset + 8, 16)
        {
            let mut u = [0u8; 16];
            u.copy_from_slice(&uuid_bytes);
            uuid = Some(u);
        } else if cmd == LC_SYMTAB && cmd_size >= 24 {
            // symtab_command layout: cmd(4) cmdsize(4) symoff(4) nsyms(4) stroff(4) strsize(4)
            symoff = reader.read_u32(load_address + offset + 8).unwrap_or(0);
            nsyms = reader.read_u32(load_address + offset + 12).unwrap_or(0);
            stroff = reader.read_u32(load_address + offset + 16).unwrap_or(0);
            strsize = reader.read_u32(load_address + offset + 20).unwrap_or(0);
            found_symtab = nsyms > 0;
        }

        offset += cmd_size;
    }

    if !found_text || text_vmsize == 0 {
        return (default_end, uuid, None, None);
    }

    // ASLR slide = load_address - text_vmaddr
    let slide = load_address.wrapping_sub(text_vmaddr);

    // Apply ASLR slide to __crash_info section address
    let crash_info = crash_info_addr.map(|addr| addr.wrapping_add(slide));

    // End address = load_address + __TEXT vmsize.
    // This gives the correct extent for both standalone binaries and dyld shared
    // cache images (where __DATA segments are in separate memory regions and using
    // all segments would produce overlapping ranges).
    let end_address = load_address.wrapping_add(text_vmsize);

    // Build SymtabRef if we have both LC_SYMTAB and __LINKEDIT
    let symtab = if found_symtab && found_linkedit {
        // In-memory base of __LINKEDIT data
        let linkedit_base = load_address
            .wrapping_add(linkedit_vmaddr)
            .wrapping_sub(text_vmaddr)
            .wrapping_sub(linkedit_fileoff);
        Some(SymtabRef {
            symtab_addr: linkedit_base.wrapping_add(symoff as u64),
            nsyms,
            strtab_addr: linkedit_base.wrapping_add(stroff as u64),
            strsize,
            text_vmaddr,
        })
    } else {
        None
    };

    (end_address, uuid, symtab, crash_info)
}

/// Resolves a program counter address to a symbol name and offset using the
/// image's symbol table.
///
/// Reads nlist_64 entries from remote memory, filters for defined section symbols
/// (N_SECT, not stabs), slides them by the ASLR offset, then binary searches for
/// the closest function start <= `pc`.
/// Returns `(symbol_name, offset_from_function_start)` or `None` if no match.
pub fn resolve_symbol(
    reader: &dyn MemoryReader,
    symtab: &SymtabRef,
    pc: u64,
    load_address: u64,
) -> Option<(String, u64)> {
    // nlist_64 is 16 bytes: n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8)
    const NLIST_SIZE: usize = 16;

    // Cap to avoid reading excessively large symbol tables
    let nsyms = symtab.nsyms.min(1_000_000) as usize;

    // Read the entire nlist array in one bulk read
    let total_size = nsyms * NLIST_SIZE;
    let nlist_data = reader.read_memory(symtab.symtab_addr, total_size)?;

    // ASLR slide: difference between runtime load address and preferred __TEXT vmaddr
    let slide = load_address.wrapping_sub(symtab.text_vmaddr);

    // Collect defined section symbols as (slid_address, string_table_index)
    let mut symbols: Vec<(u64, u32)> = Vec::new();

    for i in 0..nsyms {
        let base = i * NLIST_SIZE;
        if base + NLIST_SIZE > nlist_data.len() {
            break;
        }

        let n_strx = u32::from_le_bytes([
            nlist_data[base],
            nlist_data[base + 1],
            nlist_data[base + 2],
            nlist_data[base + 3],
        ]);
        let n_type = nlist_data[base + 4];
        let n_value = u64::from_le_bytes([
            nlist_data[base + 8],
            nlist_data[base + 9],
            nlist_data[base + 10],
            nlist_data[base + 11],
            nlist_data[base + 12],
            nlist_data[base + 13],
            nlist_data[base + 14],
            nlist_data[base + 15],
        ]);

        // Skip stab entries (debugging symbols) and non-section symbols
        // N_STAB mask: 0xe0, N_TYPE mask: 0x0e, N_SECT = 0x0e
        if (n_type & 0xe0) != 0 || (n_type & 0x0e) != 0x0e {
            continue;
        }

        if n_value != 0 {
            // Slide n_value to get the runtime virtual address
            symbols.push((n_value.wrapping_add(slide), n_strx));
        }
    }

    if symbols.is_empty() {
        return None;
    }

    // Sort by address for binary search
    symbols.sort_unstable_by_key(|&(addr, _)| addr);

    // Find the largest symbol address <= pc
    let idx = match symbols.binary_search_by_key(&pc, |&(addr, _)| addr) {
        Ok(i) => i,
        Err(0) => return None, // pc is before all symbols
        Err(i) => i - 1,
    };

    let (sym_addr, n_strx) = symbols[idx];
    let offset_from_sym = pc.wrapping_sub(sym_addr);

    // Read the symbol name from the string table
    if n_strx as u64 >= symtab.strsize as u64 {
        return None;
    }

    let name = read_c_string(reader, symtab.strtab_addr + n_strx as u64)?;

    // Strip leading underscore (Mach-O C symbol convention)
    let name = if let Some(stripped) = name.strip_prefix('_') {
        stripped.to_string()
    } else {
        name
    };

    // Demangle C++/Rust symbols
    let name = demangle_symbol(&name);

    Some((name, offset_from_sym))
}

/// Attempts to demangle a C++ or Rust symbol name.
///
/// Tries Rust demangling first (handles both legacy `_ZN...` and v0 `_R...` formats),
/// then falls back to C++ Itanium ABI demangling (`_Z...`).
/// Returns the original name unchanged if neither demangler recognizes it.
fn demangle_symbol(name: &str) -> String {
    // Try Rust demangling (handles legacy _ZN and v0 _R formats)
    let rust_demangled = rustc_demangle::try_demangle(name);
    if let Ok(demangled) = rust_demangled {
        return format!("{demangled:#}");
    }

    // Try C++ Itanium ABI demangling
    if let Ok(sym) = cpp_demangle::Symbol::new(name)
        && let Ok(demangled) = sym.demangle()
    {
        return demangled;
    }

    name.to_string()
}

/// Looks up a symbol by its raw nlist name (including Mach-O leading underscore)
/// and returns its runtime (ASLR-slid) address. Returns None if not found.
pub(crate) fn find_symbol_address(
    reader: &dyn MemoryReader,
    symtab: &SymtabRef,
    target_name: &str,
    load_address: u64,
) -> Option<u64> {
    const NLIST_SIZE: usize = 16;
    let nsyms = symtab.nsyms.min(1_000_000) as usize;
    let total_size = nsyms * NLIST_SIZE;
    let nlist_data = reader.read_memory(symtab.symtab_addr, total_size)?;
    let slide = load_address.wrapping_sub(symtab.text_vmaddr);

    for i in 0..nsyms {
        let base = i * NLIST_SIZE;
        if base + NLIST_SIZE > nlist_data.len() {
            break;
        }

        let n_strx = u32::from_le_bytes([
            nlist_data[base],
            nlist_data[base + 1],
            nlist_data[base + 2],
            nlist_data[base + 3],
        ]);
        let n_value = u64::from_le_bytes([
            nlist_data[base + 8],
            nlist_data[base + 9],
            nlist_data[base + 10],
            nlist_data[base + 11],
            nlist_data[base + 12],
            nlist_data[base + 13],
            nlist_data[base + 14],
            nlist_data[base + 15],
        ]);

        if n_value == 0 || (n_strx as u64) >= symtab.strsize as u64 {
            continue;
        }

        if let Some(name) = read_c_string(reader, symtab.strtab_addr + n_strx as u64)
            && name == target_name
        {
            return Some(n_value.wrapping_add(slide));
        }
    }

    None
}

/// Reads a potentially large null-terminated C string from remote process memory.
/// Reads up to 64 KB in 4 KB chunks, suitable for crash reporter info buffers.
pub(crate) fn read_large_c_string(reader: &dyn MemoryReader, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut result = Vec::new();
    let chunk_size = 4096usize;
    for chunk_idx in 0..16u64 {
        let bytes = reader.read_memory(addr + chunk_idx * chunk_size as u64, chunk_size)?;
        if let Some(null_pos) = bytes.iter().position(|&b| b == 0) {
            result.extend_from_slice(&bytes[..null_pos]);
            return if result.is_empty() {
                None
            } else {
                String::from_utf8(result).ok()
            };
        }
        result.extend_from_slice(&bytes);
    }
    if result.is_empty() {
        None
    } else {
        String::from_utf8(result).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // demangle_symbol tests
    // ========================================================================

    #[test]
    fn demangle_rust_legacy() {
        // Legacy Rust mangling (_ZN...)
        let result = demangle_symbol("_ZN4main3foo17h1234567890abcdefE");
        assert!(result.contains("main"));
        assert!(result.contains("foo"));
        assert!(!result.contains("_ZN")); // should be demangled
    }

    #[test]
    fn demangle_cpp_itanium() {
        // C++ Itanium ABI mangling
        let result = demangle_symbol("_ZN3foo3barEi");
        assert_eq!(result, "foo::bar(int)");
    }

    #[test]
    fn demangle_plain_c_symbol() {
        // Plain C symbol — no demangling, returned as-is
        assert_eq!(demangle_symbol("_main"), "_main");
        assert_eq!(demangle_symbol("printf"), "printf");
    }

    #[test]
    fn demangle_empty_string() {
        assert_eq!(demangle_symbol(""), "");
    }

    #[test]
    fn demangle_invalid_mangling() {
        // Looks like a mangled name but isn't valid
        assert_eq!(demangle_symbol("_ZNgarbage"), "_ZNgarbage");
    }

    // ========================================================================
    // read_c_string tests (via mock MemoryReader)
    // ========================================================================

    struct MockReader {
        data: Vec<u8>,
        base: u64,
    }

    impl MockReader {
        fn new(base: u64, data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                base,
            }
        }
    }

    impl crashrustler::unwind::MemoryReader for MockReader {
        fn read_memory(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
            if addr < self.base {
                return None;
            }
            let offset = (addr - self.base) as usize;
            if offset >= self.data.len() {
                return None;
            }
            let end = (offset + size).min(self.data.len());
            Some(self.data[offset..end].to_vec())
        }
    }

    #[test]
    fn read_c_string_basic() {
        let reader = MockReader::new(0x1000, b"hello\0world\0");
        assert_eq!(read_c_string(&reader, 0x1000), Some("hello".to_string()));
    }

    #[test]
    fn read_c_string_empty() {
        let reader = MockReader::new(0x1000, b"\0rest");
        assert_eq!(read_c_string(&reader, 0x1000), Some("".to_string()));
    }

    #[test]
    fn read_c_string_null_address() {
        let reader = MockReader::new(0x1000, b"hello\0");
        assert_eq!(read_c_string(&reader, 0), None);
    }

    #[test]
    fn read_c_string_at_offset() {
        let reader = MockReader::new(0x1000, b"hello\0world\0");
        assert_eq!(read_c_string(&reader, 0x1006), Some("world".to_string()));
    }

    #[test]
    fn read_c_string_invalid_address() {
        let reader = MockReader::new(0x1000, b"hello\0");
        assert_eq!(read_c_string(&reader, 0x2000), None);
    }

    // ========================================================================
    // read_large_c_string tests
    // ========================================================================

    #[test]
    fn read_large_c_string_basic() {
        let reader = MockReader::new(0x1000, b"large string content\0");
        assert_eq!(
            read_large_c_string(&reader, 0x1000),
            Some("large string content".to_string())
        );
    }

    #[test]
    fn read_large_c_string_empty() {
        let reader = MockReader::new(0x1000, b"\0");
        assert_eq!(read_large_c_string(&reader, 0x1000), None);
    }
}
