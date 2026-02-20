//! Mach-O section finder operating on byte slices from MemoryReader.
//!
//! Parses the Mach-O header and load commands to locate key sections:
//! `__TEXT,__unwind_info`, `__TEXT,__eh_frame`, and `__TEXT,__text`.

use super::{MemoryReader, SectionRef};

/// Results of Mach-O section lookup.
pub struct MachOSections {
    pub unwind_info: Option<SectionRef>,
    pub eh_frame: Option<SectionRef>,
    pub text: Option<SectionRef>,
}

// Mach-O constants
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_MAGIC: u32 = 0xFEED_FACE;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x01;
const LC_UUID: u32 = 0x1B;

/// Finds key sections in a Mach-O binary at the given load address.
pub fn find_sections(
    reader: &dyn MemoryReader,
    load_address: u64,
    is_64_bit: bool,
) -> MachOSections {
    let mut result = MachOSections {
        unwind_info: None,
        eh_frame: None,
        text: None,
    };

    if is_64_bit {
        find_sections_64(reader, load_address, &mut result);
    } else {
        find_sections_32(reader, load_address, &mut result);
    }

    result
}

/// Extracts the LC_UUID from a Mach-O binary.
pub fn find_uuid(
    reader: &dyn MemoryReader,
    load_address: u64,
    is_64_bit: bool,
) -> Option<[u8; 16]> {
    let magic = reader.read_u32(load_address)?;

    let (header_size, expected_magic, lc_segment) = if is_64_bit {
        (32u64, MH_MAGIC_64, LC_SEGMENT_64)
    } else {
        (28u64, MH_MAGIC, LC_SEGMENT)
    };

    if magic != expected_magic {
        return None;
    }

    let ncmds = reader.read_u32(load_address + 16)? as u64;
    let _ = lc_segment; // used in find_sections, not needed here

    let mut offset = header_size;
    for _ in 0..ncmds {
        let cmd = reader.read_u32(load_address + offset)?;
        let cmd_size = reader.read_u32(load_address + offset + 4)? as u64;

        if cmd == LC_UUID && cmd_size >= 24 {
            let uuid_bytes = reader.read_memory(load_address + offset + 8, 16)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&uuid_bytes);
            return Some(uuid);
        }

        offset += cmd_size;
    }

    None
}

fn find_sections_64(reader: &dyn MemoryReader, load_address: u64, result: &mut MachOSections) {
    let Some(magic) = reader.read_u32(load_address) else {
        return;
    };
    if magic != MH_MAGIC_64 {
        return;
    }

    let Some(ncmds) = reader.read_u32(load_address + 16) else {
        return;
    };

    // 64-bit header is 32 bytes
    let mut offset = 32u64;

    for _ in 0..ncmds {
        let Some(cmd) = reader.read_u32(load_address + offset) else {
            return;
        };
        let Some(cmd_size) = reader.read_u32(load_address + offset + 4) else {
            return;
        };

        if cmd == LC_SEGMENT_64 {
            // Read segment name (16 bytes at offset+8)
            let Some(seg_name_bytes) = reader.read_memory(load_address + offset + 8, 16) else {
                offset += cmd_size as u64;
                continue;
            };
            let seg_name = bytes_to_name(&seg_name_bytes);

            if seg_name == "__TEXT" {
                // Parse sections within this segment
                // nsects is at offset+48 (after segname(16)+vmaddr(8)+vmsize(8)+fileoff(8)+filesize(8))
                let Some(nsects) = reader.read_u32(load_address + offset + 64) else {
                    offset += cmd_size as u64;
                    continue;
                };

                // Section headers start at offset+72 (segment_command_64 size)
                let mut sect_offset = offset + 72;
                for _ in 0..nsects {
                    parse_section_64(reader, load_address, sect_offset, result);
                    sect_offset += 80; // sizeof(section_64)
                }
            }
        }

        offset += cmd_size as u64;
    }
}

fn find_sections_32(reader: &dyn MemoryReader, load_address: u64, result: &mut MachOSections) {
    let Some(magic) = reader.read_u32(load_address) else {
        return;
    };
    if magic != MH_MAGIC {
        return;
    }

    let Some(ncmds) = reader.read_u32(load_address + 16) else {
        return;
    };

    // 32-bit header is 28 bytes
    let mut offset = 28u64;

    for _ in 0..ncmds {
        let Some(cmd) = reader.read_u32(load_address + offset) else {
            return;
        };
        let Some(cmd_size) = reader.read_u32(load_address + offset + 4) else {
            return;
        };

        if cmd == LC_SEGMENT {
            let Some(seg_name_bytes) = reader.read_memory(load_address + offset + 8, 16) else {
                offset += cmd_size as u64;
                continue;
            };
            let seg_name = bytes_to_name(&seg_name_bytes);

            if seg_name == "__TEXT" {
                let Some(nsects) = reader.read_u32(load_address + offset + 48) else {
                    offset += cmd_size as u64;
                    continue;
                };

                let mut sect_offset = offset + 56; // sizeof(segment_command)
                for _ in 0..nsects {
                    parse_section_32(reader, load_address, sect_offset, result);
                    sect_offset += 68; // sizeof(section)
                }
            }
        }

        offset += cmd_size as u64;
    }
}

fn parse_section_64(
    reader: &dyn MemoryReader,
    load_address: u64,
    sect_offset: u64,
    result: &mut MachOSections,
) {
    // section_64: sectname(16) + segname(16) + addr(8) + size(8)
    let Some(sect_name_bytes) = reader.read_memory(load_address + sect_offset, 16) else {
        return;
    };
    let sect_name = bytes_to_name(&sect_name_bytes);

    let Some(addr) = reader.read_u64(load_address + sect_offset + 32) else {
        return;
    };
    let Some(size) = reader.read_u64(load_address + sect_offset + 40) else {
        return;
    };

    match sect_name.as_str() {
        "__unwind_info" => {
            result.unwind_info = Some(SectionRef {
                vm_addr: addr,
                size,
            });
        }
        "__eh_frame" => {
            result.eh_frame = Some(SectionRef {
                vm_addr: addr,
                size,
            });
        }
        "__text" => {
            result.text = Some(SectionRef {
                vm_addr: addr,
                size,
            });
        }
        _ => {}
    }
}

fn parse_section_32(
    reader: &dyn MemoryReader,
    load_address: u64,
    sect_offset: u64,
    result: &mut MachOSections,
) {
    let Some(sect_name_bytes) = reader.read_memory(load_address + sect_offset, 16) else {
        return;
    };
    let sect_name = bytes_to_name(&sect_name_bytes);

    // section: sectname(16) + segname(16) + addr(4) + size(4)
    let Some(addr) = reader.read_u32(load_address + sect_offset + 32) else {
        return;
    };
    let Some(size) = reader.read_u32(load_address + sect_offset + 36) else {
        return;
    };

    match sect_name.as_str() {
        "__unwind_info" => {
            result.unwind_info = Some(SectionRef {
                vm_addr: addr as u64,
                size: size as u64,
            });
        }
        "__eh_frame" => {
            result.eh_frame = Some(SectionRef {
                vm_addr: addr as u64,
                size: size as u64,
            });
        }
        "__text" => {
            result.text = Some(SectionRef {
                vm_addr: addr as u64,
                size: size as u64,
            });
        }
        _ => {}
    }
}

/// Converts a null-padded byte array to a string.
fn bytes_to_name(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

#[cfg(test)]
mod tests {
    use super::super::SliceMemoryReader;
    use super::*;

    /// Builds a minimal 64-bit Mach-O with one LC_SEGMENT_64 (__TEXT)
    /// containing __unwind_info, __eh_frame, and __text sections.
    fn build_test_macho_64() -> Vec<u8> {
        let mut data = Vec::new();

        // Mach-O header (32 bytes)
        data.extend_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic
        data.extend_from_slice(&0u32.to_le_bytes()); // cputype
        data.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        data.extend_from_slice(&0u32.to_le_bytes()); // filetype
        data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
        let sizeofcmds = 72 + 80 * 3; // segment_command_64 + 3 sections
        data.extend_from_slice(&(sizeofcmds as u32).to_le_bytes()); // sizeofcmds
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved
        assert_eq!(data.len(), 32);

        // LC_SEGMENT_64 (72 bytes base + 80 * nsects)
        let cmd_size = 72 + 80 * 3;
        data.extend_from_slice(&LC_SEGMENT_64.to_le_bytes()); // cmd
        data.extend_from_slice(&(cmd_size as u32).to_le_bytes()); // cmdsize
        // segname: "__TEXT\0..."
        let mut segname = [0u8; 16];
        segname[..6].copy_from_slice(b"__TEXT");
        data.extend_from_slice(&segname);
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // vmaddr
        data.extend_from_slice(&0x3000u64.to_le_bytes()); // vmsize
        data.extend_from_slice(&0u64.to_le_bytes()); // fileoff
        data.extend_from_slice(&0u64.to_le_bytes()); // filesize
        data.extend_from_slice(&0u32.to_le_bytes()); // maxprot
        data.extend_from_slice(&0u32.to_le_bytes()); // initprot
        data.extend_from_slice(&3u32.to_le_bytes()); // nsects = 3
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        assert_eq!(data.len(), 104); // 32 + 72

        // Section 1: __text
        write_section_64(&mut data, "__text", "__TEXT", 0x1100, 0x500);
        // Section 2: __unwind_info
        write_section_64(&mut data, "__unwind_info", "__TEXT", 0x2000, 0x200);
        // Section 3: __eh_frame
        write_section_64(&mut data, "__eh_frame", "__TEXT", 0x2200, 0x400);

        data
    }

    fn write_section_64(data: &mut Vec<u8>, sectname: &str, segname: &str, addr: u64, size: u64) {
        // section_64 is 80 bytes
        let mut sn = [0u8; 16];
        let bytes = sectname.as_bytes();
        sn[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        data.extend_from_slice(&sn);

        let mut sg = [0u8; 16];
        let bytes = segname.as_bytes();
        sg[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        data.extend_from_slice(&sg);

        data.extend_from_slice(&addr.to_le_bytes()); // addr
        data.extend_from_slice(&size.to_le_bytes()); // size
        data.extend_from_slice(&0u32.to_le_bytes()); // offset
        data.extend_from_slice(&0u32.to_le_bytes()); // align
        data.extend_from_slice(&0u32.to_le_bytes()); // reloff
        data.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved3 (padding to 80 bytes)
    }

    #[test]
    fn find_sections_64bit() {
        let macho_data = build_test_macho_64();
        let reader = SliceMemoryReader {
            data: macho_data,
            base_address: 0,
        };

        let sections = find_sections(&reader, 0, true);

        let text = sections.text.unwrap();
        assert_eq!(text.vm_addr, 0x1100);
        assert_eq!(text.size, 0x500);

        let unwind = sections.unwind_info.unwrap();
        assert_eq!(unwind.vm_addr, 0x2000);
        assert_eq!(unwind.size, 0x200);

        let eh = sections.eh_frame.unwrap();
        assert_eq!(eh.vm_addr, 0x2200);
        assert_eq!(eh.size, 0x400);
    }

    #[test]
    fn find_sections_bad_magic() {
        let reader = SliceMemoryReader {
            data: vec![0u8; 64],
            base_address: 0,
        };
        let sections = find_sections(&reader, 0, true);
        assert!(sections.text.is_none());
        assert!(sections.unwind_info.is_none());
        assert!(sections.eh_frame.is_none());
    }

    #[test]
    fn bytes_to_name_with_null() {
        let b = b"__TEXT\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(bytes_to_name(b), "__TEXT");
    }

    #[test]
    fn bytes_to_name_full() {
        let b = b"__longerthan16ch";
        assert_eq!(bytes_to_name(b), "__longerthan16ch");
    }
}
