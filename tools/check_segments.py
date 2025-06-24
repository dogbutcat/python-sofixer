#!/usr/bin/env python3
"""
Check ELF Segments (Program Headers)
===================================

Simple tool to compare ELF segments between C++ and Python versions.
"""

import struct
import sys

def read_program_headers(filename):
    """Read and display ELF program headers (segments)"""
    try:
        with open(filename, 'rb') as f:
            # Read ELF header
            header = f.read(64)
            
            # Check if it's 64-bit ELF
            if header[4] != 2:
                print(f"❌ {filename}: Not a 64-bit ELF file")
                return None
            
            # Parse 64-bit ELF header fields
            e_phoff = struct.unpack('<Q', header[32:40])[0]      # Program header offset
            e_phentsize = struct.unpack('<H', header[54:56])[0]  # Program header entry size  
            e_phnum = struct.unpack('<H', header[56:58])[0]      # Number of program headers
            
            print(f"\n📁 {filename}")
            print(f"Program headers: {e_phnum} entries at offset 0x{e_phoff:x}")
            print("-" * 80)
            print(f"{'Type':<12} {'Offset':<12} {'VAddr':<12} {'PAddr':<12} {'FileSz':<12} {'MemSz':<12} {'Flags'}")
            print("-" * 80)
            
            # Read each program header
            segments = []
            f.seek(e_phoff)
            
            type_names = {1: "LOAD", 2: "DYNAMIC", 6: "PHDR", 0x6474e550: "GNU_EH_FRAME"}
            
            for i in range(e_phnum):
                # Read 64-bit program header (56 bytes)
                phdr_data = f.read(56)
                if len(phdr_data) < 56:
                    break
                    
                # Unpack program header fields
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                    struct.unpack('<LLQQQQQQ', phdr_data)
                
                type_str = type_names.get(p_type, f"0x{p_type:x}")
                
                # Format flags
                flag_str = ""
                if p_flags & 4: flag_str += "R"
                if p_flags & 2: flag_str += "W"  
                if p_flags & 1: flag_str += "X"
                
                print(f"{type_str:<12} 0x{p_offset:<10x} 0x{p_vaddr:<10x} 0x{p_paddr:<10x} "
                      f"0x{p_filesz:<10x} 0x{p_memsz:<10x} {flag_str}")
                
                segments.append({
                    'type': p_type, 'offset': p_offset, 'vaddr': p_vaddr,
                    'filesz': p_filesz, 'memsz': p_memsz, 'flags': p_flags
                })
            
            return segments
            
    except Exception as e:
        print(f"❌ Error reading {filename}: {e}")
        return None

def compare_segments(cpp_file, py_file):
    """Compare segments between C++ and Python versions"""
    print("=" * 80)
    print("ELF SEGMENTS COMPARISON")
    print("=" * 80)
    
    cpp_segments = read_program_headers(cpp_file)
    py_segments = read_program_headers(py_file)
    
    if not cpp_segments or not py_segments:
        return
    
    print(f"\n🔍 COMPARISON RESULTS:")
    print("=" * 80)
    
    if len(cpp_segments) != len(py_segments):
        print(f"❌ Different number of segments: C++={len(cpp_segments)}, Python={len(py_segments)}")
        return
    
    differences = 0
    for i, (cpp, py) in enumerate(zip(cpp_segments, py_segments)):
        if cpp != py:
            differences += 1
            print(f"❌ Segment {i} differs:")
            print(f"   C++:    offset=0x{cpp['offset']:x}, vaddr=0x{cpp['vaddr']:x}, "
                  f"filesz=0x{cpp['filesz']:x}, memsz=0x{cpp['memsz']:x}")
            print(f"   Python: offset=0x{py['offset']:x}, vaddr=0x{py['vaddr']:x}, "
                  f"filesz=0x{py['filesz']:x}, memsz=0x{py['memsz']:x}")
        else:
            print(f"✅ Segment {i}: identical")
    
    if differences == 0:
        print("🎉 ALL SEGMENTS ARE IDENTICAL!")
    else:
        print(f"💥 Found {differences} different segments")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        compare_segments(sys.argv[1], sys.argv[2])
    else:
        # Default comparison
        cpp_file = "libjiagu_fixed.so"
        py_file = "libjiagu_fixed_py.so"
        
        if len(sys.argv) == 2:
            py_file = sys.argv[1]
        
        compare_segments(cpp_file, py_file)