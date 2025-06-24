#!/usr/bin/env python3
"""
比较C++和Python版本生成的段头表
"""
import struct

def read_section_headers(filename):
    """读取ELF文件的段头表"""
    with open(filename, 'rb') as f:
        # 读取ELF头
        elf_header = f.read(64)
        
        # 解析ELF头
        e_shoff = struct.unpack('<Q', elf_header[40:48])[0]
        e_shnum = struct.unpack('<H', elf_header[60:62])[0]
        e_shstrndx = struct.unpack('<H', elf_header[62:64])[0]
        
        print(f"段头表偏移: 0x{e_shoff:x}")
        print(f"段头表条目数: {e_shnum}")
        print(f"字符串表索引: {e_shstrndx}")
        
        # 读取段头表
        f.seek(e_shoff)
        section_headers = []
        
        for i in range(e_shnum):
            # 64位段头结构 (40字节)
            shdr_data = f.read(64)  # sizeof(Elf64_Shdr) = 64
            
            if len(shdr_data) < 64:
                print(f"警告: 段头{i}数据不完整")
                continue
                
            shdr = struct.unpack('<LLQQQQLLQQ', shdr_data)
            section_headers.append({
                'sh_name': shdr[0],
                'sh_type': shdr[1], 
                'sh_flags': shdr[2],
                'sh_addr': shdr[3],
                'sh_offset': shdr[4],
                'sh_size': shdr[5],
                'sh_link': shdr[6],
                'sh_info': shdr[7],
                'sh_addralign': shdr[8],
                'sh_entsize': shdr[9]
            })
        
        # 读取字符串表
        if e_shstrndx < len(section_headers):
            shstrtab_shdr = section_headers[e_shstrndx]
            f.seek(shstrtab_shdr['sh_offset'])
            shstrtab = f.read(shstrtab_shdr['sh_size'])
        else:
            shstrtab = b''
        
        return section_headers, shstrtab

def get_section_name(shstrtab, name_offset):
    """从字符串表中获取段名"""
    if name_offset >= len(shstrtab):
        return f"<invalid:{name_offset}>"
    
    end = shstrtab.find(0, name_offset)
    if end == -1:
        end = len(shstrtab)
        
    return shstrtab[name_offset:end].decode('utf-8', errors='ignore')

def compare_files(cpp_file, py_file):
    """比较两个文件的段头表"""
    print("=== C++版本段头表 ===")
    cpp_headers, cpp_strtab = read_section_headers(cpp_file)
    for i, shdr in enumerate(cpp_headers):
        name = get_section_name(cpp_strtab, shdr['sh_name'])
        print(f"{i:2d}: {name:<20} type={shdr['sh_type']:2d} addr=0x{shdr['sh_addr']:08x} size=0x{shdr['sh_size']:08x}")
    
    print("\n=== Python版本段头表 ===")
    py_headers, py_strtab = read_section_headers(py_file)
    for i, shdr in enumerate(py_headers):
        name = get_section_name(py_strtab, shdr['sh_name'])
        print(f"{i:2d}: {name:<20} type={shdr['sh_type']:2d} addr=0x{shdr['sh_addr']:08x} size=0x{shdr['sh_size']:08x}")
    
    print("\n=== 差异分析 ===")
    if len(cpp_headers) != len(py_headers):
        print(f"❌ 段头表条目数不同: C++={len(cpp_headers)}, Python={len(py_headers)}")
    
    max_len = max(len(cpp_headers), len(py_headers))
    differences = 0
    
    for i in range(max_len):
        cpp_shdr = cpp_headers[i] if i < len(cpp_headers) else None
        py_shdr = py_headers[i] if i < len(py_headers) else None
        
        if cpp_shdr is None:
            print(f"❌ 段{i}: Python有额外段")
            differences += 1
        elif py_shdr is None:
            print(f"❌ 段{i}: C++有额外段") 
            differences += 1
        else:
            cpp_name = get_section_name(cpp_strtab, cpp_shdr['sh_name'])
            py_name = get_section_name(py_strtab, py_shdr['sh_name'])
            
            if cpp_shdr != py_shdr or cpp_name != py_name:
                print(f"❌ 段{i}: {cpp_name} vs {py_name}")
                if cpp_name != py_name:
                    print(f"    名称: '{cpp_name}' vs '{py_name}'")
                for field in ['sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 'sh_size']:
                    if cpp_shdr[field] != py_shdr[field]:
                        print(f"    {field}: 0x{cpp_shdr[field]:x} vs 0x{py_shdr[field]:x}")
                differences += 1
            else:
                print(f"✓ 段{i}: {cpp_name} - 完全一致")
    
    if differences == 0:
        print("\n🎉 所有段头表完全一致!")
    else:
        print(f"\n💥 发现{differences}个差异")

if __name__ == '__main__':
    compare_files(
        '/Users/oliver/Documents/Projects/C++/SoFixer/libjiagu_fixed.so',
        '/Users/oliver/Documents/Projects/C++/SoFixer/libjiagu_fixed_py.so'
    )