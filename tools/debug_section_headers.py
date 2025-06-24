#!/usr/bin/env python3
"""
ELF Section Header Debug Tool
=============================

用于诊断Python版本和C++版本生成的ELF文件在段头表方面的差异。
这个工具帮助识别为什么IDA显示的段名不同。
"""

import sys
import struct
from typing import List, Dict, Any

def read_elf_header(file_path: str) -> Dict[str, Any]:
    """读取ELF头部信息"""
    with open(file_path, 'rb') as f:
        # 读取ELF标识符
        e_ident = f.read(16)
        if e_ident[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF file")
        
        is_64bit = e_ident[4] == 2
        
        if is_64bit:
            # 64位ELF头部格式
            data = f.read(48)  # 64位头部剩余48字节
            fields = struct.unpack('<HHIQQQIHHHHHH', data)
            header = {
                'is_64bit': True,
                'e_type': fields[0],
                'e_machine': fields[1],
                'e_version': fields[2],
                'e_entry': fields[3],
                'e_phoff': fields[4],
                'e_shoff': fields[5],
                'e_flags': fields[6],
                'e_ehsize': fields[7],
                'e_phentsize': fields[8],
                'e_phnum': fields[9],
                'e_shentsize': fields[10],
                'e_shnum': fields[11],
                'e_shstrndx': fields[12]
            }
        else:
            # 32位ELF头部格式
            data = f.read(36)  # 32位头部剩余36字节
            fields = struct.unpack('<HHIIIIIHHHHHH', data)
            header = {
                'is_64bit': False,
                'e_type': fields[0],
                'e_machine': fields[1],
                'e_version': fields[2],
                'e_entry': fields[3],
                'e_phoff': fields[4],
                'e_shoff': fields[5],
                'e_flags': fields[6],
                'e_ehsize': fields[7],
                'e_phentsize': fields[8],
                'e_phnum': fields[9],
                'e_shentsize': fields[10],
                'e_shnum': fields[11],
                'e_shstrndx': fields[12]
            }
        
        return header

def read_section_headers(file_path: str) -> List[Dict[str, Any]]:
    """读取所有段头表"""
    with open(file_path, 'rb') as f:
        header = read_elf_header(file_path)
        
        # 跳转到段头表位置
        f.seek(header['e_shoff'])
        
        sections = []
        for i in range(header['e_shnum']):
            if header['is_64bit']:
                # 64位段头格式
                data = f.read(64)
                fields = struct.unpack('<IIQQQQQQQQ', data)
                section = {
                    'sh_name': fields[0],
                    'sh_type': fields[1],
                    'sh_flags': fields[2],
                    'sh_addr': fields[3],
                    'sh_offset': fields[4],
                    'sh_size': fields[5],
                    'sh_link': fields[6],
                    'sh_info': fields[7],
                    'sh_addralign': fields[8],
                    'sh_entsize': fields[9]
                }
            else:
                # 32位段头格式
                data = f.read(40)
                fields = struct.unpack('<IIIIIIIIII', data)
                section = {
                    'sh_name': fields[0],
                    'sh_type': fields[1],
                    'sh_flags': fields[2],
                    'sh_addr': fields[3],
                    'sh_offset': fields[4],
                    'sh_size': fields[5],
                    'sh_link': fields[6],
                    'sh_info': fields[7],
                    'sh_addralign': fields[8],
                    'sh_entsize': fields[9]
                }
            sections.append(section)
        
        return sections

def read_string_table(file_path: str, sections: List[Dict[str, Any]], strtab_index: int) -> bytes:
    """读取字符串表"""
    if strtab_index >= len(sections):
        return b''
    
    strtab_section = sections[strtab_index]
    with open(file_path, 'rb') as f:
        f.seek(strtab_section['sh_offset'])
        return f.read(strtab_section['sh_size'])

def get_section_name(strtab: bytes, name_offset: int) -> str:
    """从字符串表获取段名"""
    if name_offset >= len(strtab):
        return ""
    
    end = strtab.find(b'\x00', name_offset)
    if end == -1:
        end = len(strtab)
    
    return strtab[name_offset:end].decode('utf-8', errors='ignore')

def analyze_elf_file(file_path: str) -> Dict[str, Any]:
    """完整分析ELF文件的段头表"""
    print(f"\n分析文件: {file_path}")
    print("=" * 80)
    
    try:
        header = read_elf_header(file_path)
        sections = read_section_headers(file_path)
        
        # 读取段名字符串表
        if header['e_shstrndx'] < len(sections):
            strtab = read_string_table(file_path, sections, header['e_shstrndx'])
        else:
            strtab = b''
        
        print(f"ELF 头部信息:")
        print(f"  架构: {'64位' if header['is_64bit'] else '32位'}")
        print(f"  机器类型: {header['e_machine']}")
        print(f"  段头表偏移: 0x{header['e_shoff']:x}")
        print(f"  段数量: {header['e_shnum']}")
        print(f"  段名字符串表索引: {header['e_shstrndx']}")
        
        print(f"\n段头表详细信息:")
        print(f"{'索引':<4} {'段名':<20} {'类型':<12} {'地址':<12} {'偏移':<12} {'大小':<12} {'对齐':<8}")
        print("-" * 80)
        
        section_info = []
        for i, section in enumerate(sections):
            name = get_section_name(strtab, section['sh_name']) if strtab else f"offset_{section['sh_name']}"
            
            # 段类型映射
            type_names = {
                0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 
                5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 
                11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 0x70000001: "ARM_EXIDX"
            }
            type_name = type_names.get(section['sh_type'], f"{section['sh_type']}")
            
            print(f"{i:<4} {name:<20} {type_name:<12} 0x{section['sh_addr']:<10x} "
                  f"0x{section['sh_offset']:<10x} 0x{section['sh_size']:<10x} {section['sh_addralign']:<8}")
            
            section_info.append({
                'index': i,
                'name': name,
                'type': section['sh_type'],
                'type_name': type_name,
                'addr': section['sh_addr'],
                'offset': section['sh_offset'],
                'size': section['sh_size'],
                'align': section['sh_addralign']
            })
        
        return {
            'header': header,
            'sections': section_info,
            'raw_strtab': strtab
        }
        
    except Exception as e:
        print(f"分析文件时出错: {e}")
        return None

def compare_files(file1: str, file2: str):
    """比较两个ELF文件的段头表差异"""
    print(f"\n比较文件: {file1} vs {file2}")
    print("=" * 80)
    
    info1 = analyze_elf_file(file1)
    info2 = analyze_elf_file(file2)
    
    if not info1 or not info2:
        print("无法完成比较，文件分析失败")
        return
    
    print(f"\n差异分析:")
    print("-" * 80)
    
    # 比较段数量
    if len(info1['sections']) != len(info2['sections']):
        print(f"⚠️  段数量不同: {len(info1['sections'])} vs {len(info2['sections'])}")
    else:
        print(f"✓ 段数量相同: {len(info1['sections'])}")
    
    # 比较各段详情
    max_sections = max(len(info1['sections']), len(info2['sections']))
    
    print(f"\n段对比详情:")
    print(f"{'索引':<4} {'文件1段名':<20} {'文件2段名':<20} {'地址差异':<12} {'大小差异':<12}")
    print("-" * 80)
    
    for i in range(max_sections):
        s1 = info1['sections'][i] if i < len(info1['sections']) else None
        s2 = info2['sections'][i] if i < len(info2['sections']) else None
        
        if s1 and s2:
            addr_diff = s1['addr'] - s2['addr'] if s1['addr'] != s2['addr'] else 0
            size_diff = s1['size'] - s2['size'] if s1['size'] != s2['size'] else 0
            
            status = "✓" if s1['name'] == s2['name'] and addr_diff == 0 and size_diff == 0 else "⚠️"
            
            print(f"{i:<4} {s1['name']:<20} {s2['name']:<20} "
                  f"{addr_diff:+<12} {size_diff:+<12} {status}")
            
            if s1['name'] != s2['name']:
                print(f"     ⚠️  段名不同!")
            if addr_diff != 0:
                print(f"     ⚠️  地址不同: 0x{s1['addr']:x} vs 0x{s2['addr']:x}")
            if size_diff != 0:
                print(f"     ⚠️  大小不同: 0x{s1['size']:x} vs 0x{s2['size']:x}")
        elif s1:
            print(f"{i:<4} {s1['name']:<20} {'<缺失>':<20} {'N/A':<12} {'N/A':<12} ⚠️")
        elif s2:
            print(f"{i:<4} {'<缺失>':<20} {s2['name']:<20} {'N/A':<12} {'N/A':<12} ⚠️")

def main():
    if len(sys.argv) < 2:
        print("用法:")
        print(f"  {sys.argv[0]} <elf_file>              # 分析单个文件")
        print(f"  {sys.argv[0]} <file1> <file2>         # 比较两个文件")
        sys.exit(1)
    
    if len(sys.argv) == 2:
        # 分析单个文件
        analyze_elf_file(sys.argv[1])
    else:
        # 比较两个文件
        compare_files(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()