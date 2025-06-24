#!/usr/bin/env python3
import struct

def check_elf_header(filename):
    with open(filename, 'rb') as f:
        data = f.read(64)
        
        magic = data[:4]
        if magic != b'\x7fELF':
            print('不是有效的ELF文件')
            return
            
        class_byte = data[4]
        print(f'ELF类别: {"64-bit" if class_byte == 2 else "32-bit"}')
        
        if class_byte == 2:
            e_shoff = struct.unpack('<Q', data[40:48])[0]
            e_shnum = struct.unpack('<H', data[60:62])[0]
            e_shstrndx = struct.unpack('<H', data[62:64])[0]
            
            print(f'段头表偏移: 0x{e_shoff:x}')
            print(f'段头表条目数: {e_shnum}')
            print(f'字符串表索引: {e_shstrndx}')
            
            if e_shoff == 0:
                print('❌ 段头表偏移为0，没有段头表!')
            else:
                print('✓ 段头表偏移有效')

print('Python版本:')
check_elf_header('/Users/oliver/Documents/Projects/C++/SoFixer/libjiagu_fixed_py.so')
print()
print('C++版本:')  
check_elf_header('/Users/oliver/Documents/Projects/C++/SoFixer/libjiagu_fixed.so')