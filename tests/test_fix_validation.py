#!/usr/bin/env python3
"""
测试修复后的程序头
"""

import sys
import os
import logging

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sofixer.elf_reader import ObfuscatedELFReader
from sofixer.elf_rebuilder import ELFRebuilder

# 配置日志
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

def test_with_debug():
    """测试修复后的程序头处理"""
    input_file = "libjiagu_64.so_0x7a1301e000_0x27e000.so"
    dump_base_addr = 0x7a1301e000
    output_file = "libjiagu_fixed_py_new.so"
    
    print(f"测试文件: {input_file}")
    print(f"Dump基地址: 0x{dump_base_addr:x}")
    print("=" * 80)
    
    try:
        # 创建ELF读取器
        with ObfuscatedELFReader(input_file) as elf_reader:
            elf_reader.set_dump_base_addr(dump_base_addr)
            
            # 读取原始程序头
            if not (elf_reader.open() and 
                    elf_reader.read_elf_header() and 
                    elf_reader.read_program_headers()):
                print("❌ ELF文件读取失败")
                return False
            
            print("\n修复前的程序头:")
            elf_reader.list_program_headers()
            
            # 执行修复
            elf_reader.fix_dump_program_headers()
            
            print("\n修复后的程序头:")
            elf_reader.list_program_headers()
            
            # 完成加载流程
            if not (elf_reader.reserve_address_space() and
                    elf_reader.load_segments() and
                    elf_reader.find_phdr() and
                    elf_reader.apply_phdr_table() and
                    elf_reader.read_section_headers()):
                print("❌ ELF完整加载失败")
                return False
            
            print("✓ ELF完整加载成功")
            
            # 重建ELF文件
            rebuilder = ELFRebuilder(elf_reader)
            if not rebuilder.rebuild():
                print("❌ ELF重建失败")
                return False
            
            # 保存到文件
            rebuilt_data = rebuilder.get_rebuilt_data()
            if rebuilt_data:
                with open(output_file, 'wb') as f:
                    f.write(rebuilt_data)
                print(f"✓ 新文件已保存: {output_file}")
                return True
            else:
                print("❌ 重建数据为空")
                return False
                
    except Exception as e:
        print(f"❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_with_debug()