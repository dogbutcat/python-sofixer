#!/usr/bin/env python3
"""
测试程序头差异
"""

import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sofixer.elf_reader import ELFReader

def test_program_headers(file_path):
    """测试程序头"""
    print(f"\n分析文件: {file_path}")
    
    with ELFReader(file_path) as reader:
        if not reader.open():
            print("❌ 文件打开失败")
            return False
            
        if not reader.read_elf_header():
            print("❌ ELF头部读取失败")
            return False
            
        if not reader.read_program_headers():
            print("❌ 程序头读取失败") 
            return False
        
        reader.list_program_headers()
        return True

if __name__ == "__main__":
    print("比较C++和Python版本的程序头...")
    
    cpp_file = "libjiagu_fixed.so"
    py_file = "libjiagu_fixed_py_new.so"  # 使用新生成的文件
    
    print("=" * 80)
    print("C++版本程序头:")
    test_program_headers(cpp_file)
    
    print("\n" + "=" * 80)
    print("Python版本程序头:")
    test_program_headers(py_file)