#!/usr/bin/env python3
"""
SoFixer调试脚本
=============

这个脚本提供了快速调试和测试SoFixer功能的便捷方法。
包含了多种调试场景和验证检查。
"""

import sys
import os
import logging

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sofixer.elf_reader import ObfuscatedELFReader
from sofixer.elf_rebuilder import ELFRebuilder
from sofixer.utils import setup_logging, parse_memory_address

def debug_basic_functionality():
    """调试基本的ELF修复功能"""
    print("🔧 调试基本ELF修复功能")
    
    # 设置参数
    input_file = "samples/libjiagu_64.so_0x7a1301e000_0x27e000.so"
    output_file = "output/libjiagu_fixed_debug.so"
    dump_base_addr = 0x7a1301e000
    
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"❌ 输入文件不存在: {input_file}")
        return False
    
    print(f"📂 输入文件: {input_file}")
    print(f"📤 输出文件: {output_file}")
    print(f"🏠 内存基地址: 0x{dump_base_addr:x}")
    
    try:
        # 创建ELF读取器
        with ObfuscatedELFReader(input_file) as elf_reader:
            print("\n📖 加载ELF文件...")
            elf_reader.set_dump_base_addr(dump_base_addr)
            if not elf_reader.load():
                print("❌ ELF文件加载失败")
                return False
            
            print(f"✅ ELF文件加载成功")
            print(f"   架构: {'64位' if elf_reader.is_64bit else '32位'}")
            print(f"   程序头数量: {len(elf_reader.program_headers)}")
            
            # 创建重建器
            rebuilder = ELFRebuilder(elf_reader)
            print("\n🔨 开始ELF重建...")
            
            if not rebuilder.rebuild():
                print("❌ ELF重建失败")
                return False
            
            print("✅ ELF重建成功")
            
            # 保存结果
            os.makedirs("output", exist_ok=True)
            if rebuilder.save_rebuilt_elf(output_file):
                print(f"✅ 文件保存成功: {output_file}")
                return True
            else:
                print("❌ 文件保存失败")
                return False
                
    except Exception as e:
        print(f"❌ 调试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
        return False

def debug_program_headers():
    """调试程序头处理"""
    print("\n📋 调试程序头处理")
    
    input_file = "samples/libjiagu_64.so_0x7a1301e000_0x27e000.so"
    
    if not os.path.exists(input_file):
        print(f"❌ 输入文件不存在: {input_file}")
        return
    
    try:
        with ObfuscatedELFReader(input_file) as elf_reader:
            elf_reader.set_dump_base_addr(0x7a1301e000)
            if not elf_reader.load():
                print("❌ ELF文件加载失败")
                return
            
            print(f"程序头信息:")
            for i, phdr in enumerate(elf_reader.program_headers):
                print(f"  段 {i}: 类型={phdr.p_type:2d} 偏移=0x{phdr.p_offset:08x} "
                      f"虚拟地址=0x{phdr.p_vaddr:08x} 大小=0x{phdr.p_filesz:08x}")
                
    except Exception as e:
        print(f"❌ 程序头调试失败: {e}")

def debug_section_creation():
    """调试段创建过程"""
    print("\n🏗️ 调试段创建过程")
    
    input_file = "samples/libjiagu_64.so_0x7a1301e000_0x27e000.so"
    
    if not os.path.exists(input_file):
        print(f"❌ 输入文件不存在: {input_file}")
        return
    
    try:
        with ObfuscatedELFReader(input_file) as elf_reader:
            elf_reader.set_dump_base_addr(0x7a1301e000)
            if not elf_reader.load():
                print("❌ ELF文件加载失败")
                return
            
            rebuilder = ELFRebuilder(elf_reader)
            
            # 提取SO信息
            if not rebuilder.extract_so_info():
                print("❌ SO信息提取失败")
                return
            
            print("✅ SO信息提取成功")
            print(f"   最小加载地址: 0x{rebuilder.so_info.min_load:x}")
            print(f"   最大加载地址: 0x{rebuilder.so_info.max_load:x}")
            print(f"   动态段数量: {rebuilder.so_info.dynamic_count}")
            
    except Exception as e:
        print(f"❌ 段创建调试失败: {e}")

def run_comparison_test():
    """运行比较测试"""
    print("\n🔍 运行比较测试")
    
    # 检查是否有C++版本的输出用于比较
    cpp_output = "samples/libjiagu_fixed.so"
    python_output = "output/libjiagu_fixed_debug.so"
    
    if os.path.exists(cpp_output) and os.path.exists(python_output):
        print(f"📊 比较C++版本和Python版本的输出...")
        # 这里可以调用check_segments.py或其他比较工具
        import subprocess
        try:
            result = subprocess.run([
                "python", "../tools/check_segments.py", cpp_output, python_output
            ], capture_output=True, text=True, cwd=os.path.dirname(__file__))
            print(result.stdout)
            if result.stderr:
                print("错误输出:", result.stderr)
        except Exception as e:
            print(f"❌ 比较测试失败: {e}")
    else:
        print("⚠️ 缺少比较文件，跳过比较测试")

def main():
    """主调试函数"""
    print("🚀 SoFixer Python版本调试脚本")
    print("=" * 50)
    
    # 设置日志
    setup_logging(debug=True)
    
    # 切换到debug目录
    debug_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(debug_dir)
    
    print(f"📁 工作目录: {os.getcwd()}")
    
    # 运行调试测试
    tests = [
        ("基本功能测试", debug_basic_functionality),
        ("程序头调试", debug_program_headers),
        ("段创建调试", debug_section_creation),
        ("比较测试", run_comparison_test)
    ]
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if callable(test_func):
                test_func()
            else:
                test_func
        except Exception as e:
            print(f"❌ {test_name}失败: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*50}")
    print("🏁 调试脚本执行完成")

if __name__ == "__main__":
    main()