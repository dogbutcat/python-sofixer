#!/usr/bin/env python3
"""
分析dump文件结构来理解正确的偏移量计算
"""

def analyze_files():
    """分析不同文件的结构"""
    
    # 分析原始dump文件
    print("=== 分析原始dump文件 ===")
    with open("libjiagu_64.so_0x7a1301e000_0x27e000.so", "rb") as f:
        f.seek(0x1e758)  # Python版本的第二段偏移
        data1 = f.read(16)
        print(f"offset 0x1e758: {data1.hex()}")
        
        f.seek(0x2e758)  # C++版本的第二段偏移  
        data2 = f.read(16)
        print(f"offset 0x2e758: {data2.hex()}")
    
    print("\n=== 分析C++生成的文件 ===")
    with open("libjiagu_fixed.so", "rb") as f:
        f.seek(0x2e758)  # C++版本的第二段偏移
        data3 = f.read(16)
        print(f"offset 0x2e758: {data3.hex()}")
    
    print("\n=== 分析Python生成的文件 ===")
    with open("libjiagu_fixed_py.so", "rb") as f:
        f.seek(0x1e758)  # Python版本的第二段偏移
        data4 = f.read(16)
        print(f"offset 0x1e758: {data4.hex()}")
        
        f.seek(0x2e758)  # 也检查C++版本的偏移位置
        data5 = f.read(16)
        print(f"offset 0x2e758: {data5.hex()}")
    
    # 计算dump_base_addr的含义
    print(f"\n=== dump_base_addr分析 ===")
    dump_base = 0x7a1301e000
    print(f"dump_base_addr: 0x{dump_base:x}")
    print(f"第一段vaddr: 0x0")
    print(f"第二段vaddr: 0x2e758")
    
    # 如果dump_base_addr是内存中的基地址
    # 那么第二段在内存中的地址是: dump_base + 0x2e758
    second_segment_mem_addr = dump_base + 0x2e758
    print(f"第二段内存地址: 0x{second_segment_mem_addr:x}")
    
    # 在dump文件中，这个地址对应的文件偏移应该是什么？
    # 如果dump文件是从dump_base开始的连续内存映像
    # 那么偏移量应该就是相对于dump_base的偏移，即0x2e758
    
    print(f"\n理论上正确的偏移量:")
    print(f"第一段: vaddr=0x0, offset=0x0")  
    print(f"第二段: vaddr=0x2e758, offset=0x2e758")

if __name__ == "__main__":
    analyze_files()