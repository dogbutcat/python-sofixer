#!/usr/bin/env python3
"""
ELF Reader Module for SoFixer
============================

提取自sofixer.py的ELF读取器模块，专门负责ELF文件的解析和加载。

包含两个主要类：
- ELFReader: 基础ELF文件读取器，使用内存映射技术
- ObfuscatedELFReader: 专门处理混淆/dumped SO文件的增强版读取器

特性：
- 内存映射文件读取，提供高性能访问
- 自动检测32/64位架构
- 完整的ELF结构解析（头部、程序头、段头）  
- 虚拟地址到内存偏移量的精确转换
- 动态段解析和重定位支持
- 混淆SO文件的程序头修复
"""

import sys
import os
import ctypes
import mmap
import logging
import struct
from typing import Optional, List

# 导入所有ELF类型定义
from .types import *

# 配置日志
logger = logging.getLogger(__name__)

# =============================================================================
# ELF架构检测和类型选择
# =============================================================================

def detect_elf_architecture(file_path: str) -> Optional[str]:
    """
    自动检测ELF文件是32位还是64位架构
    
    Args:
        file_path: ELF文件路径
        
    Returns:
        "32" 表示32位，"64" 表示64位，None表示无效ELF或错误
    """
    try:
        with open(file_path, 'rb') as f:
            # 读取ELF标识信息（前16字节）
            e_ident = f.read(16)
            
            # 检查ELF魔数
            if len(e_ident) < 5 or e_ident[:4] != b'\x7fELF':
                return None
                
            # 第5个字节（索引4）指示架构类型
            # 1 = 32位，2 = 64位
            elf_class = e_ident[4]
            if elf_class == 1:
                return "32"
            elif elf_class == 2:
                return "64"
            else:
                return None
                
    except (IOError, OSError):
        return None


def get_elf_types(is_64bit: bool):
    """
    根据ELF架构获取相应的ctypes结构类型
    
    Args:
        is_64bit: True表示64位，False表示32位
        
    Returns:
        包含所有ELF结构类型的字典
    """
    if is_64bit:
        return {
            'Ehdr': Elf64_Ehdr,
            'Phdr': Elf64_Phdr,
            'Shdr': Elf64_Shdr,
            'Dyn': Elf64_Dyn,
            'Sym': Elf64_Sym,
            'Rel': Elf64_Rel,
            'Rela': Elf64_Rela,
            'auxv_t': Elf64_auxv_t,
            'Addr': Elf64_Addr,
            'Off': Elf64_Off,
            'Word': Elf64_Word,
            'Half': Elf64_Half,
            'Xword': Elf64_Xword,
        }
    else:
        return {
            'Ehdr': Elf32_Ehdr,
            'Phdr': Elf32_Phdr,
            'Shdr': Elf32_Shdr,
            'Dyn': Elf32_Dyn,
            'Sym': Elf32_Sym,
            'Rel': Elf32_Rel,
            'Rela': Elf32_Rela,
            'auxv_t': Elf32_auxv_t,
            'Addr': Elf32_Addr,
            'Off': Elf32_Off,
            'Word': Elf32_Word,
            'Half': Elf32_Half,
            'Xword': Elf32_Xword,
        }


# =============================================================================
# 内存映射ELF文件读取器
# =============================================================================

class ELFReader:
    """
    使用ctypes精确二进制解析的内存映射ELF文件读取器
    
    该类提供高性能的ELF文件读取功能，使用内存映射和ctypes结构
    来完全匹配C语言ELF定义，确保二进制级别的准确性。
    """
    
    def __init__(self, file_path: str):
        """
        使用文件路径初始化ELF读取器
        
        Args:
            file_path: 要读取的ELF文件路径
        """
        self.file_path = file_path
        self.file_size = 0
        self.mmap_file = None
        self.file_handle = None
        self.is_64bit = False
        self.types = None
        self.header = None
        self.program_headers = []
        self.section_headers = []
        self.load_bias = 0
        self.loaded_data = None
        
    def __enter__(self):
        """上下文管理器入口"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()
        
    def open(self) -> bool:
        """
        打开并内存映射ELF文件
        
        Returns:
            成功打开返回True，失败返回False
        """
        try:
            # 首先检测架构
            arch = detect_elf_architecture(self.file_path)
            if arch is None:
                logger.error(f"Not a valid ELF file: {self.file_path}")
                return False
                
            self.is_64bit = (arch == "64")
            self.types = get_elf_types(self.is_64bit)
            
            # 打开文件并创建内存映射
            self.file_handle = open(self.file_path, 'rb')
            self.file_size = os.path.getsize(self.file_path)
            
            if self.file_size == 0:
                logger.error("File is empty")
                return False
                
            self.mmap_file = mmap.mmap(self.file_handle.fileno(), 0, access=mmap.ACCESS_READ)
            
            logger.info(f"Opened ELF file: {self.file_path} "
                       f"({'64-bit' if self.is_64bit else '32-bit'}, {self.file_size} bytes)")
            return True
            
        except (IOError, OSError, ValueError) as e:
            logger.error(f"Failed to open file {self.file_path}: {e}")
            self.close()
            return False
    
    def close(self):
        """关闭文件句柄和内存映射"""
        if self.mmap_file:
            self.mmap_file.close()
            self.mmap_file = None
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def read_elf_header(self) -> bool:
        """
        使用ctypes读取和解析ELF头部
        
        Returns:
            头部成功读取返回True，失败返回False
        """
        if not self.mmap_file:
            return False
            
        try:
            # 直接从内存映射中使用ctypes读取头部
            header_size = ctypes.sizeof(self.types['Ehdr'])
            if self.file_size < header_size:
                logger.error("File too small for ELF header")
                return False
                
            # 从内存映射创建头部结构
            self.header = self.types['Ehdr'].from_buffer_copy(self.mmap_file[:header_size])
            
            # 验证ELF魔数
            magic = bytes(self.header.e_ident[:4])
            if magic != b'\x7fELF':
                logger.error("Invalid ELF magic number")
                return False
                
            # 验证架构是否匹配检测结果
            expected_class = ELFClass.ELFCLASS64 if self.is_64bit else ELFClass.ELFCLASS32
            if self.header.e_ident[4] != expected_class:
                logger.error("ELF class mismatch")
                return False
                
            # 检查字节序（我们期望小端序）
            if self.header.e_ident[5] != ELFData.ELFDATA2LSB:
                logger.error("Only little-endian ELF files are supported")
                return False
                
            logger.debug(f"ELF header: type={self.header.e_type}, machine={self.header.e_machine}, "
                        f"entry=0x{self.header.e_entry:x}, phnum={self.header.e_phnum}")
            return True
            
        except (ValueError, struct.error) as e:
            logger.error(f"Failed to read ELF header: {e}")
            return False
    
    def read_program_headers(self) -> bool:
        """
        使用ctypes读取所有程序头
        
        Returns:
            程序头成功读取返回True，失败返回False
        """
        if not self.header:
            return False
            
        try:
            phoff = self.header.e_phoff
            phentsize = self.header.e_phentsize
            phnum = self.header.e_phnum
            
            if phnum == 0:
                logger.warning("No program headers found")
                return True
                
            # 验证程序头表边界
            expected_size = ctypes.sizeof(self.types['Phdr'])
            if phentsize != expected_size:
                logger.error(f"Program header size mismatch: expected {expected_size}, got {phentsize}")
                return False
                
            table_size = phnum * phentsize
            if phoff + table_size > self.file_size:
                logger.error("Program header table extends beyond file")
                return False
            
            # 直接从内存映射读取程序头
            self.program_headers = []
            for i in range(phnum):
                offset = phoff + (i * phentsize)
                phdr_data = self.mmap_file[offset:offset + phentsize]
                phdr = self.types['Phdr'].from_buffer_copy(phdr_data)
                self.program_headers.append(phdr)
                
                logger.debug(f"Program header {i}: type={phdr.p_type}, "
                           f"vaddr=0x{phdr.p_vaddr:x}, memsz=0x{phdr.p_memsz:x}")

            # ==========================================================
            # 新增代码：保存一份原始程序头的深拷贝，用于文件重构
            import copy
            self.original_program_headers = copy.deepcopy(self.program_headers)
            # ==========================================================

            logger.info(f"Read {len(self.program_headers)} program headers")
            return True
            
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to read program headers: {e}")
            return False
    
    def read_section_headers(self) -> bool:
        """
        使用ctypes读取所有段头
        
        Returns:
            段头成功读取返回True，失败返回False
        """
        if not self.header:
            return False
            
        try:
            shoff = self.header.e_shoff
            shentsize = self.header.e_shentsize
            shnum = self.header.e_shnum
            
            if shnum == 0 or shoff == 0:
                logger.warning("No section headers found")
                return True
                
            # 验证段头表边界
            expected_size = ctypes.sizeof(self.types['Shdr'])
            if shentsize != expected_size:
                logger.error(f"Section header size mismatch: expected {expected_size}, got {shentsize}")
                return False
                
            table_size = shnum * shentsize
            if shoff + table_size > self.file_size:
                logger.error("Section header table extends beyond file")
                return False
            
            # 直接从内存映射读取段头
            self.section_headers = []
            for i in range(shnum):
                offset = shoff + (i * shentsize)
                shdr_data = self.mmap_file[offset:offset + shentsize]
                shdr = self.types['Shdr'].from_buffer_copy(shdr_data)
                self.section_headers.append(shdr)
                
                logger.debug(f"Section header {i}: type={shdr.sh_type}, "
                           f"addr=0x{shdr.sh_addr:x}, size=0x{shdr.sh_size:x}")
            
            logger.info(f"Read {len(self.section_headers)} section headers")
            return True
            
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to read section headers: {e}")
            return False
    
    def calculate_load_size(self) -> tuple:
        """
        计算所有可加载段所需的内存大小
        
        Returns:
            (min_vaddr, max_vaddr, total_size)元组
        """
        if self.is_64bit:
            min_vaddr = 0xFFFFFFFFFFFFFFFF
        else:
            min_vaddr = 0xFFFFFFFF
        max_vaddr = 0
        found_load = False
        
        load_segment_count = 0
        for i, phdr in enumerate(self.program_headers):
            if phdr.p_type != SegmentType.PT_LOAD:
                continue
                
            found_load = True
            load_segment_count += 1
            logger.info(f"Found loadable segment #{load_segment_count} at program header index {i}")
            logger.info(f"  Virtual address: 0x{phdr.p_vaddr:x} - 0x{phdr.p_vaddr + phdr.p_memsz:x}")
            logger.info(f"  Memory size: 0x{phdr.p_memsz:x} bytes")
            
            if phdr.p_vaddr < min_vaddr:
                min_vaddr = phdr.p_vaddr
            if phdr.p_vaddr + phdr.p_memsz > max_vaddr:
                max_vaddr = phdr.p_vaddr + phdr.p_memsz
        
        if not found_load:
            return 0, 0, 0
            
        # 对齐到页边界 
        page_size = 4096
        min_vaddr = min_vaddr & ~(page_size - 1)  # PAGE_START
        max_vaddr = (max_vaddr + page_size - 1) & ~(page_size - 1)  # PAGE_END
        
        return min_vaddr, max_vaddr, max_vaddr - min_vaddr
    
    def load_segments(self) -> bool:
        """
        将所有PT_LOAD段加载到内存缓冲区
        
        Returns:
            段成功加载返回True，失败返回False
        """
        min_vaddr, max_vaddr, load_size = self.calculate_load_size()
        
        if load_size == 0:
            logger.error("No loadable segments found")
            return False
            
        self.load_bias = -min_vaddr  # 用于调整虚拟地址的偏移量
        
        # 为加载的段分配内存缓冲区
        self.loaded_data = bytearray(load_size)
        
        logger.info(f"Loading segments into {load_size} byte buffer "
                   f"(vaddr range: 0x{min_vaddr:x} - 0x{max_vaddr:x})")
        
        # 加载每个PT_LOAD段
        for i, phdr in enumerate(self.program_headers):
            if phdr.p_type != SegmentType.PT_LOAD:
                continue
                
            # 计算段在内存缓冲区中的位置
            seg_start = phdr.p_vaddr - min_vaddr
            seg_end = seg_start + phdr.p_filesz
            
            # 验证段边界
            if seg_end > load_size:
                logger.error(f"Segment {i} extends beyond allocated memory")
                return False
                
            if phdr.p_offset + phdr.p_filesz > self.file_size:
                logger.error(f"Segment {i} extends beyond file")
                return False
            
            # 从内存映射复制段数据到缓冲区
            if phdr.p_filesz > 0:
                file_start = phdr.p_offset
                file_end = file_start + phdr.p_filesz
                self.loaded_data[seg_start:seg_end] = self.mmap_file[file_start:file_end]
                
                logger.debug(f"Loaded segment {i}: file[0x{file_start:x}:0x{file_end:x}] "
                           f"-> mem[0x{seg_start:x}:0x{seg_end:x}]")
            
            # 零填充额外内存 (p_memsz > p_filesz)
            if phdr.p_memsz > phdr.p_filesz:
                zero_start = seg_start + phdr.p_filesz
                zero_end = seg_start + phdr.p_memsz
                if zero_end <= load_size:
                    # 由bytearray初始化已经归零
                    pass
        
        logger.info("All segments loaded successfully")
        return True
    
    def list_program_headers(self) -> None:
        """
        列出所有程序头的详细信息，用于调试
        """
        if not self.program_headers:
            print("No program headers available")
            return
        
        print("=" * 80)
        print("PROGRAM HEADERS:")
        print("=" * 80)
        print(f"{'Index':<5} {'Type':<12} {'VAddr':<12} {'PAddr':<12} {'Offset':<12} {'FileSz':<12} {'MemSz':<12} {'Flags':<8}")
        print("-" * 80)
        
        type_names = {
            0: "NULL",
            1: "LOAD", 
            2: "DYNAMIC",
            3: "INTERP",
            4: "NOTE",
            5: "SHLIB",
            6: "PHDR",
            7: "TLS",
            0x70000001: "ARM_EXIDX"
        }
        
        for i, phdr in enumerate(self.program_headers):
            type_name = type_names.get(phdr.p_type, f"0x{phdr.p_type:x}")
            
            # 解析标志位
            flags = ""
            if hasattr(phdr, 'p_flags'):
                if phdr.p_flags & 4: flags += "R"
                if phdr.p_flags & 2: flags += "W" 
                if phdr.p_flags & 1: flags += "X"
            
            print(f"{i:<5} {type_name:<12} 0x{phdr.p_vaddr:<10x} 0x{phdr.p_paddr:<10x} "
                  f"0x{phdr.p_offset:<10x} 0x{phdr.p_filesz:<10x} 0x{phdr.p_memsz:<10x} {flags:<8}")
        
        print("=" * 80)
    
    def reserve_address_space(self) -> bool:
        """
        预留地址空间，对应C++的ReserveAddressSpace()
        
        该函数确保虚拟地址空间的正确预留和管理，这对于内存dump文件的重建至关重要。
        与简单的段加载不同，这个步骤建立了正确的地址空间映射关系。
        
        Returns:
            成功预留地址空间返回True，失败返回False
        """
        logger.debug("=======================ReserveAddressSpace=========================")
        
        if not self.program_headers:
            logger.error("No program headers available for address space reservation")
            return False
        
        # 计算加载范围（与C++版本保持一致）
        min_vaddr, max_vaddr, load_size = self.calculate_load_size()
        
        if load_size == 0:
            logger.error("Cannot reserve address space: no loadable segments")
            return False
        
        # 设置加载偏移（对应C++的load_bias计算）
        self.load_bias = -min_vaddr
        self.reserved_size = load_size
        self.reserved_min_vaddr = min_vaddr
        self.reserved_max_vaddr = max_vaddr
        
        logger.debug(f"Address space reservation:")
        logger.debug(f"  Virtual address range: 0x{min_vaddr:x} - 0x{max_vaddr:x}")
        logger.debug(f"  Reserved size: 0x{load_size:x} bytes")
        logger.debug(f"  Load bias: 0x{self.load_bias:x}")
        
        # 验证所有可加载段都在预留范围内
        for i, phdr in enumerate(self.program_headers):
            if phdr.p_type != SegmentType.PT_LOAD:
                continue
                
            seg_start = phdr.p_vaddr
            seg_end = phdr.p_vaddr + phdr.p_memsz
            
            if seg_start < min_vaddr or seg_end > max_vaddr:
                logger.error(f"Segment {i} (0x{seg_start:x}-0x{seg_end:x}) "
                           f"extends beyond reserved space (0x{min_vaddr:x}-0x{max_vaddr:x})")
                return False
        
        logger.debug("Address space successfully reserved")
        return True
    
    def find_phdr(self) -> bool:
        """
        查找并验证程序头表，对应C++的FindPhdr()
        
        在段加载完成后，重新定位和验证程序头表的位置。
        这确保了程序头表信息与实际加载的段数据一致。
        
        Returns:
            成功找到并验证程序头表返回True，失败返回False
        """
        logger.debug("=======================FindPhdr=========================")
        
        if not hasattr(self, 'loaded_data') or not self.loaded_data:
            logger.error("Cannot find PHDR: segments not loaded yet")
            return False
        
        # 查找PT_PHDR段
        phdr_phdr = None
        for i, phdr in enumerate(self.program_headers):
            if phdr.p_type == SegmentType.PT_PHDR:
                phdr_phdr = phdr
                logger.debug(f"Found PT_PHDR at index {i}: vaddr=0x{phdr.p_vaddr:x}, "
                           f"size=0x{phdr.p_memsz:x}")
                break
        
        # 如果没有PT_PHDR段，尝试在ELF头中查找程序头表
        if phdr_phdr is None:
            logger.debug("No PT_PHDR segment found, using ELF header program header table")
            
            # 验证ELF头中的程序头表信息
            if not self.header:
                logger.error("No ELF header available")
                return False
            
            phoff = self.header.e_phoff
            phentsize = self.header.e_phentsize
            phnum = self.header.e_phnum
            
            # 检查程序头表是否在可加载段内
            expected_size = phnum * phentsize
            
            # 尝试将文件偏移转换为虚拟地址
            for phdr in self.program_headers:
                if phdr.p_type != SegmentType.PT_LOAD:
                    continue
                    
                if (phdr.p_offset <= phoff < phdr.p_offset + phdr.p_filesz and
                    phoff + expected_size <= phdr.p_offset + phdr.p_filesz):
                    
                    # 计算程序头表的虚拟地址
                    offset_in_segment = phoff - phdr.p_offset
                    phdr_vaddr = phdr.p_vaddr + offset_in_segment
                    
                    logger.debug(f"Program header table found in segment: "
                               f"file_offset=0x{phoff:x}, vaddr=0x{phdr_vaddr:x}, "
                               f"size=0x{expected_size:x}")
                    
                    # 记录程序头表的虚拟地址
                    self.phdr_table_vaddr = phdr_vaddr
                    self.phdr_table_size = expected_size
                    break
            else:
                logger.warning("Program header table not found in any loadable segment")
                return False
        else:
            # 使用PT_PHDR段的信息
            self.phdr_table_vaddr = phdr_phdr.p_vaddr
            self.phdr_table_size = phdr_phdr.p_memsz
        
        logger.debug(f"Program header table located at vaddr=0x{self.phdr_table_vaddr:x}, "
                   f"size=0x{self.phdr_table_size:x}")
        return True
    
    def apply_phdr_table(self) -> bool:
        """
        应用程序头表到内存布局，对应C++的ApplyPhdrTable()
        
        最终确认和应用程序头表的内存布局，确保所有程序头信息
        与实际的内存映射保持一致。
        
        Returns:
            成功应用程序头表返回True，失败返回False
        """
        logger.debug("=======================ApplyPhdrTable=========================")
        
        if not hasattr(self, 'phdr_table_vaddr'):
            logger.warning("Program header table virtual address not determined, skipping apply")
            return True
        
        # 验证程序头表在loaded_data中的可访问性
        phdr_offset = self.virtual_addr_to_loaded_offset(self.phdr_table_vaddr)
        if phdr_offset is None:
            logger.error(f"Program header table at vaddr=0x{self.phdr_table_vaddr:x} "
                        f"is not accessible in loaded data")
            return False
        
        # 验证程序头表大小
        if phdr_offset + self.phdr_table_size > len(self.loaded_data):
            logger.error("Program header table extends beyond loaded data")
            return False
        
        # 读取并验证程序头表数据
        phdr_data = self.loaded_data[phdr_offset:phdr_offset + self.phdr_table_size]
        expected_size = len(self.program_headers) * ctypes.sizeof(self.types['Phdr'])
        
        if len(phdr_data) < expected_size:
            logger.warning(f"Program header table data smaller than expected: "
                         f"got {len(phdr_data)}, expected {expected_size}")
        
        logger.debug(f"Program header table successfully applied: "
                   f"offset=0x{phdr_offset:x}, size=0x{len(phdr_data):x}")
        
        # 存储应用后的程序头表信息
        self.applied_phdr_offset = phdr_offset
        self.applied_phdr_size = len(phdr_data)
        
        return True
    
    def virtual_addr_to_loaded_offset(self, vaddr: int) -> Optional[int]:
        """
        将虚拟地址精确转换为loaded_data中的偏移量
        
        该函数解决了重定位处理中的核心问题：将ELF重定位表中的虚拟地址
        正确映射到重构后的内存缓冲区中的对应位置。
        
        Args:
            vaddr: 虚拟地址（来自重定位表的r_offset等）
            
        Returns:
            Optional[int]: loaded_data中的偏移量，如果地址无效则返回None
            
        算法逻辑:
            1. 遍历所有PT_LOAD段
            2. 检查虚拟地址是否在段的虚拟地址范围内
            3. 计算段内偏移量
            4. 转换为loaded_data中的绝对偏移量
        """
        if not hasattr(self, 'loaded_data') or not self.loaded_data:
            logger.error("loaded_data not available, call load_segments() first")
            return None
            
        if not hasattr(self, 'program_headers') or not self.program_headers:
            logger.error("program_headers not available")
            return None
        
        # 获取最小虚拟地址作为基准
        min_vaddr, _, _ = self.calculate_load_size()
        
        # 遍历所有可加载段，找到包含目标虚拟地址的段
        for phdr in self.program_headers:
            if phdr.p_type != SegmentType.PT_LOAD:
                continue
                
            # 检查虚拟地址是否在当前段的地址范围内
            seg_vaddr_start = phdr.p_vaddr
            seg_vaddr_end = phdr.p_vaddr + phdr.p_memsz
            
            if seg_vaddr_start <= vaddr < seg_vaddr_end:
                # 找到了包含目标地址的段
                seg_offset = vaddr - seg_vaddr_start  # 段内偏移
                
                # 计算该段在loaded_data中的起始位置
                loaded_seg_start = seg_vaddr_start - min_vaddr
                
                # 计算最终的loaded_data偏移量
                loaded_offset = loaded_seg_start + seg_offset
                
                # 边界检查：确保偏移量在有效范围内
                if 0 <= loaded_offset < len(self.loaded_data):
                    logger.debug(f"Address mapping: vaddr=0x{vaddr:x} -> "
                               f"seg_offset=0x{seg_offset:x} -> "
                               f"loaded_offset=0x{loaded_offset:x}")
                    return loaded_offset
                else:
                    logger.warning(f"Calculated offset 0x{loaded_offset:x} out of bounds "
                                 f"(loaded_data size: 0x{len(self.loaded_data):x})")
                    return None
        
        # 没有找到包含该虚拟地址的段
        logger.warning(f"Virtual address 0x{vaddr:x} not found in any PT_LOAD segment")
        return None
    
    def read_dynamic_section(self) -> List:
        """
        使用ctypes和正确的联合访问读取动态段条目
        
        重要：必须在load_segments()之后调用，因为要从加载后的内存数据中读取
        
        Returns:
            动态条目列表，作为ctypes结构
        """
        # 检查是否已经加载了段数据
        if not self.loaded_data:
            logger.error("Segments must be loaded before reading dynamic section")
            return []
            
        # 查找PT_DYNAMIC段
        dynamic_phdr = None
        for phdr in self.program_headers:
            if phdr.p_type == SegmentType.PT_DYNAMIC:
                dynamic_phdr = phdr
                break
        
        if not dynamic_phdr:
            logger.warning("No PT_DYNAMIC segment found")
            return []
        
        try:
            # 正确模拟C++的GetDynamicSection逻辑：
            # C++: *dynamic = reinterpret_cast<Elf_Dyn*>(load_bias_ + phdr->p_vaddr);
            # 从加载后的内存数据中读取，而不是从原始文件
            
            min_vaddr, max_vaddr, load_size = self.calculate_load_size()
            
            # 计算动态段在loaded_data中的偏移量
            # 对应C++的 load_bias_ + phdr->p_vaddr
            dyn_offset_in_memory = dynamic_phdr.p_vaddr - min_vaddr
            entry_size = ctypes.sizeof(self.types['Dyn'])
            
            if dyn_offset_in_memory < 0 or dyn_offset_in_memory >= len(self.loaded_data):
                logger.error(f"Dynamic section offset {dyn_offset_in_memory} out of loaded data range")
                return []
            
            dynamic_entries = []
            current_offset = dyn_offset_in_memory
            
            logger.debug(f"Reading dynamic section from loaded memory at offset 0x{current_offset:x}")
            
            # 模拟 C++: for (Elf_Dyn* d = si.dynamic; d->d_tag != DT_NULL; ++d)
            while True:
                # 检查是否超出loaded_data边界
                if current_offset + entry_size > len(self.loaded_data):
                    logger.warning("Reached end of loaded data while reading dynamic entries")
                    break
                    
                # 检查是否超出dynamic段边界  
                if current_offset >= dyn_offset_in_memory + dynamic_phdr.p_memsz:
                    logger.warning("Reached end of dynamic section without finding DT_NULL")
                    break
                    
                # 从loaded_data中读取当前dynamic条目
                dyn_data = self.loaded_data[current_offset:current_offset + entry_size]
                
                # 检查读取的数据是否为空
                if len(dyn_data) < entry_size:
                    logger.warning("Insufficient data for dynamic entry")
                    break
                    
                dyn = self.types['Dyn'].from_buffer_copy(dyn_data)
                
                # 检查是否遇到DT_NULL (对应C++的循环条件 d->d_tag != DT_NULL)
                if dyn.d_tag == DynamicTag.DT_NULL:
                    logger.debug("Found DT_NULL, stopping dynamic section parsing")
                    break
                    
                dynamic_entries.append(dyn)
                
                # 移动到下一个条目 (对应C++的 ++d)
                current_offset += entry_size
                
                # Debug输出一些关键条目
                if dyn.d_tag == DynamicTag.DT_STRSZ:
                    logger.debug(f"DT_STRSZ: {dyn.d_un.d_val}")
                elif dyn.d_tag == DynamicTag.DT_STRTAB:
                    logger.debug(f"DT_STRTAB: 0x{dyn.d_un.d_ptr:x}")
                elif dyn.d_tag == DynamicTag.DT_NEEDED:
                    logger.debug(f"DT_NEEDED: {dyn.d_un.d_val}")
            
            logger.info(f"Read {len(dynamic_entries)} dynamic entries from loaded memory (stopped at DT_NULL)")
            return dynamic_entries
            
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to read dynamic section: {e}")
            return []
    
    def load(self) -> bool:
        """
        主要加载函数，读取所有ELF组件
        
        采用与C++版本完全一致的加载流程：
        1. 打开文件和读取头部
        2. 读取程序头
        3. 预留地址空间 (新增)
        4. 加载段
        5. 查找程序头表 (新增)
        6. 应用程序头表 (新增)
        7. 读取段头 (移至最后)
        
        Returns:
            文件成功加载返回True，失败返回False
        """
        logger.info("Starting ELF loading process (C++ compatible flow)...")
        
        return (self.open() and
                self.read_elf_header() and
                self.read_program_headers() and
                self.reserve_address_space() and
                self.load_segments() and
                self.find_phdr() and
                self.apply_phdr_table() and
                self.read_section_headers())


# =============================================================================
# 混淆ELF读取器，用于内存转储
# =============================================================================

class ObfuscatedELFReader(ELFReader):
    """
    增强的ELF读取器，专门用于混淆/转储的SO文件
    
    该类扩展了基础ELF读取器，增加了专门处理从内存转储出来的
    SO文件的功能。
    """
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.dump_base_addr = 0
        self.base_so_path = None
        self.dynamic_section_data = None
        
    def set_dump_base_addr(self, addr: int):
        """设置SO文件从内存转储时的基地址"""
        self.dump_base_addr = addr
        logger.info(f"Set dump base address: 0x{addr:x}")
    
    def set_base_so_path(self, path: str):
        """设置原始（未转储）SO文件的路径"""
        self.base_so_path = path
        logger.info(f"Set base SO path: {path}")

    def load_segments(self) -> bool:
        """
        [重写] 为混淆/转储的SO文件定制的、带条件判断的段加载逻辑。
        由于自linker加固的so在计算vaddr时可能会出现segment边界溢出，所以在修复LOAD的时候增加Flag
        当检测到溢出时，执行新的转储，即加载到新的一块内存区域中用于临时保存，后续修复。
        
        该方法会检查 self.is_self_link 标志：
        - 如果为 False (常规dump文件), 则调用父类的原始加载方法，保证原有功能不变。
        - 如果为 True (特殊dump文件), 则启用新的加载逻辑，安全地处理文件与内存布局不一致的情况。
        """
        # 关键的判断：检查是否需要启用特殊加载逻辑
        if not hasattr(self, 'is_self_link') or not self.is_self_link:
            # 这是常规情况，直接调用父类的、您原来的正常逻辑
            logger.info("这是一个常规转储文件，使用标准段加载器。")
            return super().load_segments()

        # --- 以下是仅在 is_self_link == True 时才会执行的特殊逻辑 ---
        logger.info("检测到自链接器特征，使用专用段加载器。")
        
        # 1. 使用修复后的 program_headers 计算内存布局
        min_vaddr, max_vaddr, load_size = self.calculate_load_size()
        
        if load_size == 0:
            logger.error("根据修复后的程序头，未找到可加载的段")
            return False
            
        self.load_bias = -min_vaddr
        self.loaded_data = bytearray(load_size)
        
        logger.info(f"正在加载段到 {load_size} 字节的缓冲区 "
                   f"(虚拟地址范围: 0x{min_vaddr:x} - 0x{max_vaddr:x})")
        
        # 2. 遍历并加载数据
        repaired_load_segments = [p for p in self.program_headers if p.p_type == SegmentType.PT_LOAD]
        original_load_segments = [p for p in self.original_program_headers if p.p_type == SegmentType.PT_LOAD]

        if len(repaired_load_segments) != len(original_load_segments):
            logger.error("原始和修复后的可加载段数量不匹配。")
            return False

        for repaired_phdr, original_phdr in zip(repaired_load_segments, original_load_segments):
            
            # a) 计算在内存缓冲区中的写入位置 (使用修复后的头)
            seg_start_in_mem = repaired_phdr.p_vaddr - min_vaddr
            
            # b) 确定从原始文件中读取的位置和大小 (使用原始头)
            read_offset = original_phdr.p_offset
            read_size = original_phdr.p_filesz

            if read_size == 0:
                continue

            # c) 安全检查：确保读取不会越界原始文件
            if read_offset + read_size > self.file_size:
                logger.warning(f"段读取请求 (偏移=0x{read_offset:x}, 大小=0x{read_size:x}) "
                               f"超出原始文件大小 (0x{self.file_size:x})。将截断读取。")
                read_size = self.file_size - read_offset
                if read_size <= 0:
                    continue
            
            # d) 安全检查：确保写入不会越界内存缓冲区
            seg_end_in_mem = seg_start_in_mem + read_size
            if seg_end_in_mem > load_size:
                logger.error(f"段写入 (内存偏移=0x{seg_start_in_mem:x}, 大小=0x{read_size:x}) "
                             f"将超出已分配的内存缓冲区 (0x{load_size:x})。")
                return False

            # e) 执行数据复制
            segment_data = self.mmap_file[read_offset : read_offset + read_size]
            self.loaded_data[seg_start_in_mem : seg_end_in_mem] = segment_data

            logger.debug(f"已加载段: 文件[0x{read_offset:x}:0x{read_offset+read_size:x}] "
                       f"-> 内存[0x{seg_start_in_mem:x}:0x{seg_end_in_mem:x}]")

        logger.info("所有段已通过专用加载器成功加载到内存缓冲区")
        return True
    
    def fix_dump_program_headers(self):
        """修复内存转储特征的程序头 - 完全对应C++的FixDumpSoPhdr()"""
        if self.dump_base_addr == 0:
            logger.warning("No dump base address set, skipping program header fixes")
            return
            
        logger.info(f"Fixing program headers for memory dump (base_addr=0x{self.dump_base_addr:x})...")
        
        # 第一阶段：修复可加载段大小 - 对应C++的第一部分逻辑
        if self.dump_base_addr != 0:
            # 收集所有可加载段
            load_segments = []
            for phdr in self.program_headers:
                if phdr.p_type == SegmentType.PT_LOAD:
                    load_segments.append(phdr)
            
            # 按虚拟地址排序
            load_segments.sort(key=lambda p: p.p_vaddr)
            
            logger.debug("修复前的可加载段:")
            for i, phdr in enumerate(load_segments):
                logger.debug(f"  段{i}: vaddr=0x{phdr.p_vaddr:x}, offset=0x{phdr.p_offset:x}, "
                            f"filesz=0x{phdr.p_filesz:x}, memsz=0x{phdr.p_memsz:x}")
            
            # 修复每个可加载段的大小
            if load_segments:
                for i in range(len(load_segments)):
                    phdr = load_segments[i]
                    
                    if i < len(load_segments) - 1:
                        # 设置段大小到下一个段的开始
                        next_phdr = load_segments[i + 1]
                        phdr.p_memsz = next_phdr.p_vaddr - phdr.p_vaddr
                        # 在内存转储中，文件大小等于内存大小
                        phdr.p_filesz = phdr.p_memsz
                    else:
                        # 最后一个段的处理 - 关键修复点
                        calculated_size = self.file_size - phdr.p_vaddr
                        
                        if calculated_size <= 0:
                            # 对于自链接器文件，保持原有大小或使用合理的默认值
                            logger.warning(f"检测到自链接器文件特征: file_size(0x{self.file_size:x}) <= vaddr(0x{phdr.p_vaddr:x})")
                            self.is_self_link = True
                            phdr.p_memsz = phdr.p_memsz
                            logger.info(f"保持最后段原有大小: memsz=0x{phdr.p_memsz:x}")
                        else:
                            phdr.p_memsz = calculated_size
                            phdr.p_filesz = phdr.p_memsz
                    
                    logger.debug(f"修复段{i}大小: memsz=0x{phdr.p_memsz:x}, filesz=0x{phdr.p_filesz:x}")
        
        # 第二阶段：统一设置所有程序头的偏移量 - 对应C++的第二部分逻辑
        logger.debug("设置所有程序头的偏移量:")
        for i, phdr in enumerate(self.program_headers):
            orig_offset = phdr.p_offset
            orig_paddr = phdr.p_paddr
            
            # 关键修复：在内存dump文件中，偏移量等于虚拟地址
            phdr.p_paddr = phdr.p_vaddr
            phdr.p_offset = phdr.p_vaddr
            
            logger.debug(f"程序头{i}: type=0x{phdr.p_type:x}, "
                        f"offset: 0x{orig_offset:x} -> 0x{phdr.p_offset:x}, "
                        f"paddr: 0x{orig_paddr:x} -> 0x{phdr.p_paddr:x}")
        
        logger.info("程序头修复完成")
    
    def load_dynamic_from_base_so(self) -> bool:
        """从原始SO文件加载动态段"""
        if not self.base_so_path:
            return False
            
        try:
            with ELFReader(self.base_so_path) as base_reader:
                if not base_reader.load():
                    return False
                    
                # 在基础SO中查找动态段
                for phdr in base_reader.program_headers:
                    if phdr.p_type == SegmentType.PT_DYNAMIC:
                        # 提取动态段数据
                        dyn_start = phdr.p_offset
                        dyn_size = phdr.p_filesz
                        
                        if dyn_start + dyn_size <= base_reader.file_size:
                            self.dynamic_section_data = base_reader.mmap_file[dyn_start:dyn_start + dyn_size]
                            logger.info(f"Loaded dynamic section from base SO: {len(self.dynamic_section_data)} bytes")
                            return True
                            
            return False
            
        except Exception as e:
            logger.error(f"Failed to load dynamic section from base SO: {e}")
            return False
    
    def load(self) -> bool:
        """增强的混淆/转储SO文件加载过程
        
        采用与C++版本一致的流程，并添加混淆SO文件特有的处理：
        1. 基础ELF头部和程序头读取
        2. 修复dump特征的程序头 (混淆SO特有)
        3. 从基础SO加载动态段 (可选，混淆SO特有)
        4. 预留地址空间
        5. 加载段
        6. 查找程序头表
        7. 应用程序头表
        8. 读取段头
        """
        logger.info("Starting obfuscated ELF loading process (C++ compatible flow)...")
        
        # 执行基本ELF加载（对应C++的前3步）
        if not (self.open() and
                self.read_elf_header() and
                self.read_program_headers()):
            return False
        
        # 修复内存转储特征的程序头 (对应C++的FixDumpSoPhdr)
        self.fix_dump_program_headers()
        
        # 如果需要，尝试从基础SO加载动态段 (对应C++的LoadDynamicSectionFromBaseSource)
        if self.base_so_path:
            logger.info("Attempting to load dynamic section from base SO...")
            self.load_dynamic_from_base_so()
        
        # 执行完整的C++兼容加载流程
        return (self.reserve_address_space() and
                self.load_segments() and
                self.find_phdr() and
                self.apply_phdr_table() and
                self.read_section_headers())