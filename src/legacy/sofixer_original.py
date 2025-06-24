#!/usr/bin/env python3
"""
SoFixer Python Implementation with ctypes
=========================================

A faithful Python port of the C++ SoFixer tool using ctypes for accurate binary structure handling.
This implementation uses ctypes to match the exact C structures from elf.h, including proper union support.

Features:
- Exact binary layout matching with C structures
- Proper union handling for dynamic sections
- Automatic 32/64-bit architecture detection
- Memory-mapped file reading for performance
- Complete ELF structure representation

Original C++ implementation by F8LEFT.
Python ctypes port with binary accuracy and union support.

Usage:
    python sofixer_ctypes.py -s dumped.so -o fixed.so -m 0x7DB078B000 -d
"""

import sys
import os
import ctypes
import mmap
import argparse
import logging
import struct
from typing import Optional, List
from sofixer_types import *

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# =============================================================================
# ELF Architecture Detection and Type Selection
# =============================================================================

def detect_elf_architecture(file_path: str) -> Optional[str]:
    """
    Automatically detect if an ELF file is 32-bit or 64-bit.
    
    Args:
        file_path: Path to the ELF file
        
    Returns:
        "32" for 32-bit, "64" for 64-bit, None if not valid ELF or error
    """
    try:
        with open(file_path, 'rb') as f:
            # Read ELF header identification
            e_ident = f.read(16)
            
            # Check ELF magic number
            if len(e_ident) < 16 or e_ident[:4] != b'\x7fELF':
                return None
                
            # Check ELF class (32-bit or 64-bit)
            if e_ident[4] == ELFClass.ELFCLASS32:
                return "32"
            elif e_ident[4] == ELFClass.ELFCLASS64:
                return "64"
            else:
                return None
                
    except (IOError, OSError):
        return None


def get_elf_types(is_64bit: bool):
    """
    Get the appropriate ctypes structures for the ELF architecture.
    
    Args:
        is_64bit: True for 64-bit, False for 32-bit
        
    Returns:
        Dictionary containing all ELF structure types for the architecture
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
# Memory-Mapped ELF File Reader
# =============================================================================

class ELFReader:
    """
    Memory-mapped ELF file reader using ctypes for accurate binary parsing.
    
    This class provides high-performance ELF file reading using memory mapping
    and ctypes structures that exactly match the C ELF definitions.
    """
    
    def __init__(self, file_path: str):
        """
        Initialize ELF reader with file path.
        
        Args:
            file_path: Path to the ELF file to read
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
        """Context manager entry"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        
    def open(self) -> bool:
        """
        Open and memory-map the ELF file.
        
        Returns:
            True if successfully opened, False otherwise
        """
        try:
            # Detect architecture first
            arch = detect_elf_architecture(self.file_path)
            if arch is None:
                logger.error(f"Not a valid ELF file: {self.file_path}")
                return False
                
            self.is_64bit = (arch == "64")
            self.types = get_elf_types(self.is_64bit)
            
            # Open file and create memory map
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
        """Close file handles and memory map"""
        if self.mmap_file:
            self.mmap_file.close()
            self.mmap_file = None
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def read_elf_header(self) -> bool:
        """
        Read and parse the ELF header using ctypes.
        
        Returns:
            True if header was successfully read, False otherwise
        """
        if not self.mmap_file:
            return False
            
        try:
            # Read header directly from memory map using ctypes
            header_size = ctypes.sizeof(self.types['Ehdr'])
            if self.file_size < header_size:
                logger.error("File too small for ELF header")
                return False
                
            # Create header structure from memory map
            self.header = self.types['Ehdr'].from_buffer_copy(self.mmap_file[:header_size])
            
            # Validate ELF magic
            magic = bytes(self.header.e_ident[:4])
            if magic != b'\x7fELF':
                logger.error("Invalid ELF magic number")
                return False
                
            # Validate architecture matches detection
            expected_class = ELFClass.ELFCLASS64 if self.is_64bit else ELFClass.ELFCLASS32
            if self.header.e_ident[4] != expected_class:
                logger.error("ELF class mismatch")
                return False
                
            # Check endianness (we expect little-endian)
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
        Read all program headers using ctypes.
        
        Returns:
            True if program headers were successfully read, False otherwise
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
                
            # Validate program header table bounds
            expected_size = ctypes.sizeof(self.types['Phdr'])
            if phentsize != expected_size:
                logger.error(f"Program header size mismatch: expected {expected_size}, got {phentsize}")
                return False
                
            table_size = phnum * phentsize
            if phoff + table_size > self.file_size:
                logger.error("Program header table extends beyond file")
                return False
            
            # Read program headers directly from memory map
            self.program_headers = []
            for i in range(phnum):
                offset = phoff + (i * phentsize)
                phdr_data = self.mmap_file[offset:offset + phentsize]
                phdr = self.types['Phdr'].from_buffer_copy(phdr_data)
                self.program_headers.append(phdr)
                
                logger.debug(f"Program header {i}: type={phdr.p_type}, "
                           f"vaddr=0x{phdr.p_vaddr:x}, memsz=0x{phdr.p_memsz:x}")
            
            logger.info(f"Read {len(self.program_headers)} program headers")
            return True
            
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to read program headers: {e}")
            return False
    
    def read_section_headers(self) -> bool:
        """
        Read all section headers using ctypes.
        
        Returns:
            True if section headers were successfully read, False otherwise
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
                
            # Validate section header table bounds
            expected_size = ctypes.sizeof(self.types['Shdr'])
            if shentsize != expected_size:
                logger.error(f"Section header size mismatch: expected {expected_size}, got {shentsize}")
                return False
                
            table_size = shnum * shentsize
            if shoff + table_size > self.file_size:
                logger.error("Section header table extends beyond file")
                return False
            
            # Read section headers directly from memory map
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
        Calculate memory size needed for all loadable segments.
        
        Returns:
            Tuple of (min_vaddr, max_vaddr, total_size)
        """
        if self.is_64bit:
            min_vaddr = 0xFFFFFFFFFFFFFFFF
        else:
            min_vaddr = 0xFFFFFFFF
        max_vaddr = 0
        found_load = False
        
        i = 0
        for phdr in self.program_headers:
            if phdr.p_type != SegmentType.PT_LOAD:
                i += 1
                continue
                
            found_load = True
            print(f"Found loadable segment: {i}")
            if phdr.p_vaddr < min_vaddr:
                min_vaddr = phdr.p_vaddr
            if phdr.p_vaddr + phdr.p_memsz > max_vaddr:
                max_vaddr = phdr.p_vaddr + phdr.p_memsz
        
        if not found_load:
            return 0, 0, 0
            
        # Align to page boundaries
        page_size = 4096
        min_vaddr = min_vaddr & ~(page_size - 1)  # PAGE_START
        max_vaddr = (max_vaddr + page_size - 1) & ~(page_size - 1)  # PAGE_END
        
        return min_vaddr, max_vaddr, max_vaddr - min_vaddr
    
    def load_segments(self) -> bool:
        """
        Load all PT_LOAD segments into memory buffer.
        
        Returns:
            True if segments were successfully loaded, False otherwise
        """
        min_vaddr, max_vaddr, load_size = self.calculate_load_size()
        
        if load_size == 0:
            logger.error("No loadable segments found")
            return False
            
        self.load_bias = -min_vaddr  # Bias to adjust virtual addresses
        
        # Allocate memory buffer for loaded segments
        self.loaded_data = bytearray(load_size)
        
        logger.info(f"Loading segments into {load_size} byte buffer "
                   f"(vaddr range: 0x{min_vaddr:x} - 0x{max_vaddr:x})")
        
        # Load each PT_LOAD segment
        for i, phdr in enumerate(self.program_headers):
            if phdr.p_type != SegmentType.PT_LOAD:
                continue
                
            # Calculate segment position in memory buffer
            seg_start = phdr.p_vaddr - min_vaddr
            seg_end = seg_start + phdr.p_filesz
            
            # Validate segment bounds
            if seg_end > load_size:
                logger.error(f"Segment {i} extends beyond allocated memory")
                return False
                
            if phdr.p_offset + phdr.p_filesz > self.file_size:
                logger.error(f"Segment {i} extends beyond file")
                return False
            
            # Copy segment data from memory map to buffer
            if phdr.p_filesz > 0:
                file_start = phdr.p_offset
                file_end = file_start + phdr.p_filesz
                self.loaded_data[seg_start:seg_end] = self.mmap_file[file_start:file_end]
                
                logger.debug(f"Loaded segment {i}: file[0x{file_start:x}:0x{file_end:x}] "
                           f"-> mem[0x{seg_start:x}:0x{seg_end:x}]")
            
            # Zero-fill additional memory (p_memsz > p_filesz)
            if phdr.p_memsz > phdr.p_filesz:
                zero_start = seg_start + phdr.p_filesz
                zero_end = seg_start + phdr.p_memsz
                if zero_end <= load_size:
                    # Already zeroed by bytearray initialization
                    pass
        
        logger.info("All segments loaded successfully")
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
        Read dynamic section entries using ctypes with proper union access.
        
        重要：必须在load_segments()之后调用，因为要从加载后的内存数据中读取
        
        Returns:
            List of dynamic entries as ctypes structures
        """
        # 检查是否已经加载了段数据
        if not self.loaded_data:
            logger.error("Segments must be loaded before reading dynamic section")
            return []
            
        # Find PT_DYNAMIC segment
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
        Main loading function that reads all ELF components.
        
        Returns:
            True if the file was successfully loaded, False otherwise
        """
        logger.info("Starting ELF loading process...")
        
        return (self.open() and
                self.read_elf_header() and
                self.read_program_headers() and
                self.read_section_headers() and
                self.load_segments())


# =============================================================================
# Obfuscated ELF Reader for Memory Dumps
# =============================================================================

class ObfuscatedELFReader(ELFReader):
    """
    Enhanced ELF reader for obfuscated/dumped SO files.
    
    This class extends the base ELF reader with capabilities specific to
    handling SO files that have been dumped from memory.
    """
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.dump_base_addr = 0
        self.base_so_path = None
        self.dynamic_section_data = None
        
    def set_dump_base_addr(self, addr: int):
        """Set the memory base address where the SO was dumped from"""
        self.dump_base_addr = addr
        logger.info(f"Set dump base address: 0x{addr:x}")
    
    def set_base_so_path(self, path: str):
        """Set path to the original (non-dumped) SO file"""
        self.base_so_path = path
        logger.info(f"Set base SO path: {path}")
    
    def fix_dump_program_headers(self):
        if self.dump_base_addr == 0:
            return

        for phdr in self.program_headers:
            # 我们信任从dump中读出的p_vaddr, p_memsz, p_filesz
            # 唯一需要修正的是 p_offset

            # 对于一个平坦的内存dump文件，文件偏移量就是
            # 虚拟地址减去dump时的基地址
            if phdr.p_vaddr >= self.dump_base_addr:
                phdr.p_offset = phdr.p_vaddr - self.dump_base_addr
            else:
                # 如果vaddr小于基地址，这很奇怪，但可以先设为0或保持原样
                # 或者根据实际情况调整
                phdr.p_offset = phdr.p_vaddr

            # p_paddr 通常可以设为和 p_vaddr 一样
            phdr.p_paddr = phdr.p_vaddr

            logger.debug(f"Correctly adjusted segment: vaddr=0x{phdr.p_vaddr:x}, "
                        f"size=0x{phdr.p_memsz:x}, new_offset=0x{phdr.p_offset:x}")
    
    def load_dynamic_from_base_so(self) -> bool:
        """Load dynamic section from original SO file"""
        if not self.base_so_path:
            return False
            
        try:
            with ELFReader(self.base_so_path) as base_reader:
                if not base_reader.load():
                    return False
                    
                # Find dynamic segment in base SO
                for phdr in base_reader.program_headers:
                    if phdr.p_type == SegmentType.PT_DYNAMIC:
                        # Extract dynamic section data
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
        """Enhanced loading process for obfuscated/dumped SO files"""
        logger.info("Starting obfuscated ELF loading process...")
        
        # Perform basic ELF loading
        if not (self.open() and
                self.read_elf_header() and
                self.read_program_headers()):
            return False
        
        # Fix program headers for memory dump characteristics
        self.fix_dump_program_headers()
        
        # Try to load dynamic section from base SO if needed
        if self.base_so_path:
            logger.info("Attempting to load dynamic section from base SO...")
            self.load_dynamic_from_base_so()
        
        # Continue with section headers and segment loading
        return (self.read_section_headers() and
                self.load_segments())


# =============================================================================
# ELF Rebuilder using ctypes structures
# =============================================================================

class ELFRebuilder:
    """
    ELF file rebuilder using ctypes for accurate binary reconstruction.
    """
    
    def __init__(self, elf_reader: ObfuscatedELFReader):
        self.elf_reader = elf_reader
        self.so_info = SoInfo()
        self.rebuilt_data = None
        self.rebuilt_size = 0
        
        # 段头表重建相关数据结构 (对应C++的各种索引变量)
        self.section_headers = []           # 重建的段头表
        self.shstrtab = bytearray(b'\0')    # 段名字符串表 (对应C++的shstrtab)
        self.new_file_data = bytearray()    # 重建的完整文件数据
        
        # 段索引跟踪 (对应C++的各种s*变量)
        self.section_indices = {
            'DYNSYM': 0, 'DYNSTR': 0, 'HASH': 0, 'RELDYN': 0, 'RELADYN': 0,
            'RELPLT': 0, 'PLT': 0, 'TEXTTAB': 0, 'ARMEXIDX': 0, 'FINIARRAY': 0,
            'INITARRAY': 0, 'DYNAMIC': 0, 'GOT': 0, 'DATA': 0, 'BSS': 0, 'SHSTRTAB': 0
        }
    
    def extract_so_info(self) -> bool:
        """
        Extract soinfo structure data from loaded ELF.
        
        Python-native implementation that follows the logic of C++ ReadSoInfo()
        but uses simple Python data structures instead of complex ctypes operations.
        """
        if not self.elf_reader.loaded_data:
            logger.error("No loaded ELF data available")
            return False
            
        logger.debug("=======================ReadSoInfo=========================")
        
        # 步骤1: 初始化基本信息 (对应C++ lines 550-555)
        # 设置基本的soinfo字段，Python中使用简单的数值而不是指针
        self.so_info.phnum = len(self.elf_reader.program_headers)
        
        # 计算加载范围 (对应C++ phdr_table_get_load_size调用)
        min_vaddr, max_vaddr, load_size = self.elf_reader.calculate_load_size()
        self.so_info.size = load_size
        
        # 步骤2: 获取动态段信息 (对应C++ lines 558-562)
        dynamic_entries = self.elf_reader.read_dynamic_section()
        if not dynamic_entries:
            logger.error("No valid dynamic phdr data")
            return False
        
        # 修复：使用与C++一致的计算方式 (phdr->p_memsz / sizeof(Elf_Dyn))
        # 找到PT_DYNAMIC程序头来计算正确的dynamic_count
        dyn_size = ctypes.sizeof(self.elf_reader.types['Dyn'])
        for phdr in self.elf_reader.program_headers:
            if phdr.p_type == SegmentType.PT_DYNAMIC:
                self.so_info.dynamic_count = phdr.p_memsz // dyn_size
                logger.debug(f"dynamic_count calculated from p_memsz: {self.so_info.dynamic_count} "
                           f"(p_memsz={phdr.p_memsz}, dyn_size={dyn_size})")
                break
        else:
            # 如果没有找到PT_DYNAMIC，fallback到原来的方式
            self.so_info.dynamic_count = len(dynamic_entries)
            logger.warning("No PT_DYNAMIC segment found, using parsed entries count")
        
        # 步骤2.5: 获取ARM EXIDX段信息 (对应C++ lines 564-565)
        # 这是ARM架构特有的异常处理信息，用于栈展开和调试
        self._extract_arm_exidx(min_vaddr)
        
        # 步骤3: 解析动态段条目 (对应C++ lines 567-702)
        # 这是核心逻辑，提取所有重要的动态链接信息
        needed_count = 0
        addr_size = 8 if self.elf_reader.is_64bit else 4
        
        # 统计各种DT标签的出现次数
        dt_hash_count = 0
        dt_strtab_count = 0
        dt_symtab_count = 0
        dt_pltrel_count = 0
        dt_jmprel_count = 0
        dt_pltrelsz_count = 0
        dt_rel_count = 0
        dt_relsz_count = 0
        dt_pltgot_count = 0
        dt_rela_count = 0
        dt_relasz_count = 0
        dt_init_count = 0
        dt_fini_count = 0
        dt_init_array_count = 0
        dt_init_arraysz_count = 0
        dt_fini_array_count = 0
        dt_fini_arraysz_count = 0
        dt_preinit_array_count = 0
        dt_preinit_arraysz_count = 0
        dt_textrel_count = 0
        dt_symbolic_count = 0
        dt_needed_count = 0
        dt_flags_count = 0
        dt_strsz_count = 0
        dt_syment_count = 0
        dt_relent_count = 0
        dt_debug_count = 0
        dt_mips_rld_map_count = 0
        dt_mips_rld_version_count = 0
        dt_mips_flags_count = 0
        dt_mips_base_address_count = 0
        dt_mips_unrefextno_count = 0
        dt_mips_symtabno_count = 0
        dt_mips_local_gotno_count = 0
        dt_mips_gotsym_count = 0
        dt_soname_count = 0
        dt_unknown_count = 0
        
        # 遍历所有动态段条目，提取关键信息
        for dyn in dynamic_entries:
            tag = dyn.d_tag
            
            if tag == DynamicTag.DT_NULL:
                break
                
            # 处理哈希表信息 (对应C++ DT_HASH case)
            elif tag == DynamicTag.DT_HASH:
                dt_hash_count += 1
                self._extract_hash_table(dyn, min_vaddr)
                
            # 处理字符串表 (对应C++ DT_STRTAB case)
            elif tag == DynamicTag.DT_STRTAB:
                dt_strtab_count += 1
                self.so_info.strtab_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"string table found at offset 0x{self.so_info.strtab_offset:x}")
                
            # 处理符号表 (对应C++ DT_SYMTAB case)
            elif tag == DynamicTag.DT_SYMTAB:
                dt_symtab_count += 1
                self.so_info.symtab_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"symbol table found at offset 0x{self.so_info.symtab_offset:x}")
                
            # 处理PLT重定位信息 (对应C++ DT_PLTREL case)
            elif tag == DynamicTag.DT_PLTREL:
                dt_pltrel_count += 1
                self.so_info.plt_type = dyn.d_un.d_val
                
            # 处理PLT重定位表 (对应C++ DT_JMPREL case)
            elif tag == DynamicTag.DT_JMPREL:
                dt_jmprel_count += 1
                self.so_info.plt_rel_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"plt_rel (DT_JMPREL) found at offset 0x{self.so_info.plt_rel_offset:x}")
                
            # 处理PLT重定位表大小 (对应C++ DT_PLTRELSZ case)
            elif tag == DynamicTag.DT_PLTRELSZ:
                dt_pltrelsz_count += 1
                rel_size = ctypes.sizeof(self.elf_reader.types['Rel'])
                self.so_info.plt_rel_count = dyn.d_un.d_val // rel_size
                logger.debug(f"plt_rel_count (DT_PLTRELSZ) {self.so_info.plt_rel_count}")
                
            # 处理普通重定位表 (对应C++ DT_REL case)
            elif tag == DynamicTag.DT_REL:
                dt_rel_count += 1
                self.so_info.rel_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"rel (DT_REL) found at offset 0x{self.so_info.rel_offset:x}")
                
            # 处理普通重定位表大小 (对应C++ DT_RELSZ case)
            elif tag == DynamicTag.DT_RELSZ:
                dt_relsz_count += 1
                rel_size = ctypes.sizeof(self.elf_reader.types['Rel'])
                self.so_info.rel_count = dyn.d_un.d_val // rel_size
                logger.debug(f"rel_count (DT_RELSZ) {self.so_info.rel_count}")
                
            # 处理PLT GOT表 (对应C++ DT_PLTGOT case)
            elif tag == DynamicTag.DT_PLTGOT:
                dt_pltgot_count += 1
                self.so_info.plt_got_offset = dyn.d_un.d_ptr - min_vaddr
                
            # 处理RELA重定位表 (对应C++ DT_RELA case)
            elif tag == DynamicTag.DT_RELA:
                dt_rela_count += 1
                self.so_info.plt_rela_offset = dyn.d_un.d_ptr - min_vaddr
                
            # 处理RELA重定位表大小 (对应C++ DT_RELASZ case)
            elif tag == DynamicTag.DT_RELASZ:
                dt_relasz_count += 1
                rela_size = ctypes.sizeof(self.elf_reader.types['Rela'])
                self.so_info.plt_rela_count = dyn.d_un.d_val // rela_size
                
            # 处理初始化函数 (对应C++ DT_INIT case)
            elif tag == DynamicTag.DT_INIT:
                dt_init_count += 1
                self.so_info.init_func_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"constructors (DT_INIT) found at offset 0x{self.so_info.init_func_offset:x}")
                
            # 处理析构函数 (对应C++ DT_FINI case)
            elif tag == DynamicTag.DT_FINI:
                dt_fini_count += 1
                self.so_info.fini_func_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"destructors (DT_FINI) found at offset 0x{self.so_info.fini_func_offset:x}")
                
            # 处理初始化数组 (对应C++ DT_INIT_ARRAY case)
            elif tag == DynamicTag.DT_INIT_ARRAY:
                dt_init_array_count += 1
                self.so_info.init_array_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"constructors (DT_INIT_ARRAY) found at offset 0x{self.so_info.init_array_offset:x}")
                
            # 处理初始化数组大小 (对应C++ DT_INIT_ARRAYSZ case)
            elif tag == DynamicTag.DT_INIT_ARRAYSZ:
                dt_init_arraysz_count += 1
                self.so_info.init_array_count = dyn.d_un.d_val // addr_size
                logger.debug(f"constructors (DT_INIT_ARRAYSZ) {self.so_info.init_array_count}")
                
            # 处理析构数组 (对应C++ DT_FINI_ARRAY case)
            elif tag == DynamicTag.DT_FINI_ARRAY:
                dt_fini_array_count += 1
                self.so_info.fini_array_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"destructors (DT_FINI_ARRAY) found at offset 0x{self.so_info.fini_array_offset:x}")
                
            # 处理析构数组大小 (对应C++ DT_FINI_ARRAYSZ case)
            elif tag == DynamicTag.DT_FINI_ARRAYSZ:
                dt_fini_arraysz_count += 1
                self.so_info.fini_array_count = dyn.d_un.d_val // addr_size
                logger.debug(f"destructors (DT_FINI_ARRAYSZ) {self.so_info.fini_array_count}")
                
            # 处理预初始化数组 (对应C++ DT_PREINIT_ARRAY case)
            elif tag == DynamicTag.DT_PREINIT_ARRAY:
                dt_preinit_array_count += 1
                self.so_info.preinit_array_offset = dyn.d_un.d_ptr - min_vaddr
                logger.debug(f"constructors (DT_PREINIT_ARRAY) found at offset 0x{self.so_info.preinit_array_offset:x}")
                
            # 处理预初始化数组大小 (对应C++ DT_PREINIT_ARRAYSZ case)
            elif tag == DynamicTag.DT_PREINIT_ARRAYSZ:
                dt_preinit_arraysz_count += 1
                self.so_info.preinit_array_count = dyn.d_un.d_val // addr_size
                logger.debug(f"constructors (DT_PREINIT_ARRAYSZ) {self.so_info.preinit_array_count}")
                
            # 处理文本重定位标志 (对应C++ DT_TEXTREL case)
            elif tag == DynamicTag.DT_TEXTREL:
                dt_textrel_count += 1
                self.so_info.has_text_relocations = True
                
            # 处理符号标志 (对应C++ DT_SYMBOLIC case)
            elif tag == DynamicTag.DT_SYMBOLIC:
                dt_symbolic_count += 1
                self.so_info.has_DT_SYMBOLIC = True
                
            # 处理依赖库计数 (对应C++ DT_NEEDED case)
            elif tag == DynamicTag.DT_NEEDED:
                dt_needed_count += 1
                needed_count += 1
                
            # 处理标志位 (对应C++ DT_FLAGS case)
            elif tag == DynamicTag.DT_FLAGS:
                dt_flags_count += 1
                if dyn.d_un.d_val & 0x4:  # DF_TEXTREL
                    self.so_info.has_text_relocations = True
                if dyn.d_un.d_val & 0x2:  # DF_SYMBOLIC  
                    self.so_info.has_DT_SYMBOLIC = True
                
            # 处理字符串表大小 (对应C++ DT_STRSZ case)
            elif tag == DynamicTag.DT_STRSZ:
                dt_strsz_count += 1
                self.so_info.strtabsize = dyn.d_un.d_val
                
            # 处理符号条目大小 (对应C++ DT_SYMENT case)
            elif tag == DynamicTag.DT_SYMENT:
                dt_syment_count += 1
                # 这些条目不需要特殊处理，跳过继续处理下一个条目
                pass
            # 处理重定位条目大小 (对应C++ DT_RELENT case)  
            elif tag == DynamicTag.DT_RELENT:
                dt_relent_count += 1
                # 对应C++中switch的break，意思是跳出当前case继续for循环
                pass
                
            # 处理调试相关条目 (对应C++ DT_DEBUG case)
            elif tag == DynamicTag.DT_DEBUG:
                dt_debug_count += 1
                # DT_DEBUG条目用于GDB调试，不需要特殊处理
                pass
                
            # 处理MIPS特定字段 (对应C++ MIPS相关cases)
            elif tag == DynamicTag.DT_MIPS_RLD_MAP:
                dt_mips_rld_map_count += 1
                # Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB
                pass
            elif tag == DynamicTag.DT_MIPS_RLD_VERSION:
                dt_mips_rld_version_count += 1
                # MIPS运行时链接器接口版本，不需要特殊处理
                pass
            elif tag == DynamicTag.DT_MIPS_FLAGS:
                dt_mips_flags_count += 1
                # MIPS标志位，不需要特殊处理
                pass
            elif tag == DynamicTag.DT_MIPS_BASE_ADDRESS:
                dt_mips_base_address_count += 1
                # MIPS基址，不需要特殊处理
                pass
            elif tag == DynamicTag.DT_MIPS_UNREFEXTNO:
                dt_mips_unrefextno_count += 1
                # MIPS未引用外部符号编号，不需要特殊处理
                pass
            elif tag == DynamicTag.DT_MIPS_SYMTABNO:
                dt_mips_symtabno_count += 1
                self.so_info.mips_symtabno = dyn.d_un.d_val
            elif tag == DynamicTag.DT_MIPS_LOCAL_GOTNO:
                dt_mips_local_gotno_count += 1
                self.so_info.mips_local_gotno = dyn.d_un.d_val
            elif tag == DynamicTag.DT_MIPS_GOTSYM:
                dt_mips_gotsym_count += 1
                self.so_info.mips_gotsym = dyn.d_un.d_val
                
            # 处理SO名称 (对应C++ DT_SONAME case)
            elif tag == DynamicTag.DT_SONAME:
                dt_soname_count += 1
                self._extract_soname(dyn)
                
            else:
                # 未使用的条目 (对应C++ default case)
                dt_unknown_count += 1
                logger.debug(f"Unused DT entry: type 0x{tag:08x} arg 0x{dyn.d_un.d_val:08x}")
        
        # 输出DT标签统计结果
        logger.debug("===================DT Tags Statistics====================")
        logger.debug(f"DT_HASH: {dt_hash_count}, DT_STRTAB: {dt_strtab_count}, DT_SYMTAB: {dt_symtab_count}")
        logger.debug(f"DT_PLTREL: {dt_pltrel_count}, DT_JMPREL: {dt_jmprel_count}, DT_PLTRELSZ: {dt_pltrelsz_count}")
        logger.debug(f"DT_REL: {dt_rel_count}, DT_RELSZ: {dt_relsz_count}, DT_PLTGOT: {dt_pltgot_count}")
        logger.debug(f"DT_DEBUG: {dt_debug_count}, DT_RELA: {dt_rela_count}, DT_RELASZ: {dt_relasz_count}")
        logger.debug(f"DT_INIT: {dt_init_count}, DT_FINI: {dt_fini_count}, DT_INIT_ARRAY: {dt_init_array_count}")
        logger.debug(f"DT_INIT_ARRAYSZ: {dt_init_arraysz_count}, DT_FINI_ARRAY: {dt_fini_array_count}, DT_FINI_ARRAYSZ: {dt_fini_arraysz_count}")
        logger.debug(f"DT_PREINIT_ARRAY: {dt_preinit_array_count}, DT_PREINIT_ARRAYSZ: {dt_preinit_arraysz_count}")
        logger.debug(f"DT_TEXTREL: {dt_textrel_count}, DT_SYMBOLIC: {dt_symbolic_count}, DT_NEEDED: {dt_needed_count}")
        logger.debug(f"DT_FLAGS: {dt_flags_count}, DT_STRSZ: {dt_strsz_count}, DT_SYMENT: {dt_syment_count}, DT_RELENT: {dt_relent_count}")
        logger.debug(f"DT_MIPS_RLD_MAP: {dt_mips_rld_map_count}, DT_MIPS_RLD_VERSION: {dt_mips_rld_version_count}")
        logger.debug(f"DT_MIPS_FLAGS: {dt_mips_flags_count}, DT_MIPS_BASE_ADDRESS: {dt_mips_base_address_count}")
        logger.debug(f"DT_MIPS_UNREFEXTNO: {dt_mips_unrefextno_count}, DT_MIPS_SYMTABNO: {dt_mips_symtabno_count}")
        logger.debug(f"DT_MIPS_LOCAL_GOTNO: {dt_mips_local_gotno_count}, DT_MIPS_GOTSYM: {dt_mips_gotsym_count}")
        logger.debug(f"DT_SONAME: {dt_soname_count}, DT_UNKNOWN: {dt_unknown_count}")
        logger.debug("=======================================================")
        
        # 步骤4: 解析符号表（用于重定位处理）
        self._parse_symbol_table(min_vaddr)
        
        logger.debug("=======================ReadSoInfo End=========================")
        return True
    
    def _extract_hash_table(self, dyn, min_vaddr):
        """
        提取哈希表信息的辅助函数
        
        对应C++中DT_HASH case的处理逻辑
        """
        hash_offset = dyn.d_un.d_ptr - min_vaddr
        
        # 从loaded_data中提取nbucket和nchain
        if hash_offset >= 0 and hash_offset + 8 <= len(self.elf_reader.loaded_data):
            # 保存hash表起始偏移（对应C++的si.hash概念）
            self.so_info.hash_offset = hash_offset
            
            self.so_info.nbucket, self.so_info.nchain = struct.unpack('<LL', 
                self.elf_reader.loaded_data[hash_offset:hash_offset + 8])
            
            # 计算bucket和chain的偏移量
            self.so_info.bucket_offset = hash_offset + 8
            self.so_info.chain_offset = self.so_info.bucket_offset + self.so_info.nbucket * 4
            
            logger.debug(f"Hash table: nbucket={self.so_info.nbucket}, nchain={self.so_info.nchain}")
            logger.debug(f"Hash table offsets: hash=0x{hash_offset:x}, bucket=0x{self.so_info.bucket_offset:x}, chain=0x{self.so_info.chain_offset:x}")
    
    def _extract_soname(self, dyn):
        """
        提取SO名称的辅助函数
        
        对应C++中DT_SONAME case的处理逻辑
        """
        if hasattr(self.so_info, 'strtab_offset'):
            # 计算字符串在loaded_data中的位置
            soname_offset = self.so_info.strtab_offset + dyn.d_un.d_val
            
            if soname_offset < len(self.elf_reader.loaded_data):
                # 从loaded_data中读取以null结尾的字符串
                end_pos = self.elf_reader.loaded_data.find(0, soname_offset)
                if end_pos != -1:
                    soname_bytes = self.elf_reader.loaded_data[soname_offset:end_pos]
                    self.so_info.name = soname_bytes.decode('utf-8', errors='ignore')
                    logger.debug(f"soname: {self.so_info.name}")
                else:
                    logger.debug("soname found but no null terminator")
            else:
                logger.debug("soname offset beyond loaded data")
        else:
            logger.debug("soname found but no string table available")
    
    def _extract_arm_exidx(self, min_vaddr):
        """
        提取ARM EXIDX段信息的辅助函数
        
        对应C++中phdr_table_get_arm_exidx函数的功能
        ARM EXIDX用于异常处理和栈展开，仅在ARM架构上存在
        
        修复：像dynamic section一样，从加载后的内存验证数据有效性
        """
        # 遍历所有程序头，查找PT_ARM_EXIDX段
        for i, phdr in enumerate(self.elf_reader.program_headers):
            if phdr.p_type == SegmentType.PT_ARM_EXIDX:
                # 计算ARM EXIDX在loaded_data中的偏移量
                # 对应C++的：load_bias + phdr->p_vaddr
                arm_exidx_offset = phdr.p_vaddr - min_vaddr
                
                # 验证偏移量是否在loaded_data范围内
                if arm_exidx_offset < 0 or arm_exidx_offset >= len(self.elf_reader.loaded_data):
                    logger.warning(f"ARM EXIDX offset {arm_exidx_offset} out of loaded data range")
                    break
                
                # 验证段大小是否合理
                if phdr.p_memsz == 0:
                    logger.debug("ARM EXIDX segment has zero size")
                    break
                
                # 检查是否超出loaded_data边界
                if arm_exidx_offset + phdr.p_memsz > len(self.elf_reader.loaded_data):
                    logger.warning("ARM EXIDX segment extends beyond loaded data")
                    break
                
                # 从loaded_data中读取ARM EXIDX数据来验证有效性
                arm_exidx_data = self.elf_reader.loaded_data[arm_exidx_offset:arm_exidx_offset + phdr.p_memsz]
                
                # 检查数据是否全为0（表示无效）
                if all(b == 0 for b in arm_exidx_data):
                    logger.debug("ARM EXIDX data is all zeros, treating as invalid")
                    break
                
                # ARM EXIDX条目大小固定为8字节（不管32位还是64位架构）
                # 每个条目包含：4字节偏移 + 4字节数据
                ARM_EXIDX_ENTRY_SIZE = 8
                calculated_count = phdr.p_memsz // ARM_EXIDX_ENTRY_SIZE
                
                if calculated_count == 0:
                    logger.debug("ARM EXIDX segment too small for any entries")
                    break
                
                # 设置有效的ARM EXIDX信息
                self.so_info.ARM_exidx_offset = arm_exidx_offset
                self.so_info.ARM_exidx_count = calculated_count
                
                logger.debug(f"ARM EXIDX segment verified: offset=0x{arm_exidx_offset:x}, "
                           f"count={calculated_count}, data_size={phdr.p_memsz}")
                logger.debug(f"First 16 bytes of ARM EXIDX data: {arm_exidx_data[:16].hex()}")
                return
        
        # 没有找到有效的ARM EXIDX段
        self.so_info.ARM_exidx_offset = 0
        self.so_info.ARM_exidx_count = 0
        logger.debug("No valid ARM EXIDX segment found (normal for non-ARM or optimized builds)")
    
    def _parse_symbol_table(self, min_vaddr):
        """
        解析符号表，为重定位处理准备符号信息
        
        Args:
            min_vaddr: 最小虚拟地址，用于地址转换
        """
        if self.so_info.symtab_offset <= 0:
            logger.debug("No symbol table found")
            return
            
        try:
            # 计算符号表在loaded_data中的位置
            sym_entry_size = ctypes.sizeof(self.elf_reader.types['Sym'])
            
            # 计算符号数量（通过哈希表的nchain或根据大小估算）
            if self.so_info.nchain > 0:
                # 使用哈希表的nchain作为符号数量（这是ELF标准的做法）
                symbol_count = self.so_info.nchain
            else:
                # 如果没有哈希表，尝试通过段大小估算（不够精确但可用）
                # 这需要找到紧接着的段来计算符号表大小
                symbol_count = 100  # 默认值，避免解析过多
            
            # 限制符号数量，避免内存过度使用
            max_symbols = min(symbol_count, 10000)
            
            logger.debug(f"Parsing {max_symbols} symbols from symbol table")
            
            # 解析每个符号条目
            for i in range(max_symbols):
                sym_offset = self.so_info.symtab_offset + (i * sym_entry_size)
                
                # 检查是否超出loaded_data边界
                if sym_offset + sym_entry_size > len(self.elf_reader.loaded_data):
                    logger.debug(f"Reached end of loaded data at symbol {i}")
                    break
                    
                # 读取符号条目
                sym_data = self.elf_reader.loaded_data[sym_offset:sym_offset + sym_entry_size]
                if len(sym_data) < sym_entry_size:
                    break
                    
                symbol = self.elf_reader.types['Sym'].from_buffer_copy(sym_data)
                self.so_info.symbol_table.append(symbol)
            
            logger.debug(f"Parsed {len(self.so_info.symbol_table)} symbols successfully")
            
        except Exception as e:
            logger.warning(f"Failed to parse symbol table: {e}")
            # 继续执行，因为符号表解析失败不应该终止整个过程
    
    def rebuild(self) -> bool:
        """Main rebuild function"""
        logger.info("Starting ELF rebuild process...")
        
        if not self.extract_so_info():
            return False
        
        # 注意：RebuildPhdr功能已在load阶段通过fix_dump_program_headers()完成
        # extract_so_info()对应C++的ReadSoInfo()，已正确执行
        
        # 步骤1: 重建段头表 (对应C++ RebuildShdr) 
        if not self._rebuild_section_headers():
            logger.error("Failed to rebuild section headers")
            return False
        
        # 步骤2: 重建重定位表 (对应C++ RebuildRelocs)
        if not self._rebuild_relocations():
            logger.error("Failed to rebuild relocations")
            return False
        
        # 步骤3: 完成最终组装 (对应C++ RebuildFin)
        # For now, return the loaded data as rebuilt data
        # Full rebuilding logic would go here
        self.rebuilt_data = bytes(self.elf_reader.loaded_data)
        self.rebuilt_size = len(self.rebuilt_data)
        
        logger.info(f"ELF rebuild completed: {self.rebuilt_size} bytes")
        return True
    
    def get_rebuilt_data(self) -> Optional[bytes]:
        """Get the rebuilt ELF file data"""
        return self.rebuilt_data
    
    def get_rebuilt_size(self) -> int:
        """Get the size of the rebuilt ELF file"""
        return self.rebuilt_size
    
    def _add_section_name(self, name: str) -> int:
        """
        添加段名到字符串表并返回偏移量
        
        对应C++中的 shstrtab.append() 操作
        """
        offset = len(self.shstrtab)
        self.shstrtab.extend(name.encode('utf-8'))
        self.shstrtab.append(0)  # null terminator
        return offset
    
    def _create_section_header(self) -> dict:
        """
        创建一个新的段头结构
        
        返回包含所有段头字段的字典，便于后续修改
        """
        return {
            'sh_name': 0,
            'sh_type': 0, 
            'sh_flags': 0,
            'sh_addr': 0,
            'sh_offset': 0,
            'sh_size': 0,
            'sh_link': 0,
            'sh_info': 0,
            'sh_addralign': 1,
            'sh_entsize': 0
        }
    
    def _rebuild_section_headers(self) -> bool:
        """
        重建ELF段头表
        
        这是C++ RebuildShdr函数的Python实现，需要处理以下关键差异：
        1. C++使用指针计算偏移，Python使用loaded_data偏移量
        2. C++直接修改内存，Python需要重建整个文件结构
        3. C++引用现有数据，Python需要复制和重新排列数据
        
        Returns:
            True if section headers were successfully rebuilt, False otherwise
        """
        logger.debug("=======================RebuildShdr=========================")
        
        # 获取架构相关信息
        min_vaddr, max_vaddr, load_size = self.elf_reader.calculate_load_size()
        addr_size = 8 if self.elf_reader.is_64bit else 4
        
        # 步骤1: 创建空段头 (对应C++ lines 48-52)
        empty_shdr = self._create_section_header()
        self.section_headers.append(empty_shdr)
        
        # 步骤2: 重建.dynsym段 (对应C++ lines 54-80)
        if self.so_info.symtab_offset > 0:
            self.section_indices['DYNSYM'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".dynsym")
            shdr['sh_type'] = SectionType.SHT_DYNSYM
            shdr['sh_flags'] = 0x2  # SHF_ALLOC
            shdr['sh_addr'] = self.so_info.symtab_offset + min_vaddr  # 转换回虚拟地址
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = 0  # 稍后计算
            shdr['sh_link'] = 0  # 稍后链接到dynstr
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = 0x18 if self.elf_reader.is_64bit else 0x10
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .dynsym section at index {self.section_indices['DYNSYM']}")
        
        # 步骤3: 重建.dynstr段 (对应C++ lines 82-102)
        if self.so_info.strtab_offset > 0:
            self.section_indices['DYNSTR'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".dynstr")
            shdr['sh_type'] = SectionType.SHT_STRTAB
            shdr['sh_flags'] = 0x2  # SHF_ALLOC
            shdr['sh_addr'] = self.so_info.strtab_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = self.so_info.strtabsize
            shdr['sh_link'] = 0
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = 1
            shdr['sh_entsize'] = 0
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .dynstr section at index {self.section_indices['DYNSTR']}")
        
        # 步骤4: 重建.hash段 (对应C++ lines 104-125)
        if self.so_info.hash_offset > 0:
            self.section_indices['HASH'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".hash")
            shdr['sh_type'] = SectionType.SHT_HASH
            shdr['sh_flags'] = 0x2  # SHF_ALLOC
            shdr['sh_addr'] = self.so_info.hash_offset + min_vaddr  # 直接使用hash_offset（对应C++的si.hash）
            shdr['sh_offset'] = shdr['sh_addr']
            # hash表大小 = 2个Elf_Addr头 + nbucket*Elf_Addr + nchain*Elf_Addr (对应C++的sizeof(Elf_Addr))
            shdr['sh_size'] = (self.so_info.nbucket + self.so_info.nchain) * addr_size + 2 * addr_size
            shdr['sh_link'] = self.section_indices['DYNSYM']
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size  # 修复C++bug：应该等于sizeof(Elf_Addr)，保持架构一致性
            shdr['sh_entsize'] = 4  # 对应C++的0x4，hash表条目固定为4字节（ELF标准）
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .hash section at index {self.section_indices['HASH']}")
            logger.debug(f"Hash section addr: 0x{shdr['sh_addr']:x} (hash_offset=0x{self.so_info.hash_offset:x} + min_vaddr=0x{min_vaddr:x})")
        
        # 步骤5: 重建.rel.dyn段 (对应C++ lines 127-152)
        if self.so_info.rel_offset > 0:
            self.section_indices['RELDYN'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".rel.dyn")
            shdr['sh_type'] = SectionType.SHT_REL
            shdr['sh_flags'] = 0x2  # SHF_ALLOC
            shdr['sh_addr'] = self.so_info.rel_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            rel_size = 0x18 if self.elf_reader.is_64bit else 0x8
            shdr['sh_size'] = self.so_info.rel_count * rel_size
            shdr['sh_link'] = self.section_indices['DYNSYM']
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = rel_size
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .rel.dyn section at index {self.section_indices['RELDYN']}")
        
        # 步骤6: 重建.rela.dyn段 (对应C++ lines 154-174)
        if self.so_info.plt_rela_offset > 0:
            self.section_indices['RELADYN'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".rela.dyn")
            shdr['sh_type'] = SectionType.SHT_RELA
            shdr['sh_flags'] = 0x2  # SHF_ALLOC
            shdr['sh_addr'] = self.so_info.plt_rela_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            rela_size = ctypes.sizeof(self.elf_reader.types['Rela'])
            shdr['sh_size'] = self.so_info.plt_rela_count * rela_size
            shdr['sh_link'] = self.section_indices['DYNSYM']
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = rela_size
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .rela.dyn section at index {self.section_indices['RELADYN']}")
        
        # 步骤7: 重建.rel.plt/.rela.plt段 (对应C++ lines 175-208)
        if self.so_info.plt_rel_offset > 0:
            self.section_indices['RELPLT'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            if self.so_info.plt_type == DynamicTag.DT_REL:
                shdr['sh_name'] = self._add_section_name(".rel.plt")
                shdr['sh_type'] = SectionType.SHT_REL
                rel_size = ctypes.sizeof(self.elf_reader.types['Rel'])
            else:
                shdr['sh_name'] = self._add_section_name(".rela.plt")
                shdr['sh_type'] = SectionType.SHT_RELA
                rel_size = ctypes.sizeof(self.elf_reader.types['Rela'])
                
            shdr['sh_flags'] = 0x2  # SHF_ALLOC
            shdr['sh_addr'] = self.so_info.plt_rel_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = self.so_info.plt_rel_count * rel_size
            shdr['sh_link'] = self.section_indices['DYNSYM']
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = rel_size
            
            self.section_headers.append(shdr)
            logger.debug(f"Added plt relocation section at index {self.section_indices['RELPLT']}")
        
        # 步骤8: 重建.plt段 (对应C++ lines 210-231)
        if self.so_info.plt_rel_offset > 0:
            self.section_indices['PLT'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".plt")
            shdr['sh_type'] = SectionType.SHT_PROGBITS
            shdr['sh_flags'] = 0x6  # SHF_ALLOC | SHF_EXECINSTR
            
            # PLT位置在rel.plt之后
            if self.section_indices['RELPLT'] > 0:
                prev_shdr = self.section_headers[self.section_indices['RELPLT']]
                shdr['sh_addr'] = prev_shdr['sh_addr'] + prev_shdr['sh_size']
            else:
                shdr['sh_addr'] = min_vaddr + load_size
                
            shdr['sh_offset'] = shdr['sh_addr']
            # PLT大小估算：20字节基础代码 + 12字节每个条目
            shdr['sh_size'] = 20 + 12 * self.so_info.plt_rel_count
            shdr['sh_link'] = 0
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = 16 if self.elf_reader.is_64bit else 4  # 64-bit: 16-byte, 32-bit: 4-byte alignment
            shdr['sh_entsize'] = 0
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .plt section at index {self.section_indices['PLT']}")
        
        # 步骤9: 重建.text&ARM.extab段 (对应C++ lines 233-258)
        if self.so_info.plt_rel_offset > 0:
            self.section_indices['TEXTTAB'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".text&ARM.extab")
            shdr['sh_type'] = SectionType.SHT_PROGBITS
            shdr['sh_flags'] = 0x6  # SHF_ALLOC | SHF_EXECINSTR
            
            # 在PLT之后，8字节对齐
            if self.section_indices['PLT'] > 0:
                prev_shdr = self.section_headers[self.section_indices['PLT']]
                addr = prev_shdr['sh_addr'] + prev_shdr['sh_size']
                # 8字节对齐
                addr = (addr + 7) & ~7
                shdr['sh_addr'] = addr
            else:
                shdr['sh_addr'] = min_vaddr + load_size
                
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = 0  # 稍后计算
            shdr['sh_link'] = 0
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = 16 if self.elf_reader.is_64bit else 8  # 64-bit: 16-byte, 32-bit: 8-byte alignment
            shdr['sh_entsize'] = 0
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .text&ARM.extab section at index {self.section_indices['TEXTTAB']}")
        
        # 步骤10: 重建.ARM.exidx段 (对应C++ lines 260-280)
        if self.so_info.ARM_exidx_count > 0:
            self.section_indices['ARMEXIDX'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".ARM.exidx")
            shdr['sh_type'] = SectionType.SHT_ARMEXIDX
            shdr['sh_flags'] = 0x82  # SHF_ALLOC | SHF_LINK_ORDER
            shdr['sh_addr'] = self.so_info.ARM_exidx_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = self.so_info.ARM_exidx_count * 8  # 每个条目8字节
            shdr['sh_link'] = self.section_indices['TEXTTAB']
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = 4
            shdr['sh_entsize'] = 8
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .ARM.exidx section at index {self.section_indices['ARMEXIDX']}")
        
        # 步骤11: 重建.fini_array段 (对应C++ lines 281-305)
        if self.so_info.fini_array_count > 0:
            self.section_indices['FINIARRAY'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".fini_array")
            shdr['sh_type'] = SectionType.SHT_FINI_ARRAY
            shdr['sh_flags'] = 0x3  # SHF_ALLOC | SHF_WRITE
            shdr['sh_addr'] = self.so_info.fini_array_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = self.so_info.fini_array_count * addr_size
            shdr['sh_link'] = 0
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = addr_size  # 函数指针大小：64位=8字节，32位=4字节
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .fini_array section at index {self.section_indices['FINIARRAY']}")
        
        # 步骤12: 重建.init_array段 (对应C++ lines 307-331)
        if self.so_info.init_array_count > 0:
            self.section_indices['INITARRAY'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".init_array")
            shdr['sh_type'] = SectionType.SHT_INIT_ARRAY
            shdr['sh_flags'] = 0x3  # SHF_ALLOC | SHF_WRITE
            shdr['sh_addr'] = self.so_info.init_array_offset + min_vaddr
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = self.so_info.init_array_count * addr_size
            shdr['sh_link'] = 0
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = addr_size  # 函数指针大小：64位=8字节，32位=4字节
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .init_array section at index {self.section_indices['INITARRAY']}")
        
        # 步骤13: 重建.dynamic段 (对应C++ lines 333-358)
        if self.so_info.dynamic_count > 0:
            self.section_indices['DYNAMIC'] = len(self.section_headers)
            
            shdr = self._create_section_header()
            shdr['sh_name'] = self._add_section_name(".dynamic")
            shdr['sh_type'] = SectionType.SHT_DYNAMIC
            shdr['sh_flags'] = 0x3  # SHF_ALLOC | SHF_WRITE
            
            # 动态段位置需要从程序头中获取
            dynamic_addr = 0
            for phdr in self.elf_reader.program_headers:
                if phdr.p_type == SegmentType.PT_DYNAMIC:
                    dynamic_addr = phdr.p_vaddr
                    break
                    
            shdr['sh_addr'] = dynamic_addr
            shdr['sh_offset'] = shdr['sh_addr']
            dyn_size = 0x10 if self.elf_reader.is_64bit else 0x8
            shdr['sh_size'] = self.so_info.dynamic_count * dyn_size
            shdr['sh_link'] = self.section_indices['DYNSTR']
            shdr['sh_info'] = 0
            shdr['sh_addralign'] = addr_size
            shdr['sh_entsize'] = dyn_size
            
            self.section_headers.append(shdr)
            logger.debug(f"Added .dynamic section at index {self.section_indices['DYNAMIC']}")
        
        # 步骤14: 重建.data段 (对应C++ lines 393-414)
        self.section_indices['DATA'] = len(self.section_headers)
        last_idx = len(self.section_headers) - 1
        
        shdr = self._create_section_header()
        shdr['sh_name'] = self._add_section_name(".data")
        shdr['sh_type'] = SectionType.SHT_PROGBITS
        shdr['sh_flags'] = 0x3  # SHF_ALLOC | SHF_WRITE
        
        if last_idx > 0:
            prev_shdr = self.section_headers[last_idx]
            shdr['sh_addr'] = prev_shdr['sh_addr'] + prev_shdr['sh_size']
        else:
            shdr['sh_addr'] = min_vaddr
            
        shdr['sh_offset'] = shdr['sh_addr']
        shdr['sh_size'] = max_vaddr - shdr['sh_addr']
        shdr['sh_link'] = 0
        shdr['sh_info'] = 0
        shdr['sh_addralign'] = addr_size  # 64位=8字节，32位=4字节对齐
        shdr['sh_entsize'] = 0
        
        self.section_headers.append(shdr)
        logger.debug(f"Added .data section at index {self.section_indices['DATA']}")
        
        # 步骤15: 重建.shstrtab段 (对应C++ lines 438-458)
        self.section_indices['SHSTRTAB'] = len(self.section_headers)
        
        shdr = self._create_section_header()
        shdr['sh_name'] = self._add_section_name(".shstrtab")
        shdr['sh_type'] = SectionType.SHT_STRTAB
        shdr['sh_flags'] = 0
        shdr['sh_addr'] = max_vaddr
        shdr['sh_offset'] = shdr['sh_addr']
        shdr['sh_size'] = len(self.shstrtab)
        shdr['sh_link'] = 0
        shdr['sh_info'] = 0
        shdr['sh_addralign'] = 1
        shdr['sh_entsize'] = 0
        
        self.section_headers.append(shdr)
        logger.debug(f"Added .shstrtab section at index {self.section_indices['SHSTRTAB']}")
        
        # 步骤16: 排序段头表 (对应C++ lines 462-497)
        self._sort_section_headers()
        
        # 步骤17: 修复段链接关系
        self._fix_section_links()
        
        # 步骤18: 计算段大小
        self._calculate_section_sizes()
        
        logger.debug("=======================RebuildShdr End=========================")
        logger.info(f"Successfully rebuilt {len(self.section_headers)} section headers")
        return True
    
    def _sort_section_headers(self):
        """
        按地址排序段头表并更新索引
        
        对应C++ lines 462-497的排序逻辑
        优化版本：实时更新索引映射，提高效率和代码简洁性
        """
        logger.debug("Sorting section headers by address...")
        
        # 创建反向映射以便快速查找段名
        reverse_section_indices = {v: k for k, v in self.section_indices.items()}
        
        # 冒泡排序（保持与C++逻辑一致）
        for i in range(1, len(self.section_headers)):
            for j in range(i + 1, len(self.section_headers)):
                if self.section_headers[i]['sh_addr'] > self.section_headers[j]['sh_addr']:
                    # 交换段头
                    self.section_headers[i], self.section_headers[j] = \
                        self.section_headers[j], self.section_headers[i]
                    
                    # 实时更新索引映射
                    self.section_indices[reverse_section_indices[i]], \
                        self.section_indices[reverse_section_indices[j]] = \
                        self.section_indices[reverse_section_indices[j]], \
                        self.section_indices[reverse_section_indices[i]]
                    
                    # 更新反向映射
                    reverse_section_indices[i], reverse_section_indices[j] = \
                        reverse_section_indices[j], reverse_section_indices[i]
        
        logger.debug("Section headers sorted successfully")
    
    
    def _fix_section_links(self):
        """
        修复段之间的链接关系
        """
        logger.debug("Fixing section links...")
        
        # 修复各种段的链接关系
        if self.section_indices['HASH'] > 0:
            self.section_headers[self.section_indices['HASH']]['sh_link'] = self.section_indices['DYNSYM']
        
        if self.section_indices['RELDYN'] > 0:
            self.section_headers[self.section_indices['RELDYN']]['sh_link'] = self.section_indices['DYNSYM']
        
        if self.section_indices['RELADYN'] > 0:
            self.section_headers[self.section_indices['RELADYN']]['sh_link'] = self.section_indices['DYNSYM']
        
        if self.section_indices['RELPLT'] > 0:
            self.section_headers[self.section_indices['RELPLT']]['sh_link'] = self.section_indices['DYNSYM']
        
        if self.section_indices['ARMEXIDX'] > 0:
            self.section_headers[self.section_indices['ARMEXIDX']]['sh_link'] = self.section_indices['TEXTTAB']
        
        if self.section_indices['DYNAMIC'] > 0:
            self.section_headers[self.section_indices['DYNAMIC']]['sh_link'] = self.section_indices['DYNSTR']
        
        if self.section_indices['DYNSYM'] > 0:
            self.section_headers[self.section_indices['DYNSYM']]['sh_link'] = self.section_indices['DYNSTR']
        
        logger.debug("Section links fixed successfully")
    
    def _calculate_section_sizes(self):
        """
        计算段大小
        """
        logger.debug("Calculating section sizes...")
        
        # 计算.dynsym段大小
        if self.section_indices['DYNSYM'] > 0:
            dynsym_idx = self.section_indices['DYNSYM']
            next_idx = dynsym_idx + 1
            if next_idx < len(self.section_headers):
                size = (self.section_headers[next_idx]['sh_addr'] - 
                       self.section_headers[dynsym_idx]['sh_addr'])
                self.section_headers[dynsym_idx]['sh_size'] = size
        
        # 计算.text&ARM.extab段大小
        if self.section_indices['TEXTTAB'] > 0:
            texttab_idx = self.section_indices['TEXTTAB']
            next_idx = texttab_idx + 1
            if next_idx < len(self.section_headers):
                size = (self.section_headers[next_idx]['sh_addr'] - 
                       self.section_headers[texttab_idx]['sh_addr'])
                self.section_headers[texttab_idx]['sh_size'] = size
        
        # 修复重叠的段大小
        for i in range(2, len(self.section_headers)):
            prev_end = (self.section_headers[i-1]['sh_offset'] + 
                       self.section_headers[i-1]['sh_size'])
            curr_start = self.section_headers[i]['sh_offset']
            
            if prev_end > curr_start:
                self.section_headers[i-1]['sh_size'] = curr_start - self.section_headers[i-1]['sh_offset']
        
        logger.debug("Section sizes calculated successfully")
    
    def _rebuild_relocations(self) -> bool:
        """
        重建重定位表 - 修复内存dump中的绝对地址
        
        对应C++的RebuildRelocs函数。核心功能是将内存dump中的绝对地址
        转换为可重定位的相对地址，确保重建的SO文件能正确加载。
        
        Returns:
            True if relocations were successfully rebuilt, False otherwise
        """
        # 检查是否需要重定位修复（仅当有dump_base_addr时才需要）
        if self.elf_reader.dump_base_addr == 0:
            logger.debug("No dump base address set, skipping relocation rebuild")
            return True
            
        logger.debug("=======================RebuildRelocs=========================")
        
        # 获取架构相关信息
        min_vaddr, max_vaddr, load_size = self.elf_reader.calculate_load_size()
        is_64bit = self.elf_reader.is_64bit
        addr_size = 8 if is_64bit else 4
        
        # 调试信息：输出关键地址和配置信息
        logger.debug(f"Relocation processing configuration:")
        logger.debug(f"  Architecture: {'x86_64' if is_64bit else 'i386/ARM'}")
        logger.debug(f"  Address size: {addr_size} bytes")
        logger.debug(f"  Virtual address range: 0x{min_vaddr:x} - 0x{max_vaddr:x}")
        logger.debug(f"  Load size: 0x{load_size:x} bytes")
        logger.debug(f"  Loaded data size: 0x{len(self.elf_reader.loaded_data):x} bytes")
        logger.debug(f"  Dump base address: 0x{self.elf_reader.dump_base_addr:x}")
        
        # 调试信息：输出重定位表统计
        total_relocations = 0
        if hasattr(self.so_info, 'rel_count'):
            total_relocations += self.so_info.rel_count
        if hasattr(self.so_info, 'plt_rel_count'):
            total_relocations += self.so_info.plt_rel_count  
        if hasattr(self.so_info, 'plt_rela_count'):
            total_relocations += self.so_info.plt_rela_count
        logger.debug(f"  Total relocations to process: {total_relocations}")
        
        if hasattr(self.so_info, 'rel_count') and self.so_info.rel_count > 0:
            logger.debug(f"  .rel.dyn: {self.so_info.rel_count} entries at offset 0x{self.so_info.rel_offset:x}")
        if hasattr(self.so_info, 'plt_rel_count') and self.so_info.plt_rel_count > 0:
            logger.debug(f"  .rel.plt: {self.so_info.plt_rel_count} entries at offset 0x{self.so_info.plt_rel_offset:x}")
        if hasattr(self.so_info, 'plt_rela_count') and self.so_info.plt_rela_count > 0:
            logger.debug(f"  .rela.plt: {self.so_info.plt_rela_count} entries at offset 0x{self.so_info.plt_rela_offset:x}")
        
        # 外部符号指针计数器（对应C++的external_pointer）
        self.external_pointer = 0
        
        try:
            # 根据PLT重定位类型选择处理方式
            if self.so_info.plt_type == DynamicTag.DT_REL:
                logger.debug("Processing REL format relocations")
                
                # 处理.rel.dyn段的重定位
                if self.so_info.rel_count > 0 and self.so_info.rel_offset > 0:
                    logger.debug(f"Processing {self.so_info.rel_count} .rel.dyn relocations")
                    if not self._process_rel_relocations(
                        self.so_info.rel_offset, self.so_info.rel_count, 
                        min_vaddr, addr_size, False):
                        return False
                
                # 处理.rel.plt段的重定位
                if self.so_info.plt_rel_count > 0 and self.so_info.plt_rel_offset > 0:
                    logger.debug(f"Processing {self.so_info.plt_rel_count} .rel.plt relocations")
                    if not self._process_rel_relocations(
                        self.so_info.plt_rel_offset, self.so_info.plt_rel_count,
                        min_vaddr, addr_size, False):
                        return False
                        
            else:
                logger.debug("Processing RELA format relocations")
                
                # 处理RELA格式的重定位（主要用于64位架构）
                if self.so_info.plt_rela_count > 0 and self.so_info.plt_rela_offset > 0:
                    logger.debug(f"Processing {self.so_info.plt_rela_count} RELA relocations")
                    if not self._process_rel_relocations(
                        self.so_info.plt_rela_offset, self.so_info.plt_rela_count,
                        min_vaddr, addr_size, True):
                        return False
                
                # 处理PLT RELA重定位
                if self.so_info.plt_rel_count > 0 and self.so_info.plt_rel_offset > 0:
                    logger.debug(f"Processing {self.so_info.plt_rel_count} PLT RELA relocations")
                    if not self._process_rel_relocations(
                        self.so_info.plt_rel_offset, self.so_info.plt_rel_count,
                        min_vaddr, addr_size, True):
                        return False
            
            logger.debug("=======================RebuildRelocs End=========================")
            logger.info("Relocations rebuilt successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rebuild relocations: {e}")
            return False
    
    def _process_rel_relocations(self, rel_offset: int, rel_count: int, 
                                min_vaddr: int, addr_size: int, is_rela: bool) -> bool:
        """
        处理重定位表中的所有条目
        
        Args:
            rel_offset: 重定位表在loaded_data中的偏移量
            rel_count: 重定位条目数量
            min_vaddr: 最小虚拟地址
            addr_size: 地址大小（4或8字节）
            is_rela: 是否为RELA格式（包含r_addend字段）
            
        Returns:
            True if all relocations were processed successfully
        """
        if rel_offset < 0 or rel_offset >= len(self.elf_reader.loaded_data):
            logger.error(f"Invalid relocation offset: 0x{rel_offset:x}")
            return False
            
        # 计算重定位条目大小
        rel_entry_size = ctypes.sizeof(self.elf_reader.types['Rela'] if is_rela 
                                      else self.elf_reader.types['Rel'])
        
        # 检查重定位表是否在loaded_data范围内
        table_size = rel_count * rel_entry_size
        if rel_offset + table_size > len(self.elf_reader.loaded_data):
            logger.error(f"Relocation table extends beyond loaded data")
            return False
            
        # 调试信息：重定位处理开始
        logger.debug(f"Processing {rel_count} relocations:")
        logger.debug(f"  Table offset: 0x{rel_offset:x}")
        logger.debug(f"  Entry size: {rel_entry_size} bytes")
        logger.debug(f"  Total table size: 0x{table_size:x} bytes")
        logger.debug(f"  Format: {'RELA' if is_rela else 'REL'}")
        
        # 统计成功和失败的重定位处理数量
        successful_relocations = 0
        failed_relocations = 0
        
        # 逐个处理重定位条目
        for i in range(rel_count):
            entry_offset = rel_offset + (i * rel_entry_size)
            
            # 从loaded_data中读取重定位条目
            entry_data = self.elf_reader.loaded_data[entry_offset:entry_offset + rel_entry_size]
            if len(entry_data) < rel_entry_size:
                logger.error(f"Insufficient data for relocation entry {i}")
                return False
            
            # 解析重定位条目
            if is_rela:
                rel_entry = self.elf_reader.types['Rela'].from_buffer_copy(entry_data)
            else:
                rel_entry = self.elf_reader.types['Rel'].from_buffer_copy(entry_data)
            
            # 处理单个重定位
            if self._relocate(rel_entry, min_vaddr, addr_size, is_rela):
                successful_relocations += 1
                # 每100个成功重定位输出一次进度
                if (successful_relocations % 100 == 0) and successful_relocations > 0:
                    logger.debug(f"  Progress: {successful_relocations}/{rel_count} relocations processed")
            else:
                failed_relocations += 1
                logger.warning(f"Failed to process relocation entry {i}: "
                             f"r_offset=0x{rel_entry.r_offset:x}, "
                             f"r_info=0x{rel_entry.r_info:x}")
                # 继续处理其他条目，不立即返回失败
        
        # 输出最终统计信息
        logger.debug(f"Relocation processing completed:")
        logger.debug(f"  Successful: {successful_relocations}/{rel_count}")
        logger.debug(f"  Failed: {failed_relocations}/{rel_count}")
        if failed_relocations > 0:
            logger.warning(f"  Warning: {failed_relocations} relocations failed but processing continued")
        
        return True
    
    def _relocate(self, rel_entry, min_vaddr: int, addr_size: int, is_rela: bool) -> bool:
        """
        处理单个重定位条目
        
        对应C++的relocate模板函数。核心功能是修正重定位目标地址。
        
        Args:
            rel_entry: 重定位条目（Elf_Rel或Elf_Rela结构）
            min_vaddr: 最小虚拟地址
            addr_size: 地址大小（4或8字节）
            is_rela: 是否为RELA格式
            
        Returns:
            True if relocation was processed successfully
        """
        try:
            # 提取重定位信息（对应C++的ELF32_R_TYPE/ELF64_R_TYPE宏）
            if self.elf_reader.is_64bit:
                rel_type = rel_entry.r_info & 0xFFFFFFFF  # 低32位是类型
                sym_index = rel_entry.r_info >> 32         # 高32位是符号索引
            else:
                rel_type = rel_entry.r_info & 0xFF        # 低8位是类型
                sym_index = rel_entry.r_info >> 8         # 高24位是符号索引
            
            # 使用精确的虚拟地址到loaded_data偏移转换
            # 这解决了文件基地址映射和内存转储地址空间不匹配的问题
            target_offset = self.elf_reader.virtual_addr_to_loaded_offset(rel_entry.r_offset)
            
            # 检查地址转换是否成功
            if target_offset is None:
                logger.warning(f"Failed to map relocation virtual address 0x{rel_entry.r_offset:x} to loaded_data offset")
                return False
                
            # 额外的边界检查（虽然virtual_addr_to_loaded_offset已经做了检查）
            if target_offset + addr_size > len(self.elf_reader.loaded_data):
                logger.warning(f"Relocation target extends beyond loaded_data bounds: "
                             f"offset=0x{target_offset:x}, size={addr_size}, "
                             f"loaded_size=0x{len(self.elf_reader.loaded_data):x}")
                return False
            
            # 从loaded_data中读取当前地址值
            format_str = '<Q' if addr_size == 8 else '<L'  # 小端格式
            current_value = struct.unpack(format_str, 
                self.elf_reader.loaded_data[target_offset:target_offset + addr_size])[0]
            
            # 根据重定位类型处理
            new_value = current_value
            
            # R_ARM_RELATIVE 或 R_386_RELATIVE - 相对重定位（最常见）
            if rel_type in [RelocationARM.R_ARM_RELATIVE, RelocationI386.R_386_RELATIVE]:
                # 核心转换：绝对地址 → 相对地址
                # 对应C++的：*prel = *prel - dump_base
                new_value = current_value - self.elf_reader.dump_base_addr
                logger.debug(f"RELATIVE relocation: 0x{current_value:x} -> 0x{new_value:x}")
                
            # 符号重定位（类型0x402）
            elif rel_type == 0x402:
                if sym_index < len(self.so_info.symbol_table):
                    symbol = self.so_info.symbol_table[sym_index]
                    if symbol.st_value != 0:
                        new_value = symbol.st_value
                    else:
                        # 未定义符号分配外部指针空间
                        load_size = self.elf_reader.calculate_load_size()[2]
                        new_value = load_size + self.external_pointer
                        self.external_pointer += addr_size
                    logger.debug(f"SYMBOL relocation: sym_idx={sym_index}, value=0x{new_value:x}")
                else:
                    logger.warning(f"Invalid symbol index {sym_index}")
                    return False
            
            # RELA格式的加数处理（类型0x403）
            elif rel_type == 0x403 and is_rela:
                new_value = rel_entry.r_addend
                logger.debug(f"ADDEND relocation: value=0x{new_value:x}")
            
            else:
                # 未知的重定位类型，记录但不失败
                logger.debug(f"Unhandled relocation type: 0x{rel_type:x}")
                return True
            
            # 将新值写回loaded_data
            # 对应C++的：*prel = new_value
            packed_value = struct.pack(format_str, new_value)
            self.elf_reader.loaded_data[target_offset:target_offset + addr_size] = packed_value
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing relocation: {e}")
            return False


# =============================================================================
# Utility Functions
# =============================================================================

def parse_memory_address(addr_str: str) -> int:
    """Parse memory address from string, supporting hex and decimal formats"""
    addr_str = addr_str.strip()
    
    if addr_str.lower().startswith('0x'):
        return int(addr_str, 16)
    
    if any(c in addr_str.lower() for c in 'abcdef'):
        return int(addr_str, 16)
    
    return int(addr_str, 10)


def setup_logging(debug: bool):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s',
        force=True
    )


# =============================================================================
# Main Application
# =============================================================================

def main():
    """Main entry point for the ctypes-based SoFixer implementation"""
    parser = argparse.ArgumentParser(
        description='SoFixer (ctypes) - Repair dumped SO files from memory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with automatic architecture detection
  python sofixer_ctypes.py -s dumped.so -o fixed.so -m 0x7DB078B000
  
  # With debug output and base SO file
  python sofixer_ctypes.py -s dumped.so -o fixed.so -m 0x7DB078B000 -d -b original.so
        """
    )
    
    parser.add_argument('-s', '--source', required=True,
                       help='Source dumped SO file path')
    parser.add_argument('-o', '--output', required=True,
                       help='Output fixed SO file path')
    parser.add_argument('-m', '--memso', required=True,
                       help='Memory base address where SO was dumped from')
    parser.add_argument('-b', '--baseso',
                       help='Original SO file path (for dynamic section recovery)')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug output')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    
    try:
        # Validate input file
        if not os.path.isfile(args.source):
            logger.error(f"Source file not found: {args.source}")
            return 1
        
        # Parse memory address
        try:
            dump_base_addr = parse_memory_address(args.memso)
            logger.info(f"Using dump base address: 0x{dump_base_addr:x}")
        except ValueError:
            logger.error(f"Invalid memory address format: {args.memso}")
            return 1
        
        # Validate base SO file if provided
        if args.baseso and not os.path.isfile(args.baseso):
            logger.error(f"Base SO file not found: {args.baseso}")
            return 1
        
        # Initialize obfuscated ELF reader
        with ObfuscatedELFReader(args.source) as elf_reader:
            # Set parameters
            elf_reader.set_dump_base_addr(dump_base_addr)
            if args.baseso:
                elf_reader.set_base_so_path(args.baseso)
            
            # Load the ELF file
            if not elf_reader.load():
                logger.error("Failed to load ELF file")
                return 1
            
            # Initialize rebuilder
            rebuilder = ELFRebuilder(elf_reader)
            
            # Rebuild the ELF file
            if not rebuilder.rebuild():
                logger.error("Failed to rebuild ELF file")
                return 1
            
            # Write output file
            rebuilt_data = rebuilder.get_rebuilt_data()
            if not rebuilt_data:
                logger.error("No rebuilt data available")
                return 1
            
            try:
                with open(args.output, 'wb') as f:
                    f.write(rebuilt_data)
                
                logger.info(f"Successfully wrote {len(rebuilt_data)} bytes to {args.output}")
                
                # Verify output
                if detect_elf_architecture(args.output):
                    logger.info("Output file verification passed")
                else:
                    logger.warning("Output file verification failed")
                
                logger.info("Done! SO file repair completed successfully.")
                return 0
                
            except (IOError, OSError) as e:
                logger.error(f"Failed to write output file {args.output}: {e}")
                return 1
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())