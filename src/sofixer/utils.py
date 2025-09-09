#!/usr/bin/env python3
"""
ELF Utilities Module
====================

This module contains utility functions for ELF file processing, including:
- Architecture detection
- Type system management  
- Address parsing
- Logging configuration

Extracted from the main SoFixer implementation for better modularity.
"""

import logging
from typing import Optional
from .types import *


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
            if len(e_ident) < 16 or e_ident[:4] != b'\x7fELF':
                return None
                
            # Check ELF class (32-bit or 64-bit)
            elf_class = e_ident[4]
            if elf_class == ELFClass.ELFCLASS32:
                return "32"
            elif elf_class == ELFClass.ELFCLASS64:
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