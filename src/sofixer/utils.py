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