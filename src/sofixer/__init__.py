#!/usr/bin/env python3
"""
SoFixer Python版本
=================

ELF文件重建工具的Python实现，专门用于修复从内存转储的共享库(.so)文件。

主要功能：
- ELF文件解析和加载
- 程序头和段头表重建
- 动态段和重定位表修复
- 内存地址映射修正

核心模块：
- elf_reader: ELF文件读取和解析
- elf_rebuilder: ELF文件重建和修复
- types: ELF结构类型定义
- utils: 通用工具函数
- main: 命令行主程序
"""

__version__ = "1.1.0"
__author__ = "F8LEFT (原始C++实现), Python移植版本"

# 导出主要类和函数
from .elf_reader import ELFReader, ObfuscatedELFReader
from .elf_rebuilder import ELFRebuilder
from .types import *
from .main import main, fix_so, fix_so_file

__all__ = [
    'ELFReader',
    'ObfuscatedELFReader', 
    'ELFRebuilder',
    'main',
    'fix_so',
    'fix_so_file',
]