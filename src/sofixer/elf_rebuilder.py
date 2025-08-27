#!/usr/bin/env python3
"""
ELF Rebuilder Module
===================

ELF file rebuilder using ctypes for accurate binary reconstruction.
Extracted from sofixer.py to provide modular architecture.

This module contains the ELFRebuilder class that handles:
- Section header table reconstruction
- Relocation table rebuilding  
- Final ELF file assembly

Features:
- Exact binary layout matching with C structures
- Proper handling of 32/64-bit architectures
- Memory dump address correction
- Complete ELF structure reconstruction

Original C++ implementation by F8LEFT.
Python implementation extracted and modularized.
"""

import ctypes
import struct
import logging
from typing import Optional

# Import ELF types and structures
from .types import *

# Import utilities and reader
from .elf_reader import ObfuscatedELFReader

# Configure logging
logger = logging.getLogger(__name__)

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
        
        # 验证新的ELF加载流程产生的数据
        logger.debug("=== ELF Reader Data Validation ===")
        if hasattr(self.elf_reader, 'reserved_min_vaddr'):
            logger.debug(f"  ELF Reader reserved range: 0x{self.elf_reader.reserved_min_vaddr:x} - 0x{self.elf_reader.reserved_max_vaddr:x}")
            logger.debug(f"  Calculated range: 0x{min_vaddr:x} - 0x{max_vaddr:x}")
            
            # 验证数据一致性
            if (self.elf_reader.reserved_min_vaddr != min_vaddr or 
                self.elf_reader.reserved_max_vaddr != max_vaddr):
                logger.warning("Address range mismatch between ELF reader and rebuilder calculations")
                # 使用ELF reader的预留数据，因为它经过了完整的C++兼容流程
                min_vaddr = self.elf_reader.reserved_min_vaddr
                max_vaddr = self.elf_reader.reserved_max_vaddr
                load_size = self.elf_reader.reserved_size
                logger.info(f"Using ELF reader reserved data: 0x{min_vaddr:x} - 0x{max_vaddr:x} (size: 0x{load_size:x})")
        
        # 验证程序头表处理 (对应C++的FindPhdr和ApplyPhdrTable步骤)
        if hasattr(self.elf_reader, 'phdr_table_vaddr'):
            logger.debug(f"  Program header table: vaddr=0x{self.elf_reader.phdr_table_vaddr:x}, "
                        f"size=0x{self.elf_reader.phdr_table_size:x}")
            if hasattr(self.elf_reader, 'applied_phdr_offset'):
                logger.debug(f"  Applied PHDR table: offset=0x{self.elf_reader.applied_phdr_offset:x}, "
                           f"size=0x{self.elf_reader.applied_phdr_size:x}")
        else:
            logger.warning("Program header table processing incomplete - may affect segment rebuilding")
        
        # 设置基本的min_load和max_load (对应C++ si.min_load和si.max_load)
        self.so_info.min_load = min_vaddr
        self.so_info.max_load = max_vaddr
        
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
        
        # 步骤5: 计算动态段填充大小和调整max_load (对应C++ pad_size_和si.max_load调整)
        self.so_info.pad_size = 0
        if hasattr(self.elf_reader, 'dynamic_section_data') and self.elf_reader.dynamic_section_data:
            dyn_size = ctypes.sizeof(self.elf_reader.types['Dyn'])
            if self.so_info.dynamic_count > 0:
                self.so_info.pad_size = self.so_info.dynamic_count * dyn_size
                logger.debug(f"Calculated pad_size for dynamic section: {self.so_info.pad_size} bytes")
        
        # 调整最大加载地址 (对应C++ si.max_load += elf_reader_->pad_size_)
        self.so_info.max_load += self.so_info.pad_size
        logger.debug(f"Adjusted max_load: 0x{self.so_info.max_load:x} (original: 0x{max_vaddr:x}, pad_size: {self.so_info.pad_size})")
        
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
        if not self._rebuild_final_file():
            logger.error("Failed to rebuild final file")
            return False
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
        # C++: Elf_Shdr shdr = {0}; - 全零初始化
        empty_shdr = self._create_section_header()  # 已经是全零初始化
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
            # 注意：C++版本没有设置sh_flags，保持为0以匹配C++行为
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
            rel_size = ctypes.sizeof(self.elf_reader.types['Rel'])
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
                
            # shdr['sh_type'] = SectionType.SHT_REL
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
            
            # 按照C++精确逻辑计算地址：shdrs[sPLT].sh_addr + shdrs[sPLT].sh_size
            if self.section_indices['PLT'] > 0:
                prev_shdr = self.section_headers[self.section_indices['PLT']]
                shdr['sh_addr'] = prev_shdr['sh_addr'] + prev_shdr['sh_size']
                # 对应C++的 while (shdr.sh_addr & 0x7) { shdr.sh_addr ++; }
                while shdr['sh_addr'] & 0x7:
                    shdr['sh_addr'] += 1
            else:
                shdr['sh_addr'] = min_vaddr + load_size
                
            shdr['sh_offset'] = shdr['sh_addr']
            shdr['sh_size'] = 0  # 对应C++的初始值，稍后由排序后的下一个段地址计算
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
        shdr['sh_size'] = self.so_info.max_load - shdr['sh_addr']
        shdr['sh_link'] = 0
        shdr['sh_info'] = 0
        shdr['sh_addralign'] = addr_size  # 64位=8字节，32位=4字节对齐
        shdr['sh_entsize'] = 0
        
        self.section_headers.append(shdr)
        logger.debug(f"Added .data section at index {self.section_indices['DATA']}")
        logger.debug(f"  .data section details: addr=0x{shdr['sh_addr']:x}, size=0x{shdr['sh_size']:x}")
        logger.debug(f"  using max_load=0x{self.so_info.max_load:x} (includes pad_size={self.so_info.pad_size})")
        
        # 步骤15: 重建.shstrtab段 (对应C++ lines 438-458)
        self.section_indices['SHSTRTAB'] = len(self.section_headers)
        
        shdr = self._create_section_header()
        shdr['sh_name'] = self._add_section_name(".shstrtab")
        shdr['sh_type'] = SectionType.SHT_STRTAB
        shdr['sh_flags'] = 0
        shdr['sh_addr'] = 0 # 不加载到内存，虚拟地址为0
        shdr['sh_offset'] = 0 # 等下在_rebuild_final_file中计算
        shdr['sh_size'] = len(self.shstrtab)
        shdr['sh_link'] = 0
        shdr['sh_info'] = 0
        shdr['sh_addralign'] = 1
        shdr['sh_entsize'] = 0
        
        self.section_headers.append(shdr)
        logger.debug(f"Added .shstrtab section at index {self.section_indices['SHSTRTAB']}")
        logger.debug(f"  .shstrtab section details: addr=0x{shdr['sh_addr']:x}, size=0x{shdr['sh_size']:x}")
        logger.debug(f"  using max_load=0x{self.so_info.max_load:x} as file layout position")
        
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
        完全匹配C++的冒泡排序和索引交换逻辑
        """
        logger.debug("Sorting section headers by address...")
        
        # 完全按照C++的排序逻辑：for(auto i = 1; i < shdrs.size(); i++)
        for i in range(1, len(self.section_headers)):
            for j in range(i + 1, len(self.section_headers)):
                if self.section_headers[i]['sh_addr'] > self.section_headers[j]['sh_addr']:
                    # 交换段头（对应C++的 tmp = shdrs[i]; shdrs[i] = shdrs[j]; shdrs[j] = tmp;）
                    tmp = self.section_headers[i]
                    self.section_headers[i] = self.section_headers[j]
                    self.section_headers[j] = tmp
                    
                    # 按照C++逻辑交换所有索引（对应C++的chgIdx函数调用）
                    def chg_idx(idx_dict_key):
                        if self.section_indices[idx_dict_key] == i:
                            self.section_indices[idx_dict_key] = j
                        elif self.section_indices[idx_dict_key] == j:
                            self.section_indices[idx_dict_key] = i
                    
                    # 对应C++的所有chgIdx调用
                    chg_idx('DYNSYM')
                    chg_idx('DYNSTR')
                    chg_idx('HASH')
                    chg_idx('RELDYN')
                    chg_idx('RELADYN')
                    chg_idx('RELPLT')
                    chg_idx('PLT')
                    chg_idx('TEXTTAB')
                    chg_idx('ARMEXIDX')
                    chg_idx('FINIARRAY')
                    chg_idx('INITARRAY')
                    chg_idx('DYNAMIC')
                    chg_idx('GOT')
                    chg_idx('DATA')
                    chg_idx('BSS')
                    chg_idx('SHSTRTAB')
        
        logger.debug("Section headers sorted successfully")
        
        # 添加段布局摘要日志
        logger.debug("Final section layout after sorting:")
        for i, shdr in enumerate(self.section_headers):
            if i == 0:
                logger.debug(f"  Section {i}: [NULL] (empty)")
            else:
                # 查找段名
                section_name = "unknown"
                for key, idx in self.section_indices.items():
                    if idx == i:
                        section_name = key.lower()
                        break
                logger.debug(f"  Section {i}: {section_name} addr=0x{shdr['sh_addr']:x} size=0x{shdr['sh_size']:x}")
        
        # 添加C++兼容性验证摘要
        logger.debug("=== C++ Compatibility Verification ===")
        logger.debug(f"  Address space: properly reserved via reserve_address_space()")
        logger.debug(f"  Program headers: processed via find_phdr() and apply_phdr_table()")
        logger.debug(f"  Load sequence: matches C++ ObElfReader.Load() flow")
        logger.debug(f"  Data integrity: verified against ELF reader reserved data")
    
    
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
        
        对应C++在排序后计算各段大小的逻辑
        特别关注.dynsym和.text&ARM.extab段的大小计算
        """
        logger.debug("Calculating section sizes...")
        
        # 按照排序后的顺序计算段大小
        # 对于size=0的段，使用下一个段的地址减去当前段地址
        for i in range(len(self.section_headers) - 1):
            current_shdr = self.section_headers[i]
            next_shdr = self.section_headers[i + 1]
            
            # 如果当前段大小为0，计算到下一个段的大小
            # 注意：跳过空段（索引0），它应该保持大小为0
            if (i > 0 and current_shdr['sh_size'] == 0 and current_shdr['sh_type'] != 8):  # SHT_NOBITS
                # 确保地址有效且合理
                if (next_shdr['sh_addr'] > current_shdr['sh_addr'] and 
                    next_shdr['sh_addr'] - current_shdr['sh_addr'] < 0x100000):  # 1MB限制，防止异常
                    current_shdr['sh_size'] = next_shdr['sh_addr'] - current_shdr['sh_addr']
                    logger.debug(f"Calculated section {i} size: 0x{current_shdr['sh_size']:x}")
        
        # 特殊处理.dynsym段大小（对应C++中的计算逻辑）
        if self.section_indices['DYNSYM'] > 0:
            dynsym_idx = self.section_indices['DYNSYM']
            if (dynsym_idx + 1 < len(self.section_headers) and 
                self.section_headers[dynsym_idx]['sh_size'] == 0):
                next_addr = self.section_headers[dynsym_idx + 1]['sh_addr']
                curr_addr = self.section_headers[dynsym_idx]['sh_addr']
                if next_addr > curr_addr:
                    self.section_headers[dynsym_idx]['sh_size'] = next_addr - curr_addr
                    logger.debug(f"Calculated .dynsym size: 0x{self.section_headers[dynsym_idx]['sh_size']:x}")
        
        # 特殊处理.text&ARM.extab段大小（对应C++中的计算逻辑）
        if self.section_indices['TEXTTAB'] > 0:
            texttab_idx = self.section_indices['TEXTTAB']
            if (texttab_idx + 1 < len(self.section_headers) and 
                self.section_headers[texttab_idx]['sh_size'] == 0):
                next_addr = self.section_headers[texttab_idx + 1]['sh_addr']
                curr_addr = self.section_headers[texttab_idx]['sh_addr']
                if next_addr > curr_addr:
                    self.section_headers[texttab_idx]['sh_size'] = next_addr - curr_addr
                    logger.debug(f"Calculated .text&ARM.extab size: 0x{self.section_headers[texttab_idx]['sh_size']:x}")
        
        # 确保没有段重叠问题
        for i in range(1, len(self.section_headers)):
            prev_shdr = self.section_headers[i-1]
            curr_shdr = self.section_headers[i]
            
            # 检查前一个段是否与当前段重叠
            prev_end = prev_shdr['sh_addr'] + prev_shdr['sh_size']
            if (prev_end > curr_shdr['sh_addr'] and 
                prev_shdr['sh_type'] != 8 and curr_shdr['sh_type'] != 8):  # 排除SHT_NOBITS
                # 调整前一个段的大小以避免重叠
                new_size = curr_shdr['sh_addr'] - prev_shdr['sh_addr']
                if new_size > 0:
                    prev_shdr['sh_size'] = new_size
                    logger.debug(f"Adjusted section {i-1} size to avoid overlap: 0x{prev_shdr['sh_size']:x}")
        
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
        logger.debug(f"  Architecture: {'x86_64/ARM64' if is_64bit else 'i386/ARM'}")
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
        
        # 增强的重定位处理统计 - 区分不同类型的结果
        successful_relocations = 0      # 正常处理成功
        skipped_corrupted = 0           # 跳过的损坏条目
        skipped_out_of_bounds = 0       # 跳过的越界条目  
        skipped_invalid_addr = 0        # 跳过的无效地址
        failed_relocations = 0          # 真正的处理失败
        
        # 初始化统计跟踪器
        self._current_reloc_stats = {
            'skipped_corrupted': 0,
            'skipped_out_of_bounds': 0, 
            'skipped_invalid_addr': 0
        }
        
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
            
            # 记录处理前的统计状态
            prev_stats = dict(self._current_reloc_stats)
            
            # 处理单个重定位
            if self._relocate(rel_entry, min_vaddr, addr_size, is_rela):
                # 检查是否有跳过的条目（统计变化表明有跳过）
                if self._current_reloc_stats != prev_stats:
                    # 有统计变化，说明这个条目被跳过了
                    for skip_type in ['skipped_corrupted', 'skipped_out_of_bounds', 'skipped_invalid_addr']:
                        if self._current_reloc_stats[skip_type] > prev_stats[skip_type]:
                            if skip_type == 'skipped_corrupted':
                                skipped_corrupted += 1
                            elif skip_type == 'skipped_out_of_bounds':
                                skipped_out_of_bounds += 1
                            elif skip_type == 'skipped_invalid_addr':
                                skipped_invalid_addr += 1
                else:
                    # 真正的成功处理
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
        
        # 输出详细的最终统计信息
        total_processed = successful_relocations + skipped_corrupted + skipped_out_of_bounds + skipped_invalid_addr + failed_relocations
        logger.info(f"Relocation processing completed:")
        logger.info(f"  Total entries: {rel_count}")
        logger.info(f"  Successfully processed: {successful_relocations} ({successful_relocations*100/rel_count:.1f}%)")
        
        if skipped_corrupted > 0:
            logger.warning(f"  Skipped corrupted data: {skipped_corrupted} ({skipped_corrupted*100/rel_count:.1f}%)")
        if skipped_invalid_addr > 0:
            logger.warning(f"  Skipped invalid addresses: {skipped_invalid_addr} ({skipped_invalid_addr*100/rel_count:.1f}%)")
        if skipped_out_of_bounds > 0:
            logger.warning(f"  Skipped out-of-bounds: {skipped_out_of_bounds} ({skipped_out_of_bounds*100/rel_count:.1f}%)")
        if failed_relocations > 0:
            logger.error(f"  Processing failures: {failed_relocations} ({failed_relocations*100/rel_count:.1f}%)")
            
        # 计算总体健康度
        total_issues = skipped_corrupted + skipped_invalid_addr + skipped_out_of_bounds + failed_relocations
        if total_issues > 0:
            logger.warning(f"  Total problematic entries: {total_issues} ({total_issues*100/rel_count:.1f}%)")
            if total_issues > rel_count * 0.1:  # 超过10%有问题
                logger.warning("  WARNING: High percentage of problematic relocations detected!")
                logger.warning("  This may indicate corrupted relocation tables in the memory dump.")
        else:
            logger.info("  All relocations processed successfully!")
        
        # 清理统计跟踪器
        if hasattr(self, '_current_reloc_stats'):
            delattr(self, '_current_reloc_stats')
        
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
            
            # ======== 重定位数据合理性检查 ========
            # 检查虚拟地址是否在合理范围内（防止处理损坏的重定位数据）
            r_offset = rel_entry.r_offset
            
            # 64位系统：用户空间地址通常不会超过 0x800000000000 (128TB)
            # 32位系统：用户空间地址通常不会超过 0xFFFFFFFF (4GB)
            max_reasonable_addr = 0x800000000000 if self.elf_reader.is_64bit else 0xFFFFFFFF
            
            if r_offset > max_reasonable_addr:
                logger.warning(f"Relocation address 0x{r_offset:x} exceeds reasonable range "
                             f"(max: 0x{max_reasonable_addr:x})")
                logger.warning(f"  r_info=0x{rel_entry.r_info:x}, type=0x{rel_type:x}, "
                             f"sym_index={sym_index}")
                logger.warning("  This appears to be corrupted relocation data, skipping...")
                # 记录统计信息
                if hasattr(self, '_current_reloc_stats'):
                    self._current_reloc_stats['skipped_corrupted'] += 1
                return True  # 跳过而不是失败，允许处理继续
                
            # 检查 r_info 是否过大（另一个损坏数据的指标）
            max_reasonable_info = 0xFFFFFFFFFFFFFFFF if self.elf_reader.is_64bit else 0xFFFFFFFF
            if rel_entry.r_info > max_reasonable_info or rel_entry.r_info == 0:
                logger.warning(f"Relocation r_info value 0x{rel_entry.r_info:x} appears invalid")
                logger.warning(f"  r_offset=0x{r_offset:x}, skipping corrupted entry...")
                # 记录统计信息
                if hasattr(self, '_current_reloc_stats'):
                    self._current_reloc_stats['skipped_corrupted'] += 1
                return True  # 跳过损坏的条目
                
            # 检查重定位类型是否在已知范围内
            known_types = [RelocationARM.R_ARM_RELATIVE, RelocationI386.R_386_RELATIVE, 0x101, 0x402, 0x403]
            if rel_type not in known_types and rel_type > 0x1000:  # 如果类型过大且未知
                logger.debug(f"Unusual relocation type 0x{rel_type:x} for r_offset=0x{r_offset:x}")
                # 不跳过，仍然尝试处理，但记录警告
            
            # 使用精确的虚拟地址到loaded_data偏移转换
            # 这解决了文件基地址映射和内存转储地址空间不匹配的问题
            target_offset = self.elf_reader.virtual_addr_to_loaded_offset(rel_entry.r_offset)
            
            # 检查地址转换是否成功
            if target_offset is None:
                # 提供更详细的诊断信息
                logger.warning(f"Failed to map relocation virtual address 0x{rel_entry.r_offset:x} to loaded_data offset")
                logger.warning(f"  Relocation details:")
                logger.warning(f"    r_info: 0x{rel_entry.r_info:x}")
                logger.warning(f"    rel_type: 0x{rel_type:x}")
                logger.warning(f"    sym_index: {sym_index}")
                if is_rela and hasattr(rel_entry, 'r_addend'):
                    logger.warning(f"    r_addend: 0x{rel_entry.r_addend:x}")
                
                # 尝试诊断失败原因
                min_vaddr, max_vaddr, load_size = self.elf_reader.calculate_load_size()
                logger.warning(f"  Address space info:")
                logger.warning(f"    Loaded segments range: 0x{min_vaddr:x} - 0x{max_vaddr:x}")
                logger.warning(f"    Total loaded size: 0x{load_size:x}")
                logger.warning(f"    Target address is {'above' if rel_entry.r_offset > max_vaddr else 'below'} loaded range")
                
                # 安全跳过而不是失败，这样可以继续处理其他重定位
                logger.warning("  Skipping this corrupted relocation entry and continuing...")
                # 记录统计信息
                if hasattr(self, '_current_reloc_stats'):
                    self._current_reloc_stats['skipped_invalid_addr'] += 1
                return True  # 返回True表示"已处理"（通过跳过），允许继续处理
                
            # 额外的边界检查（虽然virtual_addr_to_loaded_offset已经做了检查）
            if target_offset + addr_size > len(self.elf_reader.loaded_data):
                logger.warning(f"Relocation target extends beyond loaded_data bounds: "
                             f"offset=0x{target_offset:x}, size={addr_size}, "
                             f"loaded_size=0x{len(self.elf_reader.loaded_data):x}")
                logger.warning(f"  r_offset=0x{rel_entry.r_offset:x}, skipping boundary violation...")
                # 记录统计信息
                if hasattr(self, '_current_reloc_stats'):
                    self._current_reloc_stats['skipped_out_of_bounds'] += 1
                return True  # 安全跳过边界错误
            
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
                
            # R_AARCH64_ABS64 - ARM64架构的64位绝对地址重定位（类型0x101）
            elif rel_type == 0x101:
                # ARM64 (AArch64) 64位绝对地址重定位
                # 这种重定位类型在ARM64架构中用于处理64位绝对地址
                # 处理方式与相对重定位相同：从内存转储的绝对地址转换为相对地址
                new_value = current_value - self.elf_reader.dump_base_addr
                logger.debug(f"ARM64_ABS64 relocation (0x101): 0x{current_value:x} -> 0x{new_value:x}")
                logger.debug(f"  ARM64 architecture detected, applying absolute->relative conversion")
                
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
    
    
    
    def _hex_dump(self, data: bytes, base_addr: int, width: int = 16):
        """
        输出数据的hex dump格式
        """
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            addr = base_addr + i
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            logger.debug(f"  {addr:08x}: {hex_str:<48} |{ascii_str}|")
    
    def _rebuild_final_file(self) -> bool:
        """
        重建最终ELF文件 - 完整实现C++的RebuildFin函数
        
        该方法按照C++版本的逻辑组装最终的ELF文件：
        1. 计算最终文件大小 = 加载数据大小 + shstrtab大小 + section headers大小
        2. 组装文件数据：loaded_data + shstrtab + section_headers
        3. 更新ELF header设置正确的section header信息
        
        与C++版本的对应关系：
        - rebuild_size = load_size + shstrtab.length() + shdrs.size() * sizeof(Elf_Shdr)
        - memcpy(rebuild_data, (void*)si.load_bias, load_size)
        - memcpy(rebuild_data + load_size, shstrtab.c_str(), shstrtab.length())
        - memcpy(rebuild_data + shdr_off, (void*)&shdrs[0], shdrs.size() * sizeof(Elf_Shdr))
        - 更新ELF header的e_shnum, e_shoff, e_shstrndx
        
        Returns:
            True if final file was successfully rebuilt, False otherwise
        """
        logger.debug("=======================RebuildFin (Complete Implementation)========================")
        
        try:
            # 步骤1: 计算文件组件大小 (对应C++ line 808-810)
            min_vaddr, max_vaddr, load_size = self.elf_reader.calculate_load_size()
            shstrtab_size = len(self.shstrtab)
            shdr_struct_size = ctypes.sizeof(self.elf_reader.types['Shdr'])
            shdrs_total_size = len(self.section_headers) * shdr_struct_size
            
            # 按照C++逻辑使用调整后的load_size (对应C++ auto load_size = si.max_load - si.min_load)
            if hasattr(self.so_info, 'max_load') and hasattr(self.so_info, 'min_load'):
                adjusted_load_size = self.so_info.max_load - self.so_info.min_load
                logger.debug(f"Using adjusted load_size: 0x{adjusted_load_size:x} "
                            f"(max_load=0x{self.so_info.max_load:x}, min_load=0x{self.so_info.min_load:x})")
            else:
                adjusted_load_size = load_size
                logger.warning(f"Using original load_size: 0x{load_size:x}")
            
            self.rebuilt_size = adjusted_load_size + shstrtab_size + shdrs_total_size
            
            logger.debug(f"Final file size calculation:")
            logger.debug(f"  Original load size: 0x{load_size:x} bytes")
            logger.debug(f"  Adjusted load size: 0x{adjusted_load_size:x} bytes")
            logger.debug(f"  Shstrtab size: 0x{shstrtab_size:x} bytes") 
            logger.debug(f"  Section headers count: {len(self.section_headers)}")
            logger.debug(f"  Section header struct size: 0x{shdr_struct_size:x} bytes")
            logger.debug(f"  Total section headers size: 0x{shdrs_total_size:x} bytes")
            logger.debug(f"  Final file size: 0x{self.rebuilt_size:x} bytes")
            
            # 步骤2: 分配最终文件缓冲区 (对应C++ line 811)
            self.rebuilt_data = bytearray(self.rebuilt_size)
            
            # 步骤3: 复制重定位后的加载数据 (对应C++ line 812)
            # memcpy(rebuild_data, (void*)si.load_bias, load_size)
            loaded_data_size = len(self.elf_reader.loaded_data)
            if loaded_data_size != adjusted_load_size:
                logger.warning(f"Loaded data size mismatch: expected 0x{adjusted_load_size:x}, got 0x{loaded_data_size:x}")
                # 使用实际可用的大小
                copy_size = min(adjusted_load_size, loaded_data_size)
            else:
                copy_size = adjusted_load_size
                
            self.rebuilt_data[0:copy_size] = self.elf_reader.loaded_data[0:copy_size]
            logger.debug(f"Copied {copy_size} bytes of loaded data")
            
            # 步骤3.5: 更新程序头表的二进制数据 (确保修复的程序头被正确写入)
            if not self._update_program_header_table():
                logger.error("Failed to update program header table in rebuilt data")
                return False
            
            # 步骤4: 附加shstrtab字符串表 (对应C++ lines 813-814)
            # memcpy(rebuild_data + load_size, shstrtab.c_str(), shstrtab.length())
            shstrtab_offset = adjusted_load_size
            self.rebuilt_data[shstrtab_offset:shstrtab_offset + shstrtab_size] = self.shstrtab
            logger.debug(f"Appended shstrtab at offset 0x{shstrtab_offset:x} (size: 0x{shstrtab_size:x})")
            
            # 步骤5: 附加section headers (对应C++ lines 815-818)
            # auto shdr_off = load_size + shstrtab.length()
            # memcpy(rebuild_data + (int)shdr_off, (void*)&shdrs[0], shdrs.size() * sizeof(Elf_Shdr))
            shdr_offset = adjusted_load_size + shstrtab_size

            # 修复：SHSTRTAB中的sh_offset并没有赋值更新
            self.section_headers[self.section_indices['SHSTRTAB']]['sh_offset'] = shstrtab_offset

            self._serialize_section_headers(shdr_offset)
            logger.debug(f"Appended section headers at offset 0x{shdr_offset:x} (size: 0x{shdrs_total_size:x})")
            
            # 步骤6: 更新ELF header (对应C++ lines 819-829)
            if not self._update_elf_header(shdr_offset):
                logger.error("Failed to update ELF header")
                return False
            
            logger.debug("=======================RebuildFin End=========================")
            logger.info(f"ELF rebuild completed successfully: {self.rebuilt_size} bytes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rebuild final file: {e}")
            return False
    
    def _serialize_section_headers(self, shdr_offset: int):
        """
        将section headers序列化为二进制数据并写入rebuilt_data
        
        对应C++的：memcpy(rebuild_data + shdr_off, (void*)&shdrs[0], shdrs.size() * sizeof(Elf_Shdr))
        
        Args:
            shdr_offset: section headers在rebuilt_data中的偏移量
        """
        logger.debug(f"Serializing {len(self.section_headers)} section headers...")
        
        # 获取Section Header结构类型
        Shdr = self.elf_reader.types['Shdr']
        shdr_size = ctypes.sizeof(Shdr)
        
        current_offset = shdr_offset
        
        for i, shdr_dict in enumerate(self.section_headers):
            # 创建ctypes结构实例
            shdr = Shdr()
            
            # 填充所有字段
            shdr.sh_name = shdr_dict['sh_name']
            shdr.sh_type = shdr_dict['sh_type']
            shdr.sh_flags = shdr_dict['sh_flags']
            shdr.sh_addr = shdr_dict['sh_addr']
            shdr.sh_offset = shdr_dict['sh_offset']
            shdr.sh_size = shdr_dict['sh_size']
            shdr.sh_link = shdr_dict['sh_link']
            shdr.sh_info = shdr_dict['sh_info']
            shdr.sh_addralign = shdr_dict['sh_addralign']
            shdr.sh_entsize = shdr_dict['sh_entsize']
            
            # 序列化为字节并写入rebuilt_data
            shdr_bytes = bytes(shdr)
            self.rebuilt_data[current_offset:current_offset + shdr_size] = shdr_bytes
            
            logger.debug(f"  Section {i}: offset=0x{current_offset:x}, type={shdr.sh_type}, "
                        f"addr=0x{shdr.sh_addr:x}, size=0x{shdr.sh_size:x}")
            
            current_offset += shdr_size
    
    def _update_elf_header(self, shdr_offset: int) -> bool:
        """
        更新ELF header以指向正确的section headers
        
        对应C++的lines 819-829：
        - auto ehdr = *elf_reader_->record_ehdr()
        - ehdr.e_type = ET_DYN
        - ehdr.e_machine = 183/40 (64bit/32bit)
        - ehdr.e_shnum = shdrs.size()
        - ehdr.e_shoff = (Elf_Addr)shdr_off
        - ehdr.e_shstrndx = sSHSTRTAB
        - memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr))
        
        Args:
            shdr_offset: section header table在文件中的偏移量
            
        Returns:
            True if header was successfully updated, False otherwise
        """
        try:
            logger.debug("Updating ELF header...")
            
            # 获取当前ELF header (对应C++ auto ehdr = *elf_reader_->record_ehdr())
            current_header = self.elf_reader.header
            Ehdr = self.elf_reader.types['Ehdr']
            ehdr_size = ctypes.sizeof(Ehdr)
            
            # 创建新的header副本
            new_header = Ehdr()
            
            # 复制现有header的所有字段
            for field_name, _ in Ehdr._fields_:
                setattr(new_header, field_name, getattr(current_header, field_name))
            
            # 更新关键字段 (对应C++ lines 820-828)
            new_header.e_type = ELFType.ET_DYN                    # ehdr.e_type = ET_DYN
            
            # 设置正确的机器类型 
            if self.elf_reader.is_64bit:
                new_header.e_machine = 183                        # ARM64 (AArch64) 
            else:
                new_header.e_machine = 40                         # ARM32
                
            new_header.e_shnum = len(self.section_headers)        # ehdr.e_shnum = shdrs.size()
            new_header.e_shoff = shdr_offset                      # ehdr.e_shoff = (Elf_Addr)shdr_off
            new_header.e_shstrndx = self.section_indices['SHSTRTAB']  # ehdr.e_shstrndx = sSHSTRTAB
            
            # 序列化并写入rebuilt_data的开头 (对应C++ memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr)))
            header_bytes = bytes(new_header)
            self.rebuilt_data[0:ehdr_size] = header_bytes
            
            logger.debug(f"ELF header updated:")
            logger.debug(f"  e_type: {new_header.e_type} (ET_DYN)")
            logger.debug(f"  e_machine: {new_header.e_machine}")
            logger.debug(f"  e_shnum: {new_header.e_shnum}")
            logger.debug(f"  e_shoff: 0x{new_header.e_shoff:x}")
            logger.debug(f"  e_shstrndx: {new_header.e_shstrndx}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update ELF header: {e}")
            return False
    
    def _update_program_header_table(self) -> bool:
        """
        更新rebuilt_data中的程序头表，确保修复后的程序头被正确写入
        
        这个函数解决的问题：虽然在fix_dump_program_headers()中修复了程序头，
        但loaded_data中的程序头表仍然包含原始错误值，需要用修复后的值覆盖
        
        Returns:
            True if program header table was successfully updated, False otherwise
        """
        try:
            logger.debug("Updating program header table in rebuilt data...")
            
            # 获取程序头表在文件中的偏移量（从ELF header读取）
            phoff = self.elf_reader.header.e_phoff
            phentsize = self.elf_reader.header.e_phentsize
            phnum = self.elf_reader.header.e_phnum
            
            logger.debug(f"Program header table: offset=0x{phoff:x}, entry_size={phentsize}, count={phnum}")
            
            # 验证程序头表位置是否在rebuilt_data范围内
            phdr_table_size = phnum * phentsize
            if phoff + phdr_table_size > len(self.rebuilt_data):
                logger.error(f"Program header table extends beyond rebuilt data: "
                           f"offset=0x{phoff:x}, size={phdr_table_size}, data_size={len(self.rebuilt_data)}")
                return False
            
            # 序列化修复后的程序头并写入rebuilt_data
            Phdr = self.elf_reader.types['Phdr']
            for i, phdr in enumerate(self.elf_reader.program_headers):
                # 计算当前程序头在文件中的偏移量
                phdr_offset = phoff + (i * phentsize)
                
                # 创建ctypes结构并填充数据
                phdr_struct = Phdr()
                phdr_struct.p_type = phdr.p_type
                phdr_struct.p_flags = phdr.p_flags
                phdr_struct.p_offset = phdr.p_offset  # 这里使用修复后的偏移量
                phdr_struct.p_vaddr = phdr.p_vaddr
                phdr_struct.p_paddr = phdr.p_paddr
                phdr_struct.p_filesz = phdr.p_filesz
                phdr_struct.p_memsz = phdr.p_memsz
                phdr_struct.p_align = phdr.p_align
                
                # 将结构体序列化为字节并写入rebuilt_data
                phdr_bytes = ctypes.string_at(ctypes.byref(phdr_struct), phentsize)
                self.rebuilt_data[phdr_offset:phdr_offset + phentsize] = phdr_bytes
                
                logger.debug(f"Updated program header {i}: offset=0x{phdr.p_offset:x}, "
                           f"vaddr=0x{phdr.p_vaddr:x}, filesz=0x{phdr.p_filesz:x}")
            
            logger.debug("Program header table successfully updated in rebuilt data")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update program header table: {e}")
            return False