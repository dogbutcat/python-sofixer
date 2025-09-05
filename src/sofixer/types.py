import ctypes
from enum import IntEnum

# =============================================================================
# ELF Constants and Enums
# =============================================================================

class ELFClass(IntEnum):
    """ELF file class constants"""
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2


class ELFData(IntEnum):
    """ELF data encoding constants"""
    ELFDATANONE = 0
    ELFDATA2LSB = 1  # Little endian
    ELFDATA2MSB = 2  # Big endian


class ELFType(IntEnum):
    """ELF file type constants"""
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4


class SegmentType(IntEnum):
    """Program header segment type constants"""
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7
    PT_ARM_EXIDX = 0x70000001


class SectionType(IntEnum):
    """Section header type constants"""
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_INIT_ARRAY = 14        # Array of constructors
    SHT_FINI_ARRAY = 15        # Array of destructors
    SHT_ARMEXIDX = 0x70000001  # ARM exception index table


class DynamicTag(IntEnum):
    """Dynamic section tag constants - complete list from elf.h"""
    # Standard DT_ constants (0-34)
    DT_NULL = 0         # Marks end of dynamic section
    DT_NEEDED = 1       # Name of needed library
    DT_PLTRELSZ = 2     # Size in bytes of PLT relocs
    DT_PLTGOT = 3       # Processor defined value
    DT_HASH = 4         # Address of symbol hash table
    DT_STRTAB = 5       # Address of string table
    DT_SYMTAB = 6       # Address of symbol table
    DT_RELA = 7         # Address of Rela relocs
    DT_RELASZ = 8       # Total size of Rela relocs
    DT_RELAENT = 9      # Size of one Rela reloc
    DT_STRSZ = 10       # Size of string table
    DT_SYMENT = 11      # Size of one symbol table entry
    DT_INIT = 12        # Address of init function
    DT_FINI = 13        # Address of termination function
    DT_SONAME = 14      # Name of shared object
    DT_RPATH = 15       # Library search path (deprecated)
    DT_SYMBOLIC = 16    # Start symbol search here
    DT_REL = 17         # Address of Rel relocs
    DT_RELSZ = 18       # Total size of Rel relocs
    DT_RELENT = 19      # Size of one Rel reloc
    DT_PLTREL = 20      # Type of reloc in PLT
    DT_DEBUG = 21       # For debugging; unspecified
    DT_TEXTREL = 22     # Reloc might modify .text
    DT_JMPREL = 23      # Address of PLT relocs
    DT_BIND_NOW = 24    # Process relocations of object
    DT_INIT_ARRAY = 25  # Array with addresses of init fct
    DT_FINI_ARRAY = 26  # Array with addresses of fini fct
    DT_INIT_ARRAYSZ = 27  # Size in bytes of DT_INIT_ARRAY
    DT_FINI_ARRAYSZ = 28  # Size in bytes of DT_FINI_ARRAY
    DT_RUNPATH = 29     # Library search path
    DT_FLAGS = 30       # Flags for the object being loaded
    DT_ENCODING = 32    # Start of encoded range
    DT_PREINIT_ARRAY = 32   # Array with addresses of preinit fct
    DT_PREINIT_ARRAYSZ = 33 # Size in bytes of DT_PREINIT_ARRAY
    DT_NUM = 34         # Number used
    
    # OS/Processor specific ranges
    DT_LOOS = 0x60000000        # Start of OS-specific
    DT_HIOS = 0x6fffffff        # End of OS-specific
    DT_LOPROC = 0x70000000      # Start of processor-specific
    DT_HIPROC = 0x7fffffff      # End of processor-specific
    
    # GNU extensions (VALRNG)
    DT_VALRNGLO = 0x6ffffd00
    DT_GNU_PRELINKED = 0x6ffffdf5   # Prelinking timestamp
    DT_GNU_CONFLICTSZ = 0x6ffffdf6  # Size of conflict section
    DT_GNU_LIBLISTSZ = 0x6ffffdf7   # Size of library list
    DT_CHECKSUM = 0x6ffffdf8
    DT_PLTPADSZ = 0x6ffffdf9
    DT_MOVEENT = 0x6ffffdfa
    DT_MOVESZ = 0x6ffffdfb
    DT_FEATURE_1 = 0x6ffffdfc       # Feature selection (DTF_*)
    DT_POSFLAG_1 = 0x6ffffdfd       # Flags for DT_* entries
    DT_SYMINSZ = 0x6ffffdfe         # Size of syminfo table (in bytes)
    DT_SYMINENT = 0x6ffffdff        # Entry size of syminfo
    DT_VALRNGHI = 0x6ffffdff
    
    # GNU extensions (ADDRRNG)
    DT_ADDRRNGLO = 0x6ffffe00
    DT_GNU_CONFLICT = 0x6ffffef8    # Start of conflict section
    DT_GNU_LIBLIST = 0x6ffffef9     # Library list
    DT_CONFIG = 0x6ffffefa          # Configuration information
    DT_DEPAUDIT = 0x6ffffefb        # Dependency auditing
    DT_AUDIT = 0x6ffffefc           # Object auditing
    DT_PLTPAD = 0x6ffffefd          # PLT padding
    DT_MOVETAB = 0x6ffffefe         # Move table
    DT_SYMINFO = 0x6ffffeff         # Syminfo table
    DT_ADDRRNGHI = 0x6ffffeff
    
    # Version-related constants
    DT_VERSYM = 0x6ffffff0
    DT_RELACOUNT = 0x6ffffff9
    DT_RELCOUNT = 0x6ffffffa
    DT_FLAGS_1 = 0x6ffffffb         # State flags, see DF_1_* below
    DT_VERDEF = 0x6ffffffc          # Address of version definition table
    DT_VERDEFNUM = 0x6ffffffd       # Number of version definitions
    DT_VERNEED = 0x6ffffffe         # Address of table with needed versions
    DT_VERNEEDNUM = 0x6fffffff      # Number of needed versions
    
    # MIPS processor-specific extensions (在LOPROC-HIPROC范围内)
    DT_MIPS_RLD_VERSION = 0x70000001    # Runtime linker interface version
    DT_MIPS_FLAGS = 0x70000005          # Flags
    DT_MIPS_BASE_ADDRESS = 0x70000006   # Base address of segment
    DT_MIPS_LOCAL_GOTNO = 0x7000000a    # Number of local GOT entries
    DT_MIPS_SYMTABNO = 0x70000011       # Number of DYNSYM entries
    DT_MIPS_UNREFEXTNO = 0x70000012     # First external DYNSYM
    DT_MIPS_GOTSYM = 0x70000013         # First GOT entry in DYNSYM
    DT_MIPS_RLD_MAP = 0x70000016        # Address of run time loader map
    
    # Sun extensions
    DT_AUXILIARY = 0x7ffffffd       # Shared object to load before self
    DT_FILTER = 0x7fffffff          # Shared object to get values from


class RelocationARM(IntEnum):
    """ARM架构重定位类型常量"""
    R_ARM_NONE = 0                  # No relocation
    R_ARM_PC24 = 1                  # PC relative 26 bit branch
    R_ARM_ABS32 = 2                 # Direct 32 bit
    R_ARM_REL32 = 3                 # PC relative 32 bit
    R_ARM_GLOB_DAT = 21             # 32 bit GOT entry
    R_ARM_JUMP_SLOT = 22            # 32 bit PLT address
    R_ARM_RELATIVE = 23             # Adjust by program base
    R_ARM_GOTOFF = 24               # 32 bit offset to GOT
    R_ARM_GOTPC = 25                # 32 bit PC relative offset to GOT
    R_ARM_GOT32 = 26                # 32 bit GOT entry
    R_ARM_PLT32 = 27                # 32 bit PLT address


class RelocationI386(IntEnum):
    """x86/i386架构重定位类型常量"""
    R_386_NONE = 0                  # No relocation
    R_386_32 = 1                    # Direct 32 bit
    R_386_PC32 = 2                  # PC relative 32 bit
    R_386_GOT32 = 3                 # 32 bit GOT entry
    R_386_PLT32 = 4                 # 32 bit PLT address
    R_386_COPY = 5                  # Copy symbol at runtime
    R_386_GLOB_DAT = 6              # 32 bit GOT entry
    R_386_JMP_SLOT = 7              # 32 bit PLT address
    R_386_RELATIVE = 8              # Adjust by program base
    R_386_GOTOFF = 9                # 32 bit offset to GOT
    R_386_GOTPC = 10                # 32 bit PC relative offset to GOT


class RelocationX86_64(IntEnum):
    """x86-64架构重定位类型常量"""
    R_X86_64_NONE = 0               # No relocation
    R_X86_64_64 = 1                 # Direct 64 bit
    R_X86_64_PC32 = 2               # PC relative 32 bit signed
    R_X86_64_GOT32 = 3              # 32 bit GOT entry
    R_X86_64_PLT32 = 4              # 32 bit PLT address
    R_X86_64_COPY = 5               # Copy symbol at runtime
    R_X86_64_GLOB_DAT = 6           # 64 bit GOT entry
    R_X86_64_JUMP_SLOT = 7          # 64 bit PLT address
    R_X86_64_RELATIVE = 8           # Adjust by program base
    R_X86_64_GOTPCREL = 9           # 32 bit signed PC relative offset to GOT


class SegmentFlags(IntEnum):
    """Program header segment flags"""
    PF_X = 1  # Execute
    PF_W = 2  # Write
    PF_R = 4  # Read


# =============================================================================
# ctypes Type Definitions (matching elf.h exactly)
# =============================================================================

# Basic ELF types
Elf32_Addr = ctypes.c_uint32
Elf32_Off = ctypes.c_uint32
Elf32_Word = ctypes.c_uint32
Elf32_Sword = ctypes.c_int32
Elf32_Half = ctypes.c_uint16
Elf32_Xword = ctypes.c_uint64

Elf64_Addr = ctypes.c_uint64
Elf64_Off = ctypes.c_uint64
Elf64_Word = ctypes.c_uint32
Elf64_Sword = ctypes.c_int32
Elf64_Half = ctypes.c_uint32
Elf64_Quarter = ctypes.c_uint16
Elf64_Xword = ctypes.c_uint64
Elf64_Sxword = ctypes.c_int64


# =============================================================================
# ELF Header Structures
# =============================================================================

class Elf32_Ehdr(ctypes.Structure):
    """32-bit ELF header structure"""
    _fields_ = [
        ('e_ident', ctypes.c_uint8 * 16),  # Magic number and other info
        ('e_type', Elf32_Half),            # Object file type
        ('e_machine', Elf32_Half),         # Architecture
        ('e_version', Elf32_Word),         # Object file version
        ('e_entry', Elf32_Addr),           # Entry point virtual address
        ('e_phoff', Elf32_Off),            # Program header table file offset
        ('e_shoff', Elf32_Off),            # Section header table file offset
        ('e_flags', Elf32_Word),           # Processor-specific flags
        ('e_ehsize', Elf32_Half),          # ELF header size in bytes
        ('e_phentsize', Elf32_Half),       # Program header table entry size
        ('e_phnum', Elf32_Half),           # Program header table entry count
        ('e_shentsize', Elf32_Half),       # Section header table entry size
        ('e_shnum', Elf32_Half),           # Section header table entry count
        ('e_shstrndx', Elf32_Half),        # Section header string table index
    ]


class Elf64_Ehdr(ctypes.Structure):
    """64-bit ELF header structure"""
    _fields_ = [
        ('e_ident', ctypes.c_uint8 * 16),  # Magic number and other info
        ('e_type', Elf64_Quarter),         # Object file type
        ('e_machine', Elf64_Quarter),      # Architecture
        ('e_version', Elf64_Half),         # Object file version
        ('e_entry', Elf64_Addr),           # Entry point virtual address
        ('e_phoff', Elf64_Off),            # Program header table file offset
        ('e_shoff', Elf64_Off),            # Section header table file offset
        ('e_flags', Elf64_Half),           # Processor-specific flags
        ('e_ehsize', Elf64_Quarter),       # ELF header size in bytes
        ('e_phentsize', Elf64_Quarter),    # Program header table entry size
        ('e_phnum', Elf64_Quarter),        # Program header table entry count
        ('e_shentsize', Elf64_Quarter),    # Section header table entry size
        ('e_shnum', Elf64_Quarter),        # Section header table entry count
        ('e_shstrndx', Elf64_Quarter),     # Section header string table index
    ]


# =============================================================================
# Program Header Structures
# =============================================================================

class Elf32_Phdr(ctypes.Structure):
    """32-bit program header structure"""
    _fields_ = [
        ('p_type', Elf32_Word),     # Segment type
        ('p_offset', Elf32_Off),    # Segment file offset
        ('p_vaddr', Elf32_Addr),    # Segment virtual address
        ('p_paddr', Elf32_Addr),    # Segment physical address
        ('p_filesz', Elf32_Word),   # Segment size in file
        ('p_memsz', Elf32_Word),    # Segment size in memory
        ('p_flags', Elf32_Word),    # Segment flags
        ('p_align', Elf32_Word),    # Segment alignment
    ]


class Elf64_Phdr(ctypes.Structure):
    """64-bit program header structure"""
    _fields_ = [
        ('p_type', Elf64_Half),     # Segment type
        ('p_flags', Elf64_Half),    # Segment flags
        ('p_offset', Elf64_Off),    # Segment file offset
        ('p_vaddr', Elf64_Addr),    # Segment virtual address
        ('p_paddr', Elf64_Addr),    # Segment physical address
        ('p_filesz', Elf64_Xword),  # Segment size in file
        ('p_memsz', Elf64_Xword),   # Segment size in memory
        ('p_align', Elf64_Xword),   # Segment alignment
    ]


# =============================================================================
# Section Header Structures
# =============================================================================

class Elf32_Shdr(ctypes.Structure):
    """32-bit section header structure"""
    _fields_ = [
        ('sh_name', Elf32_Word),      # Section name (string table index)
        ('sh_type', Elf32_Word),      # Section type
        ('sh_flags', Elf32_Word),     # Section flags
        ('sh_addr', Elf32_Addr),      # Section virtual addr at execution
        ('sh_offset', Elf32_Off),     # Section file offset
        ('sh_size', Elf32_Word),      # Section size in bytes
        ('sh_link', Elf32_Word),      # Link to another section
        ('sh_info', Elf32_Word),      # Additional section information
        ('sh_addralign', Elf32_Word), # Section alignment
        ('sh_entsize', Elf32_Word),   # Entry size if section holds table
    ]


class Elf64_Shdr(ctypes.Structure):
    """64-bit section header structure"""
    _fields_ = [
        ('sh_name', Elf64_Half),      # Section name (string table index)
        ('sh_type', Elf64_Half),      # Section type
        ('sh_flags', Elf64_Xword),    # Section flags
        ('sh_addr', Elf64_Addr),      # Section virtual addr at execution
        ('sh_offset', Elf64_Off),     # Section file offset
        ('sh_size', Elf64_Xword),     # Section size in bytes
        ('sh_link', Elf64_Half),      # Link to another section
        ('sh_info', Elf64_Half),      # Additional section information
        ('sh_addralign', Elf64_Xword), # Section alignment
        ('sh_entsize', Elf64_Xword),  # Entry size if section holds table
    ]


# =============================================================================
# Dynamic Section Structures (with proper union support)
# =============================================================================

class Elf32_Dyn_Union(ctypes.Union):
    """32-bit dynamic entry union for d_val/d_ptr"""
    _fields_ = [
        ('d_val', Elf32_Word),  # Integer value
        ('d_ptr', Elf32_Addr),  # Address value
    ]


class Elf32_Dyn(ctypes.Structure):
    """32-bit dynamic section entry with union"""
    _fields_ = [
        ('d_tag', Elf32_Sword),        # Dynamic entry type
        ('d_un', Elf32_Dyn_Union),     # Union of value/pointer
    ]


class Elf64_Dyn_Union(ctypes.Union):
    """64-bit dynamic entry union for d_val/d_ptr"""
    _fields_ = [
        ('d_val', Elf64_Xword),  # Integer value
        ('d_ptr', Elf64_Addr),   # Address value
    ]


class Elf64_Dyn(ctypes.Structure):
    """64-bit dynamic section entry with union"""
    _fields_ = [
        ('d_tag', Elf64_Sxword),       # Dynamic entry type
        ('d_un', Elf64_Dyn_Union),     # Union of value/pointer
    ]


# =============================================================================
# Symbol Table Structures
# =============================================================================

class Elf32_Sym(ctypes.Structure):
    """32-bit symbol table entry"""
    _fields_ = [
        ('st_name', Elf32_Word),       # Symbol name (string table index)
        ('st_value', Elf32_Addr),      # Symbol value
        ('st_size', Elf32_Word),       # Symbol size
        ('st_info', ctypes.c_uint8),   # Symbol type and binding
        ('st_other', ctypes.c_uint8),  # Symbol visibility
        ('st_shndx', Elf32_Half),      # Section index
    ]


class Elf64_Sym(ctypes.Structure):
    """64-bit symbol table entry"""
    _fields_ = [
        ('st_name', Elf64_Word),       # Symbol name (string table index)
        ('st_info', ctypes.c_uint8),   # Symbol type and binding
        ('st_other', ctypes.c_uint8),  # Symbol visibility
        ('st_shndx', Elf64_Quarter),   # Section index
        ('st_value', Elf64_Addr),      # Symbol value
        ('st_size', Elf64_Xword),      # Symbol size
    ]


# =============================================================================
# Relocation Structures
# =============================================================================

class Elf32_Rel(ctypes.Structure):
    """32-bit relocation entry without addend"""
    _fields_ = [
        ('r_offset', Elf32_Addr),  # Address
        ('r_info', Elf32_Word),    # Relocation type and symbol index
    ]


class Elf32_Rela(ctypes.Structure):
    """32-bit relocation entry with addend"""
    _fields_ = [
        ('r_offset', Elf32_Addr),  # Address
        ('r_info', Elf32_Word),    # Relocation type and symbol index
        ('r_addend', Elf32_Sword), # Addend
    ]


class Elf64_Rel(ctypes.Structure):
    """64-bit relocation entry without addend"""
    _fields_ = [
        ('r_offset', Elf64_Addr),  # Address
        ('r_info', Elf64_Xword),   # Relocation type and symbol index
    ]


class Elf64_Rela(ctypes.Structure):
    """64-bit relocation entry with addend"""
    _fields_ = [
        ('r_offset', Elf64_Addr),    # Address
        ('r_info', Elf64_Xword),     # Relocation type and symbol index
        ('r_addend', Elf64_Sxword),  # Addend
    ]


# =============================================================================
# Auxiliary Vector Structures (with union)
# =============================================================================

class Elf32_auxv_Union(ctypes.Union):
    """32-bit auxiliary vector union"""
    _fields_ = [
        ('a_val', ctypes.c_long),       # Integer value
        ('a_ptr', ctypes.c_void_p),     # Pointer value
        ('a_fcn', ctypes.CFUNCTYPE(None)),  # Function pointer value
    ]


class Elf32_auxv_t(ctypes.Structure):
    """32-bit auxiliary vector entry"""
    _fields_ = [
        ('a_type', ctypes.c_int),      # Entry type
        ('a_un', Elf32_auxv_Union),    # Union of values
    ]


class Elf64_auxv_Union(ctypes.Union):
    """64-bit auxiliary vector union"""
    _fields_ = [
        ('a_val', ctypes.c_long),       # Integer value
        ('a_ptr', ctypes.c_void_p),     # Pointer value
        ('a_fcn', ctypes.CFUNCTYPE(None)),  # Function pointer value
    ]


class Elf64_auxv_t(ctypes.Structure):
    """64-bit auxiliary vector entry"""
    _fields_ = [
        ('a_type', ctypes.c_long),     # Entry type
        ('a_un', Elf64_auxv_Union),    # Union of values
    ]


# =============================================================================
# DYNAMIC_INFO Structure (from end of elf.h)
# =============================================================================

class DynamicInfo(ctypes.Structure):
    """Dynamic information structure for tracking addresses and sizes"""
    _fields_ = [
        ('str_tbl_addr', Elf32_Addr),    # String table address
        ('sym_tbl_addr', Elf32_Addr),    # Symbol table address
        ('rel_tbl_addr', Elf32_Addr),    # Relocation table address
        ('rel_tbl_size', Elf32_Word),    # Relocation table size
        ('rel_entry_size', Elf32_Word),  # Relocation entry size
        ('rela_tbl_addr', Elf32_Addr),   # Rela table address
        ('rela_tbl_size', Elf32_Word),   # Rela table size
        ('rela_entry_size', Elf32_Word), # Rela entry size
    ]


# =============================================================================
# Android soinfo Structure (exact match to C++ ElfRebuilder.h)
# =============================================================================

SOINFO_NAME_LEN = 128

class SoInfo:
    """
    Python-native soinfo structure - simplified version that follows C++ logic
    
    This class stores the same information as the C++ soinfo struct but uses
    simple Python data types instead of complex ctypes operations.
    """
    
    def __init__(self):
        """Initialize soinfo with default values"""
        # --- 基本信息 ---
        self.name = ""              # const char* name
        self.phnum = 0              # size_t phnum
        self.entry = 0              # Elf_Addr entry
        self.size = 0               # unsigned size
        self.load_bias = 0          # Elf_Addr load_bias
        
        # --- 动态节 ---
        self.dynamic_offset = 0     # .dynamic section offset
        self.dynamic_count = 0      # Number of entries in .dynamic
        
        # --- 字符串表和符号表 ---
        self.strtab_offset = 0      # .dynstr offset
        self.strtab_size = 0        # .dynstr size
        self.symtab_offset = 0      # .dynsym offset
        self.symtab_size = 0        # .dynsym size

        # --- 哈希表 (SYSV_HASH) ---
        self.hash_offset = 0        # .hash offset (nbucket, nchain, bucket, chain)
        self.nbucket = 0
        self.nchain = 0
        self.bucket_offset = 0      # Offset in loaded_data
        self.chain_offset = 0       # Offset in loaded_data
        
        # --- PLT/GOT ---
        self.plt_got_offset = 0     # .got.plt offset
        
        # --- 重定位信息 ---
        # PLT 重定位: 根据 plt_type 决定使用 rel 还是 rela
        self.plt_type = 0           # 从 DT_PLTREL 读取, 值为 DT_REL 或 DT_RELA
        self.plt_reloc_offset = 0   # .rel.plt 或 .rela.plt 的偏移量
        self.plt_reloc_size = 0     # .rel.plt 或 .rela.plt 的大小
        self.plt_reloc_count = 0    # .rel.plt 或 .rela.plt 的条目数

        # 动态数据重定位
        self.rel_offset = 0         # .rel.dyn offset
        self.rel_size = 0           # .rel.dyn size
        self.rel_ent = 0            # .rel.dyn ent
        self.rel_count = 0          # .rel.dyn count
        self.rela_offset = 0        # .rela.dyn offset
        self.rela_size = 0          # .rela.dyn size
        self.rela_ent = 0           # .rela.dyn ent
        self.rela_count = 0         # .rela.dyn count
        
        # --- 初始化/终止函数数组 ---
        self.preinit_array_offset = 0                # Offset in loaded_data
        self.preinit_array_count = 0                 # size_t preinit_array_count
        self.init_array_offset = 0                   # Offset in loaded_data
        self.init_array_count = 0                    # size_t init_array_count
        self.fini_array_offset = 0                   # Offset in loaded_data
        self.fini_array_count = 0                    # size_t fini_array_count
        
        # --- .init 和 .fini 函数 (已废弃但仍需兼容) ---
        self.init_func_offset = 0                    # Offset in loaded_data
        self.fini_func_offset = 0                    # Offset in loaded_data
        
        # --- 架构特定字段 ---
        self.ARM_exidx_offset = 0                    # Offset in loaded_data
        self.ARM_exidx_count = 0                     # size_t ARM_exidx_count
        
        # MIPS specific fields
        self.mips_symtabno = 0                       # unsigned mips_symtabno
        self.mips_local_gotno = 0                    # unsigned mips_local_gotno
        self.mips_gotsym = 0                         # unsigned mips_gotsym
        
        # --- 标志位 ---
        self.flags = 0
        self.has_text_relocations = False
        self.has_DT_SYMBOLIC = False
        
        # Symbol table for relocation processing
        self.symbol_table = []                       # List of symbol entries
        self.min_load = None
        self.max_load = None
        self.unused1 = 0
        self.unused2 = 0
        self.unused3 = 0
        self.pad_size = 0  # 动态段填充大小
