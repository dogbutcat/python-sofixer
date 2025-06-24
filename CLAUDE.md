# SoFixer Workflow and Function Call Sequence

## Overview

SoFixer reconstructs ELF files that have been
  dumped from memory, fixing the corrupted structures
   and relocations to create working shared library
  (.so) files.

## Main Execution Flow

1. Program Entry (main.cpp:121-128)

main() → main_loop() → usage() [on failure]

1. Command Line Processing (main.cpp:28-119)

- getopt_long() - Parse command line arguments
- Key parameters handled:
- -s: Source dumped SO file
- -o: Output fixed SO file
- -m: Memory dump base address
- -b: Original SO file (experimental)
- -d: Debug mode

1. ELF Loading Phase (main.cpp:87-99)

ObElfReader elf_reader;
elf_reader.setSource() →
elf_reader.setDumpSoBaseAddr() →
elf_reader.setBaseSoName() [optional] →
elf_reader.Load()

1. ObElfReader.Load() (ObElfReader.cpp:51-84)

ReadElfHeader() → VerifyElfHeader() → ReadProgramHeader() → FixDumpSoPhdr() → [LoadDynamicSectionFromBaseSource()] [if needed] → ReserveAddressSpace() → LoadSegments() → FindPhdr() → [ApplyDynamicSection()] [if base SO used] → ApplyPhdrTable()

1. ELF Rebuilding Phase (main.cpp:101-115)

ElfRebuilder elf_rebuilder(&elf_reader);
elf_rebuilder.Rebuild() → [Write output file with rebuild data]

1. ElfRebuilder.Rebuild() (ElfRebuilder.cpp:540-546)

RebuildPhdr() → ReadSoInfo() → RebuildShdr() → RebuildRelocs() → RebuildFin()

## Detailed Function Analysis

### ObElfReader Key Functions

- FixDumpSoPhdr() (ObElfReader.cpp:12-49)
- Fixes corrupted program headers from memory dumps
- Adjusts segment sizes and offsets for dumped memory layout
- LoadDynamicSectionFromBaseSource() (ObElfReader.cpp:108-140)
- Loads dynamic section from original SO file when missing from dump
- Extracts essential linking information

### ElfRebuilder Key Functions

- RebuildPhdr() (ElfRebuilder.cpp:24-39)
- Fixes program header table offsets and sizes
- Aligns file structure with memory layout
- ReadSoInfo() (ElfRebuilder.cpp:548-705)
- Parses dynamic section to extract symbols, relocations, and metadata
- Populates soinfo structure with linking information
- RebuildShdr() (ElfRebuilder.cpp:41-538)
- Reconstructs section header table from scratch
- Creates sections: .dynsym, .dynstr, .hash, .rel.dyn, .rel.plt, etc.
- RebuildRelocs() (ElfRebuilder.cpp:781-811)
- Fixes relocations by adjusting addresses relative to new base
- Handles different relocation types (R_ARM_RELATIVE, etc.)
- RebuildFin() (ElfRebuilder.cpp:708-735)
- Assembles final ELF file with corrected headers and data
- Outputs complete reconstructed SO file

## Core Data Structures

- soinfo (ElfRebuilder.h:20-88) - Mimics Android's soinfo structure
- Elf_* typedefs (macros.h:14-36) - Handle 32/64-bit ELF formats
- Program/Section headers - Standard ELF structures for metadata

## Memory Management Pattern

The tool follows a three-stage memory management
pattern:

1. Load - Read dumped SO into memory with correct
layout
2. Parse - Extract symbols, relocations, and dynamic information
3. Rebuild - Reconstruct valid ELF structure and write to disk
