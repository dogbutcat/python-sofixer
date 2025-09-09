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
- Module API for programmatic usage with bytearray I/O

Original C++ implementation by F8LEFT.
Python ctypes port with binary accuracy and union support.

Modular Architecture:
- elf_utils: Utility functions and architecture detection
- elf_reader: ELF file reading and parsing classes  
- elf_rebuilder: ELF file reconstruction and repair logic

CLI Usage:
    python sofixer.py -s dumped.so -o fixed.so -m 0x7DB078B000 -d

Module Usage:
    import sofixer
    
    # Load dumped SO data
    with open('dumped.so', 'rb') as f:
        dumped_data = bytearray(f.read())
    
    # Optional: Load base SO data
    with open('base.so', 'rb') as f:
        base_data = bytearray(f.read())
    
    # Fix the SO file
    fixed_data = sofixer.fix_so(
        dumped_data=dumped_data,
        dump_base_addr=0x7DB078B000,
        base_so_data=base_data,  # Optional
        debug=True
    )
    
    if fixed_data:
        with open('fixed.so', 'wb') as f:
            f.write(fixed_data)
"""

import sys
import os
import argparse
import logging
import tempfile
from typing import Optional, Union

# Import our modular components
from .utils import setup_logging, parse_memory_address, detect_elf_architecture
from .elf_reader import ObfuscatedELFReader
from .elf_rebuilder import ELFRebuilder

# Configure logging
logger = logging.getLogger(__name__)


def fix_so(dumped_data: Union[bytes, bytearray], 
           dump_base_addr: Union[int, str], 
           base_so_data: Optional[Union[bytes, bytearray]] = None,
           debug: bool = False) -> Optional[bytearray]:
    """
    Fix a dumped SO file data in memory.
    
    Args:
        dumped_data: The dumped SO file data as bytes or bytearray
        dump_base_addr: Memory base address where SO was dumped from (int or hex string)
        base_so_data: Optional original SO file data for dynamic section recovery
        debug: Enable debug logging
        
    Returns:
        Fixed SO file data as bytearray, or None if fixing failed
        
    Example:
        >>> with open('dumped.so', 'rb') as f:
        ...     dumped = bytearray(f.read())
        >>> fixed = fix_so(dumped, 0x7DB078B000)
        >>> if fixed:
        ...     with open('fixed.so', 'wb') as f:
        ...         f.write(fixed)
    """
    # Setup logging for module usage only if no handlers exist
    if debug and not logger.handlers:
        setup_logging(True)
    
    try:
        # Parse memory address if it's a string
        if isinstance(dump_base_addr, str):
            dump_base_addr = parse_memory_address(dump_base_addr)
        
        logger.info(f"Using dump base address: 0x{dump_base_addr:x}")
        
        # Convert input data to bytearray if needed
        if isinstance(dumped_data, bytes):
            dumped_data = bytearray(dumped_data)
        
        if base_so_data is not None and isinstance(base_so_data, bytes):
            base_so_data = bytearray(base_so_data)
        
        # Create temporary files for the readers (they expect file paths)
        with tempfile.NamedTemporaryFile(delete=False) as temp_dumped:
            temp_dumped.write(dumped_data)
            temp_dumped_path = temp_dumped.name
        
        temp_base_path = None
        if base_so_data is not None:
            with tempfile.NamedTemporaryFile(delete=False) as temp_base:
                temp_base.write(base_so_data)
                temp_base_path = temp_base.name
        
        try:
            # Initialize obfuscated ELF reader
            with ObfuscatedELFReader(temp_dumped_path) as elf_reader:
                # Set parameters
                elf_reader.set_dump_base_addr(dump_base_addr)
                if temp_base_path:
                    elf_reader.set_base_so_path(temp_base_path)
                
                # Load the ELF file
                if not elf_reader.load():
                    logger.error("Failed to load ELF file")
                    return None
                
                # Initialize rebuilder
                rebuilder = ELFRebuilder(elf_reader)
                
                # Rebuild the ELF file
                if not rebuilder.rebuild():
                    logger.error("Failed to rebuild ELF file")
                    return None
                
                # Get rebuilt data
                rebuilt_data = rebuilder.get_rebuilt_data()
                if not rebuilt_data:
                    logger.error("No rebuilt data available")
                    return None
                
                logger.info(f"Successfully rebuilt SO file ({len(rebuilt_data)} bytes)")
                
                # Convert to bytearray and return
                if isinstance(rebuilt_data, bytes):
                    return bytearray(rebuilt_data)
                else:
                    return rebuilt_data
        
        finally:
            # Clean up temporary files
            try:
                os.unlink(temp_dumped_path)
                if temp_base_path:
                    os.unlink(temp_base_path)
            except OSError:
                pass  # Ignore cleanup errors
    
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to fix SO file: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return None


def main():
    """Main entry point for the ctypes-based SoFixer implementation"""
    parser = argparse.ArgumentParser(
        description='SoFixer (ctypes) - Repair dumped SO files from memory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with automatic architecture detection
  python sofixer.py -s dumped.so -o fixed.so -m 0x7DB078B000
  
  # With debug output and base SO file
  python sofixer.py -s dumped.so -o fixed.so -m 0x7DB078B000 -d -b original.so

Module Usage:
  import sofixer
  
  # Load data
  with open('dumped.so', 'rb') as f:
      dumped = bytearray(f.read())
  
  # Fix SO file
  fixed = sofixer.fix_so(dumped, 0x7DB078B000, debug=True)
  
  # Save result
  if fixed:
      with open('fixed.so', 'wb') as f:
          f.write(fixed)
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