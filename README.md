# SoFixer Python版本

SoFixer的Python实现 - 用于修复从内存转储的ELF共享库(.so)文件的工具。
借助ClaudeAI，从[F8LEFT的原始C++实现](https://github.com/F8LEFT/SoFixer)移植而来。

## 项目概述

SoFixer Python版本是对C++版本SoFixer实现的移植，提供了类似的功能：

- **ELF文件解析**：完整支持32/64位ELF文件格式
- **程序头修复**：修正内存转储导致的程序头偏移量错误
- **段头表重建**：重构损坏的段头表和段信息
- **动态段处理**：修复动态链接信息和重定位表
- **地址映射修正**：调整虚拟地址到文件偏移量的映射

## 项目结构

```
python-sofixer/
├── src/sofixer/          # 核心源代码包
│   ├── __init__.py       # 包初始化文件
│   ├── main.py           # 主程序入口
│   ├── types.py          # ELF结构类型定义
│   ├── elf_reader.py     # ELF文件读取和解析
│   ├── elf_rebuilder.py  # ELF文件重建和修复
│   └── utils.py          # 通用工具函数
├── src/legacy/           # 旧版本文件
│   ├── sofixer.py        # 原始单文件实现
│   └── sofixer_original.py
├── tools/                # 诊断和验证工具
│   ├── check_segments.py # 程序头比较工具
│   ├── check_elf.py      # ELF文件验证
│   ├── compare_sections.py
│   ├── debug_section_headers.py
│   └── analyze_dump_structure.py
├── tests/                # 测试脚本
│   ├── test_fix.py
│   ├── test_fix_validation.py
│   ├── test_program_headers.py
│   └── validate_fix.py
├── README.md             # 本文档
├── FIX_SUMMARY.md        # 修复过程总结
├── CLAUDE.md             # 项目开发指令
├── requirements.txt      # Python依赖
└── setup.py             # 安装脚本
```

## 安装和使用

### 安装依赖

```bash
pip install -r requirements.txt
```

### 开发模式安装

```bash
pip install -e .
```

### 基本使用

```bash
# 使用模块方式运行
python -m src.sofixer.main -s dumped.so -o fixed.so -m 0x7DB078B000

# 或者安装后直接使用命令
sofixer -s dumped.so -o fixed.so -m 0x7DB078B000 -d
```

### 参数说明

- `-s, --source`: 输入的内存转储SO文件
- `-o, --output`: 输出的修复后SO文件  
- `-m, --memory-base`: 内存转储时的基地址
- `-b, --base-so`: 原始SO文件路径（实验性功能）
- `-d, --debug`: 启用调试输出

## 核心功能模块

### elf_reader.py
- `ELFReader`: 基础ELF文件读取器
- `ObfuscatedELFReader`: 处理混淆/转储SO文件的专用读取器
- 支持内存映射高性能文件访问
- 自动检测32/64位架构

### elf_rebuilder.py  
- `ELFRebuilder`: ELF文件重建器
- 段头表完整重建
- 动态段和重定位表修复
- 符号表重建

### types.py
- 完整的ELF数据结构定义
- 32/64位架构兼容
- ctypes结构用于精确的二进制操作

## 工具和验证

### 诊断工具
- `check_segments.py`: 比较修复前后的程序头差异
- `debug_section_headers.py`: 分析段头表结构
- `analyze_dump_structure.py`: 内存转储结构分析

### 测试验证
- `validate_fix.py`: 全面的修复效果验证
- `test_fix.py`: 详细的段创建测试

## 最近修复

### 程序头偏移量修复 (2025年6月23日)
解决了Python版本在IDA中显示".pregend"段而非正确段名的问题：

- **根本原因**: `fix_dump_program_headers()` 函数未正确实现C++版本的两阶段修复逻辑
- **修复方案**: 
  1. 重写程序头修复逻辑，精确匹配C++实现
  2. 确保修复后的程序头正确序列化到最终文件
- **验证结果**: 所有6个程序头与C++版本完全一致

详细修复过程请参阅 `FIX_SUMMARY.md`。

## 技术特点

### 与C++版本的兼容性
- **程序头处理**: 完全匹配C++的`FixDumpSoPhdr()`逻辑
- **段头重建**: 对应C++的`RebuildShdr()`功能
- **地址计算**: 精确的虚拟地址到文件偏移量转换
- **二进制结构**: 使用ctypes确保与C结构体完全兼容

### 性能优化
- 内存映射文件访问，减少I/O开销
- 模块化设计，便于维护和扩展
- 详细的日志系统，便于调试和问题诊断

## 开发说明

### 代码风格
- 遵循PEP 8 Python编码规范
- 使用类型注解提高代码可读性

### 测试
```bash
# 运行基本验证
python tests/validate_fix.py dumped.so 0x7DB078B000

# 比较生成结果
python tools/check_segments.py cpp_output.so python_output.so
```

## 许可证

与原始C++项目相同的许可证。

## 致谢

- **F8LEFT**: 原始C++实现的作者
- **Claude**: Python移植和问题修复

## 相关链接

- [原始C++项目](https://github.com/F8LEFT/SoFixer)
- [项目修复历史](FIX_SUMMARY.md)
- [开发指令文档](CLAUDE.md)
