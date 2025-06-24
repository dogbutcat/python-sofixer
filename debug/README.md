# SoFixer 调试指南

## 目录结构

```
debug/
├── README.md          # 本文档
├── debug_script.py    # 调试脚本
├── samples/           # 测试样本文件
│   ├── libjiagu_64.so_0x7a1301e000_0x27e000.so  # 原始转储文件
│   ├── libjiagu_fixed.so                        # C++版本修复结果（参考）
│   └── ... (其他测试文件)
└── output/            # 调试输出文件
    └── ... (生成的修复文件)
```

## VS Code 调试配置

项目已配置了多个VS Code调试配置，可在 `.vscode/launch.json` 中找到：

### 1. SoFixer Debug - Basic
基本的SoFixer调试配置，包含：
- 输入文件：`debug/samples/libjiagu_64.so_0x7a1301e000_0x27e000.so`
- 输出文件：`debug/output/libjiagu_fixed_debug.so`
- 内存基地址：`0x7a1301e000`
- 启用调试输出

### 2. SoFixer Debug - With Base SO
带有基础SO文件的调试配置，用于测试动态段恢复功能。

### 3. Check Segments Tool
运行段比较工具，用于验证Python版本和C++版本的输出是否一致。

### 4. Validate Fix Tool
运行修复验证工具，检查修复效果。

### 5. Debug Section Headers
调试段头表信息。

### 6. Debug ELF Reader
直接调试ELF读取器模块。

### 7. Debug ELF Rebuilder
直接调试ELF重建器模块。

## 使用方法

### 1. 快速调试脚本

```bash
# 进入debug目录
cd debug

# 运行调试脚本
python debug_script.py
```

这个脚本会执行：
- 基本功能测试
- 程序头调试
- 段创建调试  
- 比较测试（如果有C++版本输出）

### 2. VS Code调试

1. 在VS Code中打开项目
2. 按 `F5` 或转到 "Run and Debug" 面板
3. 选择相应的调试配置
4. 设置断点并开始调试

### 3. 手动调试

```bash
# 基本运行
python -m src.sofixer.main \
    -s debug/samples/libjiagu_64.so_0x7a1301e000_0x27e000.so \
    -o debug/output/manual_test.so \
    -m 0x7a1301e000 \
    -d

# 使用工具验证
python tools/check_segments.py \
    debug/samples/libjiagu_fixed.so \
    debug/output/manual_test.so
```

## 调试技巧

### 1. 设置断点
在关键函数中设置断点：
- `elf_reader.py:fix_dump_program_headers()` - 程序头修复
- `elf_rebuilder.py:extract_so_info()` - SO信息提取
- `elf_rebuilder.py:_rebuild_section_headers()` - 段头重建

### 2. 查看变量
重要的调试变量：
- `elf_reader.program_headers` - 程序头列表
- `rebuilder.so_info` - SO信息结构
- `rebuilder.section_headers` - 重建的段头
- `rebuilder.rebuilt_data` - 最终的二进制数据

### 3. 日志输出
使用 `-d` 参数启用详细日志输出，关注：
- `fix_dump_program_headers` 的修复过程
- 段头重建的地址计算
- 最终文件的写入过程

### 4. 比较工具
使用提供的工具进行比较：
```bash
# 比较程序头
python tools/check_segments.py file1.so file2.so

# 调试段头表
python tools/debug_section_headers.py output.so

# 全面验证
python tests/validate_fix.py input.so 0x7a1301e000
```

## 常见问题

### 1. 导入错误
确保在项目根目录运行，或正确设置PYTHONPATH：
```bash
export PYTHONPATH=$PWD/src:$PYTHONPATH
```

### 2. 文件不存在
确保样本文件已复制到 `debug/samples/` 目录。

### 3. 地址错误
确保使用正确的内存基地址 `0x7a1301e000`。

### 4. 权限问题
确保对 `debug/output/` 目录有写权限。

## 调试场景

### 1. 程序头偏移量问题
如果发现程序头偏移量不正确：
1. 在 `fix_dump_program_headers()` 设置断点
2. 检查 `dump_base_addr` 是否正确
3. 验证两阶段修复逻辑

### 2. 段头表重建问题
如果段头表重建有问题：
1. 在 `_rebuild_section_headers()` 设置断点
2. 检查 `so_info` 中的地址计算
3. 验证段排序逻辑

### 3. 最终文件输出问题
如果最终文件不正确：
1. 在 `_update_program_header_table()` 设置断点
2. 检查 `rebuilt_data` 的内容
3. 验证ctypes序列化过程

## 添加新的调试配置

要添加新的调试配置，编辑 `.vscode/launch.json`：

```json
{
    "name": "My Debug Config",
    "type": "python",
    "request": "launch",
    "module": "src.sofixer.main",
    "args": [
        "-s", "path/to/input.so",
        "-o", "path/to/output.so", 
        "-m", "0x12345678",
        "-d"
    ],
    "console": "integratedTerminal",
    "cwd": "${workspaceFolder}",
    "env": {
        "PYTHONPATH": "${workspaceFolder}/src"
    }
}
```