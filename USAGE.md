# SoFixer Python版本使用说明

## 快速开始

### 1. 基本使用

```bash
# 进入项目目录
cd python-sofixer

# 直接运行（推荐）
python -m src.sofixer.main -s dumped.so -o fixed.so -m 0x7DB078B000

# 注意：main.py现在是基于原始sofixer.py的正确入口点
```

### 2. 安装后使用

```bash
# 开发模式安装
pip install -e .

# 安装后直接使用命令
sofixer -s dumped.so -o fixed.so -m 0x7DB078B000 -d
```

### 3. 运行测试和验证

```bash
# 运行验证脚本
python tests/validate_fix.py dumped.so 0x7DB078B000

# 比较程序头
python tools/check_segments.py cpp_fixed.so python_fixed.so

# 调试段头表
python tools/debug_section_headers.py fixed.so
```

## 参数说明

- `-s, --source`: 输入的内存转储SO文件路径
- `-o, --output`: 输出的修复后SO文件路径  
- `-m, --memso`: 内存转储时的基地址（十六进制，如 0x7DB078B000）
- `-b, --baseso`: 原始SO文件路径（可选，用于动态段恢复）
- `-d, --debug`: 启用详细调试输出

## 项目结构

```
python-sofixer/
├── src/sofixer/          # 核心Python包
├── tools/                # 诊断验证工具  
├── tests/                # 测试脚本
├── debug/                # 调试文件夹
│   ├── samples/          # 测试SO文件
│   ├── output/           # 调试输出
│   ├── debug_script.py   # 调试脚本
│   └── README.md         # 调试指南
├── .vscode/              # VS Code配置
│   ├── launch.json       # 调试配置
│   ├── settings.json     # 编辑器设置
│   └── tasks.json        # 任务配置
├── .gitignore            # Git忽略文件配置
├── README.md             # 本文档
├── FIX_SUMMARY.md        # 修复过程总结
├── CLAUDE.md             # 项目开发指令
├── requirements.txt      # 依赖文件
└── setup.py             # 安装脚本
```

## 故障排除

### 导入错误
如果遇到模块导入错误，确保：
1. 在正确的目录下运行命令
2. 使用 `python -m src.sofixer.main` 格式
3. 或者先安装包：`pip install -e .`

### 架构不匹配
工具会自动检测32/64位ELF架构，如果遇到问题请检查：
1. 输入文件是否为有效的ELF文件
2. 是否为支持的架构（ARM/x86 32/64位）

### 内存地址错误
确保提供正确的内存转储基地址：
1. 地址格式为十六进制：`0x7DB078B000`
2. 地址必须是转储时SO在内存中的实际加载地址

## VS Code调试支持

项目包含完整的VS Code调试配置：

### 启动调试
1. 在VS Code中打开项目文件夹
2. 按 `F5` 选择调试配置
3. 可选择的调试配置：
   - **SoFixer Debug - Basic**: 基本调试，使用示例文件
   - **SoFixer Debug - With Base SO**: 带基础SO文件的调试
   - **Check Segments Tool**: 运行段比较工具
   - **Validate Fix Tool**: 运行修复验证
   - **Debug Section Headers**: 调试段头表
   - **Debug ELF Reader**: 调试ELF读取器
   - **Debug ELF Rebuilder**: 调试ELF重建器

### 快速调试脚本
```bash
# 运行综合调试脚本
python debug/debug_script.py

# 或使用VS Code任务
Ctrl+Shift+P -> Tasks: Run Task -> Run Debug Script
```

### 调试提示
- 在关键函数设置断点：`fix_dump_program_headers()`, `extract_so_info()`
- 使用 `-d` 参数查看详细日志
- 查看 `debug/README.md` 获取详细调试指南