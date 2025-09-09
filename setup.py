#!/usr/bin/env python3
"""
SoFixer Python版本安装脚本
========================

ELF文件重建工具的Python实现安装配置。
"""

from setuptools import setup, find_packages
import os

# 读取长描述
def read_long_description():
    here = os.path.abspath(os.path.dirname(__file__))
    try:
        with open(os.path.join(here, 'README.md'), 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "SoFixer Python版本 - ELF文件重建工具"

# 读取依赖
def read_requirements():
    here = os.path.abspath(os.path.dirname(__file__))
    try:
        with open(os.path.join(here, 'requirements.txt'), 'r', encoding='utf-8') as f:
            requirements = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    requirements.append(line)
            return requirements
    except FileNotFoundError:
        return []

setup(
    name="sofixer",
    version="1.1.0",
    author="F8LEFT (原始C++), Python移植版本",
    author_email="",
    description="ELF文件重建工具 - 修复从内存转储的共享库文件",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/dogbutcat/python-sofixer",
    
    # 包配置
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    
    # 依赖
    install_requires=read_requirements(),
    
    # Python版本要求
    python_requires=">=3.6",
    
    # 分类器
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    
    # 命令行入口点
    entry_points={
        "console_scripts": [
            "sofixer=sofixer.main:main",
        ],
    },
    
    # 项目关键词
    keywords="elf, so, shared library, memory dump, reverse engineering, binary analysis",
    
    # 项目URLs
    project_urls={
        "Bug Reports": "https://github.com/F8LEFT/SoFixer/issues",
        "Source": "https://github.com/F8LEFT/SoFixer",
        "Documentation": "https://github.com/F8LEFT/SoFixer/blob/master/README.md",
    },
    
    # 包含的非Python文件
    include_package_data=True,
    
    # 开发状态
    zip_safe=False,
)