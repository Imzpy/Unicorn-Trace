# Unicorn ARM64 动态追踪模拟器

本项目提供了一套基于 Unicorn 引擎的 ARM64 动态追踪模拟工具，支持在 IDA Pro 中作为插件运行或独立执行。本工具与 IDA 紧密集成，确保执行过程与 IDA 一致，避免出错；提供可靠的模拟执行再现能力，并生成美观的 Tenet 日志用于调试分析。主要功能包括动态代码模拟、内存转储、寄存器状态追踪和指令级日志记录。

## 主要功能

- **IDA 集成插件** (`dyn_trace_ida.py`)
  - 通过 GUI 配置模拟参数（结束地址、SO 名称、TPIDR 值等）
  - 自动转储内存段和寄存器状态
  - 支持 Tenet 兼容的追踪日志
  - 错误处理（内存访问异常、范围检查等）

- **独立模拟器** (`unicorn_trace.py`)
  - 从文件加载内存映射和寄存器状态
  - 自定义模拟范围
  - 生成详细执行日志（`uc.log` 和 `tenet.log`）

## 文件结构

```
.
├── dyn_trace_ida.py              # IDA 插件版本
├── unicorn_trace.py              # 独立模拟器
├── unicorn_trace/                # 模拟器核心
│   └── unicorn_class.py          # ARM64 模拟器基类
├── single_script/                # 实用脚本
│   ├── dynamic_dump.py           # IDA 单脚本版本
│   └── dump_single.py            # 单次转储脚本（未提供）
└── README.md                     # 项目文档
```

## 安装与使用

### 依赖安装
```bash
pip install unicorn capstone
```
### IDA 安装

将 `dyn_trace_ida.py` 和 `unicorn_trace` 文件夹放入 IDA 的 `plugins` 目录

### 单脚本模式（可选）

直接使用 `single_script/dynamic_dump.py` 在 IDA 调试时启用，无需使用库文件

### 功能一：动态 dump / 自动化调试


#### IDA 插件使用
1. 在 IDA 中使用 `Ctrl-Alt-U` 打开配置窗口
2. 设置参数：
   - 结束地址（相对偏移）
   - SO 名称 （可选，启用 tenet 需要填）
   - TPIDR 值（可选，遇到报错需要填写）
   - 输出路径 （可选，默认本地）
   - 是否启用 Tenet 日志 （可选，不建议启用，影响效率，建议离线更新）
3. 点击确认开始模拟

#### IDA 脚本使用

已安装插件可以直接使用 `dyn_trace_ida.py` 脚本，如未安装也可以使用上面单脚本 `dynamic_dump.py`

直接在 mian 函数里填写所需参数，内容同上


### 功能二：独立模拟器使用
```python
from unicorn_trace import SelfRunArm64Emulator

# 初始化模拟器
emulator = SelfRunArm64Emulator()
emulator.setup_from_files("libtarget.so", "./dumps")

# 运行模拟
emulator.custom_main_trace(
    so_name="libtarget.so",
    end_addr=0x123456,
    tenet_log_path="./trace.log",
    user_log_path="./sim.log",
    load_dumps_path="./dumps"
)
```

## 示例工作流

1. **动态执行、内存转储、保存现场**：

使用插件或者脚本运行到结束位置

2. **分析 trace，生成 tenet log**：

使用 `unicorn_trace.py` 生成 tenet.log，组合所有 log

3. **日志分析，离线模拟执行**：


## 注意事项

1. 处理特殊寄存器值（如 TPIDR）时需手动配置
2. 内存区域转储关乎效率 `DUMP_SINGLE_SEG_SIZE` 越大越慢，越小越可能出错
3. 异常处理支持：
   - 内存访问错误（UC_ERR_READ_UNMAPPED）
   - 范围越界（Code Run out of range）
   - AUTIASP 指令异常
   - B4 寄存器处理
   - UNICORN 运行中和 IDA 对比检查

## 错误处理

常见错误代码：
- `1`：需要重启脚本（通常由范围越界引起）
- `2`：需要更新内存转储（内存访问错误）
- `0`：未知错误（检查寄存器状态）

## 贡献

欢迎提交 Issue 或 Pull Request。请确保：
- 遵循现有代码风格
- 添加必要的单元测试
- 更新相关文档

## Reference

Tenet IDA 9.0: https://github.com/jiqiu2022/Tenet-IDA9.0

Tenet: https://github.com/gaasedelen/tenet