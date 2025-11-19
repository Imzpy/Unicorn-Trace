# Unicorn ARM64 动态追踪模拟器

本项目提供了一套轻量级的基于 Unicorn 引擎的 ARM64 动态追踪模拟工具，支持在 IDA Pro 中作为插件运行或独立执行。本工具与 IDA 紧密集成，确保执行过程与 IDA 一致，避免出错；提供可靠的模拟执行再现能力，并生成美观的 Tenet 日志用于调试分析。主要功能包括动态代码模拟、内存转储、寄存器状态追踪和指令级日志记录。

本工具无需全量 dump 内存，只在运行过程中按需动态 dump 内存因此效率和速度都很高，再加上过程检查能确保整个获取过程都是完善无误的。作为 trace 工具，该工具在 vm 分析中相当有用，适用性和速率都很好。但在外部调用非常多且密集的用户函数，效率会受到很大影响，后续可能会针对此进行优化

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

ida 调试到指定位置后，写入期望的运行地址，会自动运行且记录 trace 到那结束地址

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

直接在 main 函数里填写所需参数，内容同上


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

也可以参考[看雪文章](https://bbs.kanxue.com/thread-289135.htm)

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
4. 单次运行流程都是独立的，因此哪怕中间出错，对于已经生成的 dump 文件夹都是没有影响的。仅需删除最新出错 dump 文件以及处理报错原因后再次运行即可
5. 单大轮外部调用上限为 50，如果超过会显示 `restart` 后停下。如果希望更改长度可以在代码中更改 `ROUND_MAX`

## 错误处理

常见错误代码：
- 缺乏 `TPIDR`：需要报错结果附近 pc 值（或者看 log 汇编），手动调试到 `mrs xxx` 处后获取 `TPIDR` 寄存器的数值。这是因为 ida 无法获取导致的。不过全运行流程中都不会变化
- ida 断点导致出错：最好在运行时手动 disable 所有的 ida 断点，不然在运行对比和跳过调用时可能会出错
- ida 报错：ida 报错会导致运行暂停，再次运行即可

## 贡献

欢迎提交 Issue 或 Pull Request。请确保：
- 遵循现有代码风格
- 添加必要的单元测试
- 更新相关文档

## TODO

提升效率，中间 dump mem 后接着后续运行而不是重新开始

多架构适配

## Reference

Tenet IDA 9.0: https://github.com/jiqiu2022/Tenet-IDA9.0

Tenet: https://github.com/gaasedelen/tenet
