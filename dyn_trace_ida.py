import time
import json
import re
import os
import capstone
from unicorn import *
from unicorn.arm64_const import *
import ida_segment
import idc
import ida_bytes
import idaapi
import ida_dbg
from unicorn_trace.unicorn_class import Arm64Emulator # type: ignore

# ==============================
# 常量定义
# ==============================

DUMP_SINGLE_SEG_SIZE = 0x4000
ROUND_MAX = 50

# ==============================
# 插件表单类
# ==============================

class UnicornEmulatorForm(idaapi.Form):
    """Unicorn模拟器配置表单"""
    
    def __init__(self):
        idaapi.Form.__init__(self, r"""STARTITEM 0
Unicorn ARM64 Emulator

<##END Relative addr (hex)         :{end_addr}>
<##So Name (Enter when enale tenet):{so_name}>
<##TPIDR (hex, optional)           :{tpidr_value}>
<##output path (defalt .)          :{output_path}>
<##Check boxes##enable Tenet:{enable_tenet}>{enable_group}>
""", {
            'end_addr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,swidth=30),
            'so_name': idaapi.Form.StringInput(swidth=30,value=""),
            'tpidr_value': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR,swidth=30,value=0),
            'output_path': idaapi.Form.StringInput(swidth=30,value="."),
            'enable_group': idaapi.Form.ChkGroupControl(("enable_tenet",)),
        })
        
        self.end_addr = 0x1e4988
        self.so_name = ""
        self.tpidr_value = None
        self.enable_tenet = False
        self.output_path = "."

# ==============================
# 插件主类
# ==============================

class UnicornEmulatorPlugin(idaapi.plugin_t):
    """Unicorn ARM64模拟器插件"""
    
    flags = idaapi.PLUGIN_UNL
    comment = "ARM64 Unicorn Emulator"
    help = "使用Unicorn引擎模拟ARM64代码执行"
    wanted_name = "Unicorn ARM64 Emulator"
    wanted_hotkey = "Ctrl-Alt-U"

    def init(self):
        """初始化插件"""
        print("Unicorn ARM64 Emulator Plugin loaded")
        print("Use Ctrl-Alt-U to open the emulator")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        """运行插件"""
        try:
            # 创建并显示配置表单
            form = UnicornEmulatorForm()
            form.Compile()
            
            ok = form.Execute()
            if ok == 1:
                # 获取表单数据
                end_addr_relative = form.end_addr.value
                so_name = form.so_name.value
                tpidr_value = form.tpidr_value.value if form.tpidr_value.value != 0 else None
                if form.enable_group.value == 1:
                    enable_tenet = True
                else:
                    enable_tenet = None
                output_path = form.output_path.value

                print(f"[+] 配置参数:")
                print(f"结束地址: {hex(end_addr_relative)}")
                print(f"SO名称: {so_name}")
                if tpidr_value:
                    print(f"TPIDR值: {hex(tpidr_value)}")
                print(f"启用Tenet: {enable_tenet}")
                print(f"输出路径: {output_path}")
                # 创建模拟器实例并运行
                if end_addr_relative != None:
                    emulator = IDAArm64Emulator()
                    emulator.main(end_addr_relative, so_name, tpidr_value, enable_tenet, output_path)
                else:
                    print("[+] Wrong Input")
                
            form.Free()
            
        except Exception as e:
            print(f"插件运行错误: {e}")
            import traceback
            traceback.print_exc()

    def term(self):
        """终止插件"""
        pass

# ==============================
# 插件注册
# ==============================

def PLUGIN_ENTRY():
    """插件入口点"""
    return UnicornEmulatorPlugin()

# ==============================
# 原有的IDA集成ARM64模拟器类（保持不变）
# ==============================

class IDAArm64Emulator(Arm64Emulator):
    """IDA集成的ARM64模拟器，继承自Arm64Emulator基类"""
    
    def __init__(self, heap_base=0x1000000, heap_size=0x90000):
        """初始化IDA集成模拟器"""
        # 调用父类初始化
        super().__init__(heap_base, heap_size)
        
        # IDA特定的变量
        self.dumped_range = []
        self.dump_path = "./dumps"
        self.last_regs = None
        self.BASE = 0
        self.run_range = (0, 0)

    # ==============================
    # 重写父类方法 - 内存管理
    # ==============================

    def load_memory_mappings(self, load_dumps_path):
        """重写：加载内存映射，集成IDA段信息"""
        mem_list = os.listdir(load_dumps_path)
        map_list = []
        
        # 解析内存映射文件
        for filename in mem_list:
            pattern = r'0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)\.bin$'
            match = re.search(pattern, filename)
            if match:
                mem_base = int(match.group(1), 16)
                mem_end = int(match.group(2), 16)
                mem_size = int(match.group(3), 16)
                map_list.append((mem_base, mem_end, mem_size, filename))
                # self.loaded_files.append(filename)

        # 按照内存基址排序后加载
        map_list.sort(key=lambda x: x[0])
        tmp = (0, 0, 0, "")
        
        for mem_base, mem_end, mem_size, filename in map_list:
            # 内存对齐处理
            if mem_base < tmp[1]:
                mem_base = tmp[1]
            elif mem_base & 0xfff != 0:
                mem_base = mem_base & 0xfffffffffffff000

            mem_size = mem_end - mem_base
            if mem_size <= 0:
                mem_size = 0x1000
            elif mem_size & 0xfff != 0:
                mem_size = (mem_size & 0xfffffffffffff000) + 0x1000

            mem_end = mem_base + mem_size
            tmp = (mem_base, mem_end, mem_size, filename)
            
            print(f"map file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}")
            self.mu.mem_map(mem_base, mem_size)

        # 加载内存数据
        for mem_base, mem_end, mem_size, filename in map_list:
            print(f"write file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}")
            self.load_file(os.path.join(load_dumps_path, filename), mem_base, mem_size)

    # ==============================
    # 重写父类方法 - 主要模拟
    # ==============================

    def main_trace(self, so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps"):
        """重写：主要模拟函数，集成IDA错误处理"""
        try:        
            # 初始化日志文件
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

            self.init_log_files(tenet_log_path, user_log_path)
            
            # 加载内存映射
            self.load_memory_mappings(load_dumps_path)
            
            # 设置线程指针
            if self.tpidr_value is not None:
                self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, self.tpidr_value)

            # 加载寄存器状态
            self.load_registers(os.path.join(load_dumps_path, "regs.json"))
            print("Registers loaded.")  

            # 重置寄存器跟踪
            self.last_registers.clear()

            # 初始化trace日志
            if self.trace_log:
                self.init_trace_log(so_name)

            # 设置调试钩子
            start_addr = self.mu.reg_read(self.REG_MAP["pc"])
            self.hooks.append(self.mu.hook_add(UC_HOOK_CODE, self.debug_hook_code, begin=start_addr))

            # 开始模拟
            self.mu.emu_start(start_addr, self.BASE + end_addr)

        except UcError as e:
            return self._handle_uc_error(e)
        except Exception as e:
            print(f"发生未知错误: {e}")    
            self.my_reg_logger()
            return 0
        finally:
            print(f"Trace END!")
            # 清理资源
            if self.log_file:
                self.log_file.close()
            if self.trace_log:
                self.trace_log.close()
        
        return 114514

    def _handle_uc_error(self, e):
        """重写：处理Unicorn错误，集成IDA错误处理"""
        print("ERROR: %s" % e)
        err_str = "%s" % e
        self.my_reg_logger()

        if e.errno == 0:
            if "Code Run out of range" in e.args[0]:
                return self._handle_out_of_range_error()
            if "Except AUTIASP" in e.args[0]:
                return self._handle_autiasp_error()

        if "UC_ERR_EXCEPTION" in err_str:
            return self._handle_exception_error()
            
        if self.last_regs == self.dump_registers():
            print(f"[!] Stop at the same location. Jump out. Maybe Check TPIDR regs")
            return 0
        
        if any(err in err_str for err in ["UC_ERR_READ_UNMAPPED", "UC_ERR_FETCH_UNMAPPED", "UC_ERR_WRITE_UNMAPPED"]):
            self.last_regs = self.dump_registers()
            return 2
        
        return 0

    def _handle_out_of_range_error(self):
        """处理超出范围错误"""
        if self.check_registers():
            print('[!] Check REGs Wrong')
            exit(0)

        print(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['lr']):x} for further run, PC: 0x{self.mu.reg_read(self.REG_MAP['pc']):x} ")
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP['lr']))
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        print(f"[+] Restart this Script until finish")
        return 1

    def _handle_autiasp_error(self):
        """处理AUTIASP错误"""
        if self.check_registers():
            print('[!] Check REGs Wrong')
            exit(0)

        print(f"[+] Run to 0x{self.mu.reg_read(self.REG_MAP['pc']) + 4:x} for further run, PC: 0x{self.mu.reg_read(self.REG_MAP['pc']):x} ")
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP['pc']) + 4)
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        print(f"[+] Restart this Script until finish")
        return 1

    def _handle_exception_error(self):
        """处理异常错误"""
        if self.check_registers():
            print('[!] Check REGs Wrong')
            exit(0)
        
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP['lr']))
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        print(f"[+] Restart this Script until finish")
        return 1

    # ==============================
    # IDA特定的方法
    # ==============================

    def dump_segment_to_file(self, seg_start, seg_end, filename):
        """转储段数据到文件"""
        try:
            seg_size = seg_end - seg_start
            if seg_size <= 0:
                print(f"[-] Invalid segment size: {seg_size}")
                return False
            
            if seg_size > 0x4000000:
                print(f"[!] Too big segment size: {seg_size}")
                seg_size = 0x4000000
            
            segment_data = ida_bytes.get_bytes(seg_start, seg_size)
            if not segment_data:
                print(f"[-] Failed to read segment data from {hex(seg_start)} to {hex(seg_end)}")
                return False
            
            with open(filename, 'wb') as f:
                f.write(segment_data)
            
            print(f"[+] Successfully dumped segment to: {filename}")
            print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
            print(f"[+] Dumped size: {len(segment_data)} bytes ({hex(len(segment_data))})")
            return True
            
        except Exception as e:
            print(f"[-] Error during dump: {str(e)}")
            return False

    def find_segment_by_address(self, target_addr):
        """通过地址查找段"""
        try:
            if isinstance(target_addr, str):
                addr_val = int(target_addr, 16) if target_addr.startswith('0x') else int(target_addr)
            else:
                addr_val = target_addr
        except ValueError:
            print(f"[-] Invalid address format: {target_addr}")
            return None
        
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg and seg.start_ea <= addr_val < seg.end_ea:
                return seg
        
        print(f"[-] No segment found containing address: {hex(addr_val)}")
        return None

    def dump_single_segment_address(self, input_addr, range_size=0x10000, file_dump_path="./dumps", next_dump_flag=False):
        """转储单个段地址"""
        if not input_addr:
            print("[-] No address provided")
            return
        
        if isinstance(input_addr, str):
            target_addr = int(input_addr[2:], 16) if input_addr.startswith('0x') else int(input_addr)
        else:
            target_addr = input_addr

        # 处理特殊地址格式
        if target_addr & 0xb4ff000000000000 == 0xb400000000000000:
            target_addr = target_addr & 0xffffffffffffff
        
        seg = self.find_segment_by_address(target_addr)
        if not seg:
            print(f"[+] {target_addr} do not contain the addr")
            return
        
        # 计算转储范围
        if range_size < 0x10000:
            dump_base = target_addr & (~(0x1000 - 1))
        else:
            dump_base = target_addr & (~(range_size - 1))

        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        
        print(f"[+] Found segment: {seg_name}")
        print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
        print(f"[+] Segment size: {hex(seg_end - seg_start)} bytes")
        
        dump_end = dump_base + range_size
        if dump_end > seg_end:
            dump_end = seg_end
        if dump_base < seg_start:
            dump_base = seg_start
        
        # 检查是否已转储
        for exist_start, exist_end in self.dumped_range:
            if dump_base > exist_start and dump_base < exist_end:
                dump_base = exist_end
            if dump_end > exist_start and dump_end < exist_end:
                dump_end = exist_start
        
        if dump_base >= dump_end:
            print(f"[+] Range {hex(dump_base)} - {hex(dump_end)} already dumped")
            return
        
        self.dumped_range.append((dump_base, dump_end))
        
        # 生成输出文件名
        filename = f"{file_dump_path}/segment_{seg_name}_{hex(dump_base)}_{hex(dump_end)}_{hex(dump_end - dump_base)}.bin"
        
        # 转储段到文件
        self.dump_segment_to_file(dump_base, dump_end, filename)

        # 处理跨段读写
        if next_dump_flag and seg_end - seg_start < 0x1000:
            self.dump_single_segment_address(seg_end + 100, 0x1000, file_dump_path, False)

    def dump_registers_memory(self):    
        """转储寄存器指向的内存"""
        for reg_name in self.REG_MAP.keys():
            if "w" in reg_name:
                continue
            self.dump_single_segment_address(self.mu.reg_read(self.REG_MAP[reg_name]), DUMP_SINGLE_SEG_SIZE, self.dump_path, True)

    def check_registers(self):
        """检查寄存器一致性"""
        ida_dbg.run_to(self.mu.reg_read(self.REG_MAP["pc"]))
        print("[+] Waiting Ida...")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

        for reg_name in self.REG_MAP.keys():
            if "w" in reg_name:
                continue
            uc_value = self.mu.reg_read(self.REG_MAP[reg_name])
            ida_value = idc.get_reg_value(reg_name)
            if ida_value & 0xb4ff000000000000 == 0xb400000000000000:
                ida_value = ida_value & 0xffffffffffffff
            print(f"{reg_name} uc: 0x{uc_value:x} ida: 0x{ida_value:x}")
            if uc_value != ida_value:
                return True 
        return False

    def _collect_register_state(self):
        """收集寄存器状态"""
        registers = {}
        registers["sp"] = hex(idc.get_reg_value("sp"))
        registers["pc"] = hex(idc.get_reg_value("pc"))
        
        for i in range(31):
            reg_value = idc.get_reg_value(f"x{i}")
            # 处理特殊地址格式
            if reg_value & 0xb4ff000000000000 == 0xb400000000000000:
                reg_value = reg_value & 0xffffffffffffff
            print(f"x{i} = " + hex(reg_value))
            registers[f"x{i}"] = hex(reg_value)
        
        base = idaapi.get_imagebase()
        registers["base"] = hex(base)
        
        return registers

    # ==============================
    # 主函数 - 集成原有脚本的main函数
    # ==============================

    def main(self, endaddr_relative:int, so_name: str = "", tpidr_value_input: int = None, enable_tenet=False, user_path:str = "."):
        """主函数 - 集成原有脚本的main函数功能"""
        dump_round = 0
        while dump_round < ROUND_MAX:
            print("Emulate ARM64 code")
            
            # 初始化
            self.dumped_range = []
            self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            self.md.detail = True
            
            # 重新初始化Unicorn引擎
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            self.last_registers.clear()
            
            self.BASE = 0
            self.tpidr_value = None
            self.last_regs = None
            self.run_range = (0, 0)
            
            self.trace_log = None
            self.log_file = None
            
            # 创建转储目录
            now_time_stamp = str(int(time.time()))
            self.dump_path = f"{user_path}/dump_{now_time_stamp}"
            os.mkdir(self.dump_path)

            # 收集寄存器状态
            registers = self._collect_register_state()
            
            self.BASE = idaapi.get_imagebase()
            file_size = os.path.getsize(idc.get_input_file_path())
            self.run_range = (self.BASE, self.BASE + file_size)

            print(f"[+] BASE = {hex(self.BASE)}")
            print("[+] DUMPING memory")
            
            # 转储寄存器指向的内存
            for reg_value in registers.values():
                if isinstance(reg_value, str):
                    reg_value = int(reg_value, 16)
                self.dump_single_segment_address(reg_value, DUMP_SINGLE_SEG_SIZE, self.dump_path, True)
            
            # 保存寄存器状态
            print("[+] DUMPING registers")
            with open(f"{self.dump_path}/regs.json", "w+") as f:
                json.dump(registers, f)

            self.BASE = idaapi.get_imagebase()
            self.tpidr_value = tpidr_value_input
            end_addr = self.BASE + endaddr_relative
            result_code = 11400
            
            if enable_tenet:
                _tenet_log_path = f"{self.dump_path}/tenet.log"
            else:
                _tenet_log_path = None

            # 执行模拟
            while result_code != 114514:
                result_code = self.main_trace(so_name, end_addr, 
                                           user_log_path=f"{self.dump_path}/uc.log", 
                                           tenet_log_path=_tenet_log_path,
                                           load_dumps_path=self.dump_path)
                if result_code == 1:
                    break
                if result_code == 2:
                    print("Update Memory")
                    self.dump_registers_memory()
                if result_code == 0:
                    break

            dump_round += 1
            
            # 检查退出条件
            if result_code == 1:
                print("[+] restart ")
                continue
            
            if result_code == 0:
                print("[!] Something Wrong")
                break

            # 检查最终状态
            if self.mu.reg_read(self.REG_MAP["pc"]) == end_addr:
                if self.check_registers():
                    print("[!] REGs check Wrong, Breakpoint could lead to this error")
                else:
                    print("[+] Finish!")
            else:
                print("[!] Something Wrong")
            break

    # ==============================
    # 清理方法 - 重写父类方法
    # ==============================

    def cleanup(self):
        """重写：清理资源，包括IDA相关资源"""
        # 调用父类清理方法
        super().cleanup()
        
        # 清理IDA特定的资源
        self.dumped_range.clear()


if __name__ == "__main__":
    # 创建IDA集成模拟器实例
    emulator = IDAArm64Emulator()
    
    # 运行模拟
    emulator.main(0x0000, tpidr_value_input=None)
    
    # 清理资源
