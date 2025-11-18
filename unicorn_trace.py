import glob
import json
import re
import os
from unicorn import *
from unicorn.arm64_const import *
from unicorn_trace.unicorn_class import Arm64Emulator  # 导入父类

class SelfRunArm64Emulator(Arm64Emulator):
    """自定义 ARM64 模拟器，继承自 Arm64Emulator"""
    
    def __init__(self, heap_base=0x1000000, heap_size=0x90000):
        """初始化模拟器"""
        super().__init__(heap_base, heap_size)
        self.BASE = 0
        self.run_range = (0, 0)
        self.tpidr_value = None

    def setup_from_files(self, so_path, load_path):
        """从文件设置模拟器参数"""
        # 读取基础地址
        with open(f"{load_path}/regs.json", "r") as f:
            tmp = json.load(f)
            self.BASE = int(tmp["base"], 16)
        
        # 计算运行范围
        file_size = os.path.getsize(so_path)
        self.run_range = (self.BASE, self.BASE + file_size)
        
        return self.BASE

    def custom_main_trace(self, so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps"):
        """自定义主要模拟函数"""
        try:        
            # 初始化日志文件
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

            # 映射堆内存
            self.mu.mem_map(self.HEAP_BASE, self.HEAP_SIZE)

            # 设置调试钩子
            start_addr = self.mu.reg_read(self.REG_MAP["pc"])
            self.hooks.append(self.mu.hook_add(UC_HOOK_CODE, self.debug_hook_code, begin=start_addr))

            # 开始模拟
            self.mu.emu_start(start_addr, end_addr)

        except UcError as e:
            return self._handle_uc_error(e)
        except Exception as e:
            print(f"发生未知错误: {e}")    
            self.my_reg_logger()
            return 0
        finally:
            print(f"Trace END!")
            # 清理资源
            self.cleanup()
        
        return 114514

    def _handle_uc_error(self, e):
        """处理Unicorn错误"""
        print("ERROR: %s" % e)
        self.my_reg_logger()
        return 0

# ==============================
# 主函数
# ==============================

def main(endaddr_relative:int, so_path:str, tpidr_value_input: int = None, load_path:str = ".", save_path:str = "."):
    """主函数"""
    print("Emulate ARM64 code")
    
    # 创建模拟器实例
    emulator = SelfRunArm64Emulator()
    
    # 设置参数
    emulator.tpidr_value = tpidr_value_input
    
    # 从文件设置基础参数
    BASE = emulator.setup_from_files(so_path, load_path)
    
    # 计算结束地址
    end_addr = BASE + endaddr_relative

    # 提取so文件名
    so_name = so_path.split("/")[-1]
    
    # 执行模拟
    result_code = emulator.custom_main_trace(so_name, end_addr, 
                                           user_log_path=f"{save_path}/sim.log", 
                                           tenet_log_path=f"{save_path}/tenet.log",
                                           load_dumps_path=load_path)
    print("[+] Finish!")
    
def combine_logs(path, pattern, output_filename):
    """Combine all log files matching pattern into output file"""
    files = glob.glob(f'{path}/**/{pattern}', recursive=True)
    if not files:
        print(f"No {pattern} files found")
        return False
        
    with open(output_filename, 'w', encoding='utf-8') as outfile:
        for file in files:
            with open(file, 'r', encoding='utf-8') as infile:
                outfile.write(infile.read())
                outfile.write("\n")
    print(f"Combined {len(files)} files into {output_filename}")
    return True

def run_all(dump_path:str, so_path:str, end_addr_relative:int, tdpr:int=None):
    files = os.listdir(dump_path)
    for i in files:
        pattern = r"dump_\d+$"
        match = re.search(pattern, i)
        if match :
            main(end_addr_relative, 
                so_path,
                tpidr_value_input=tdpr,
                load_path=f"{dump_path}/{i}",
                save_path=f"{dump_path}/{i}")

    combine_logs(dump_path,'uc.log', 'combined_uc.log')
    combine_logs(dump_path,'sim.log', 'combined_sim.log')
    combine_logs(dump_path,'tenet.log', 'combined_tenet.log')

def run_once(dump_path:str, so_path:str,end_addr_relative:int, tdpr:int=None):
    main(end_addr_relative, 
        so_path, 
        tpidr_value_input=tdpr,
        load_path=dump_path,
        save_path=dump_path)

if __name__ == "__main__":
    run_all("./dumps","/path/to/your.so", 0x000000)