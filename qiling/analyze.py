from qiling import Qiling
from qiling.const import QL_VERBOSE

from unicorn.x86_const import *

def hook_syscall(ql: Qiling):
    ql.log.debug(f'!!! SYSCALL {ql.arch.regs.arch_pc:#x}: {ql.arch.regs.eax:#x}')
    return (0, 0)

def mem_read(ql: Qiling, access: int, address: int, size: int, value: int):
    ql.log.debug(f'intercepted a memory read from {address:#x} at {ql.arch.regs.arch_pc:#x}')

if __name__ == "__main__":
    ql = Qiling(["C:\\Users\\mauri\\Desktop\\qiling-sample\\lul.exe"],
                "C:\\Users\\mauri\\Desktop\\qiling-sample", verbose=QL_VERBOSE.DEBUG, libcache=True)

    ql.hook_mem_read(mem_read)
    ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)

    ql.run()
