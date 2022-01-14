#!/usr/bin/env python3

import sys
from hexdump import hexdump
from unicorn import *
from unicorn.arm64_const import *
from capstone import *


BASE_ADDR = 0x1_0000_0000 # base address
BASE_SIZE = 100 * 1024 # enough memory to fit the binary image

HEAP_ADDR = 0x5_0000_0000 # arbitrary address
HEAP_SIZE = 0x21_000 # some default heap size

STACK_ADDR = 0x9_0000_0000 # arbitrary address
STACK_SIZE = 0x21_000 # some default stack size
STACK_TOP = STACK_ADDR + STACK_SIZE # stack grows downwards


def hook_code(uc, address, size, user_data):
    code = BINARY[address-BASE_ADDR:address-BASE_ADDR+size]
    for i in md.disasm(code, address):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        # stop emulation when function returns
        if i.mnemonic == "ret":
            uc.emu_stop()
        #sys.stdin.read(1)
    return True


# def hook_invalid(mu, access, address, size, value, user_data):
#     print("[+] Invalid memory access: 0x%x" % (address))
#     sys.stdin.read(1)
#     return True
        

# def hook_intr(mu, intno, user_data):
#     print("[+] CPU interrupt: 0x%x" % (intno))
#     if intno != 0x2:
#         mu.emu_stop()
#         return True

#     x16 = mu.reg_read(UC_ARM64_REG_X16) 
#     print("[+] \tx16: 0x%x (%d)" % (x16, x16))

#     x0 = mu.reg_read(UC_ARM64_REG_X0)
#     if x0 != 0x0:
#         hexdump.hexdump(mu.mem_read(x0, 16))
#         sys.stdin.read(1)
#     return True


try:
    print("[+] Init")
    md = Cs(CS_ARCH_ARM64, UC_MODE_ARM)
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    print("[+] Map memory")
    mu.mem_map(BASE_ADDR, BASE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(HEAP_ADDR, HEAP_SIZE)

    print("[+] Load and map binary")
    BINARY = open("./demo", "rb").read()
    mu.mem_write(BASE_ADDR, BINARY)

    print("[+] Add hooks")
    mu.hook_add(UC_HOOK_CODE, hook_code)
    # mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_invalid)
    # mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_invalid)
    # mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_invalid)
    # mu.hook_add(UC_HOOK_INTR, hook_intr)
    
    print("[+] Setup stack pointer")
    mu.reg_write(UC_ARM64_REG_SP, STACK_TOP)

    # write our input to heap
    mu.mem_write(HEAP_ADDR, b"A" * 10)
    mu.reg_write(UC_ARM64_REG_X0, HEAP_ADDR)

    start_addr = 0x1_0000_7e78 # check_key
    end_addr = 0x1_0000_7ed8 # strcmp
    print("[+] Starting at: 0x%x" % start_addr)
    mu.emu_start(start_addr, end_addr)

    # print x0 and x1 values
    print("[+] x0: 0x%x" % (mu.reg_read(UC_ARM64_REG_X0)))
    hexdump(mu.mem_read(mu.reg_read(UC_ARM64_REG_X0), 16))

    print("[+] x1: 0x%x" % (mu.reg_read(UC_ARM64_REG_X1)))
    hexdump(mu.mem_read(mu.reg_read(UC_ARM64_REG_X1), 16))  

    print("[+] Done")
except UcError as err:
    print("[E] %s" % err)
