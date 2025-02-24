#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import base64
import hashlib
import time
import sys
from pwn import *

s_0 = "1110111"
s_1 = "1001001"
s_2 = "1011101"
s_3 = "1011011"
s_4 = "0111010"
s_5 = "1101011"
s_6 = "1101111"
s_7 = "1110010"
s_8 = "1111111"
s_9 = "1111011"
digits = [s_0, s_1, s_2, s_3, s_4, s_5, s_6, s_7, s_8, s_9]
size = 7
check = [3, 9, 13, 19, 25, 29, 35]

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(time.time(), "solving pow ...");
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    print(time.time(), "done.");
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

def solve_game(r):
    games = r.recvlines(4)[-1].decode().split(" ")[-6];
    print("start to play", games, "times ...")

    for k in range(int(games)):
        s = r.recvuntil(b" = ?").decode().split(" ")[-3];
        s = base64.b64decode(s);
        tmp = s.decode('utf-8').split("\n");
        ouput = ""
        for i in range(len(tmp[1]) // 7):
            start = i*size
            op = '\n'.join([tmp[0][start:start+size], tmp[1][start:start+size],
                            tmp[2][start:start+size], tmp[3][start:start+size], tmp[4][start:start+size]])
            # print(op)
            record = ""
            for j in check:
                if op[j] != " ": record += "1"
                else: record += "0"
            try:
                number = digits.index(record)
                ouput += str(number)
            except:
                if op[11] == "•": ouput += "/"
                elif op[19] == "╳": ouput += "*"
                elif op[19] == "┼": ouput += "+"
                else: ouput += "-"
                continue
        
        result = int(eval(ouput));
        print("expression =", ouput, ", result =", result)
        r.sendline(str(result).encode('ascii'))

if __name__ == "__main__":
    r = None
    if len(sys.argv) == 2: r = remote('localhost', int(sys.argv[1]))
    elif len(sys.argv) == 3: r = remote(sys.argv[2], int(sys.argv[1])) # ./solpow.py 10681 up.zoolab.org 
    else: r = process('./pow.py')

    solve_pow(r);
    solve_game(r);
    r.interactive();
    r.close();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
# python lab1/solpow.py 10681 up.zoolab.org