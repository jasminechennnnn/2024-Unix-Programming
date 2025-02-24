#!/usr/bin/env python3
import pwn
import sys

def sol(n: str):
	globals()['sol' + str(n)]()

def sol0():
	# addsub1:
    #     eax = 0x470704e8
    #     eax = eax + 0x8580787e
    #     eax = eax - 0xdfe188fd
	# ======
	# ======
	s = 'addsub1:\n'
	p = r.recvuntil(s.encode()).decode()
	print(p)

	s = '======'
	p = r.recvuntil(s.encode()).decode()
	p = p[:-len(s)].replace('\t', '')
	print(p)

	res = {}
	exec(p, res)

	s = ('mov eax,' + hex(res['eax']))
	print(s)
	r.sendline(s.encode())
	
def sol1():
	# addsub2:
    #     final = val1 + val2 - val3
    # ======
    #     val1 @ 0x600000-600004
    #     val2 @ 0x600004-600008
    #     val3 @ 0x600008-60000c
    #     final @ 0x60000c-600010
    # ======
    s = '''
        addsub2:
            mov eax, [0x600000]
            add eax, [0x600004]
            sub eax, [0x600008]
            mov [0x60000c], eax
    '''
    print(s)
    r.send(s.encode())

def sol2():
    # bubble: bubble sort for 10 integers
    # ======
    #       a[0] @ 0x600000-600004
    #       a[1] @ 0x600004-600008
    #       a[2] @ 0x600008-60000c
    #       a[3] @ 0x60000c-600010
    #       a[4] @ 0x600010-600014
    #       a[5] @ 0x600014-600018
    #       a[6] @ 0x600018-60001c
    #       a[7] @ 0x60001c-600020
    #       a[8] @ 0x600020-600024
    #       a[9] @ 0x600024-600028
    # ======
	s = 'bubble: bubble sort for 10 integers\n======\n'
	p = r.recvuntil(s.encode()).decode()
	print(p)
	
	s = ''
	lst = []
	while True:
		p = r.recvline()[:-1].decode()
		print(p)
		if p == '======':
			break
		lst.append(p[p.find('0x'):p.find('-')])
		for i in range(len(lst) - 1, 0, -1):
			p, q = lst[i], lst[i - 1]
			s += 'mov eax, [' + q + ']\n'
			s += 'mov ebx, [' + p + ']\n'
			s += 'cmp eax, ebx\n'
			s += 'cmovns eax, [' + p + ']\n'
			s += 'cmovns ebx, [' + q + ']\n'
			s += 'mov [' + q + '], eax\n'
			s += 'mov [' + p + '], ebx\n'
	print(s)
	r.send(s.encode())

def sol3():
    # clear17: clear bit-17 in eax (zero-based index)
    # ======
    # ======
    s = '''
        mov ebx, 1
        shl ebx, 17
        not ebx
        and eax, ebx
    '''
    print(s)
    r.send(s.encode())
	
def sol4():
    # dec2ascii: convert the value (0-9) in AL to its ASCII character
    # ======
    # ======
    s = '''
        add al, 0x30
    '''
    print(s)
    r.send(s.encode())   

def sol5():
    # dispbin:
    #     given a number in AX, store the corresponding bit string in str1.
    #     for example, if AX = 0x1234, the result should be:       
    #     str1 = 0001001000111000
    # ======
    #     str1 @ 0x600000-600014
    # ======
    s = ''	
    for i in range(16):
        s += 'mov bx, ax\n'
        s += 'shr bx, {}\n'.format(15 - i)
        s += 'and bx, 0x1\n'
        s += 'add bx, 0x30\n'
        s += 'mov [0x600000 + {}], bl\n'.format(i)
    print(s)
    r.send(s.encode())
	
def sol6():
	# eval1:
    #     Rval = -Xval + (Yval – Zval)
    # ======
    #     Xval @ 0x600000-600004
    #     Yval @ 0x600004-600008
    #     Zval @ 0x600008-60000c
    #     Rval @ 0x60000c-600010
    # ======
	s = '''
        mov eax, [0x600000]
        neg eax
        mov ebx, [0x600004]
        mov ecx, [0x600008]
        sub ebx, ecx
        add eax, ebx
        mov [0x60000c], eax
    '''
	print(s)
	r.send(s.encode())

def sol7():
	# isolatebit:
    #     get the value bit-11 ~ bit-5 in AX and store the result in val1
    #     (zero-based bit index)
    # ======
    #     val1 @ 0x600000-600001
    #     val2 @ 0x600001-600002
    # ======
	s = '''
        shr ax, 5
        and al, 0x7f
        mov [0x600000], al
    '''
	print(s)
	r.send(s.encode())

def sol8():
	# leax:
    #     eax = edi * 2
    #     ebx = edi * 3
    #     ecx = edi * 5
    #     edx = edi * 9
    # ======
    # ======
	s = '''
        mov eax, edi
        shl eax, 1
        mov ebx, edi
        shl ebx, 1
        add ebx, edi
        mov ecx, edi
        shl ecx, 2
        add ecx, edi
        mov edx, edi
        shl edx, 3
        add edx, edi
    '''
	print(s)
	r.send(s.encode())
	
def sol9():
	# loop15:
    #     str1 is a string contains 15 lowercase and uppercase alphbets.
    #     implement a loop to convert all alplabets to lowercase,
    #     and store the result in str2.
    # ======
    #     str1 @ 0x600000-600010
    #     str2 @ 0x600010-600020
    # ======
	s = '''
        mov rcx, 0
        loop15:
            cmp rcx, 15
            jge exit
            mov al, [0x600000 + rcx]
            or al, 0x20
            mov [0x600010 + rcx], al
            inc rcx
            jmp loop15

        exit:
    '''
	print(s)
	r.send(s.encode())

def sol10():
    # math1: unsigned arithmetic
    #         var4 = (var1 + var2) * var3
    # ======
    #     var1 @ 0x600000-600004
    #     var2 @ 0x600004-600008
    #     var3 @ 0x600008-60000c
    #     var4 @ 0x60000c-600010
    # ======
	s = '''
        mov eax, [0x600000]
        add eax, [0x600004]
        mov ecx, [0x600008]
        mul ecx
        mov [0x60000c], eax
    '''
	print(s)
	r.send(s.encode())

def sol11():
    # math2: signed arithmetic
    #         eax = (-var1 * var2) + var3
    # ======
    #     var1 @ 0x600000-600004
    #     var2 @ 0x600004-600008
    #     var3 @ 0x600008-60000c
    # ======
    s = '''
        mov eax, [0x600000]
        neg eax
        mov ecx, [0x600004]
        imul ecx
        add eax, [0x600008]
    '''
    print(s)
    r.send(s.encode())

def sol12():
	# math3: 32-bit unsigned arithmetic
    #     var4 = (var1 * 5) / (var2 - 3)
    #     note: overflowed part should be truncated
    # ======
    #     var1 @ 0x600000-600004
    #     var2 @ 0x600004-600008
    #     var4 @ 0x600008-60000c
    # ======
	s = '''
        mov eax, [0x600000]
        mov ebx, 5
        mul ebx
        mov ecx, [0x600004]
        sub ecx, 3
        div ecx
        mov [0x600008], eax
    '''
	print(s)
	r.send(s.encode())

def sol13():
	# math4: 32-bit signed arithmetic
    #     var4 = (var1 * -5) / (-var2 % var3)
    #     note: overflowed part should be truncated
    # ======
    #     var1 @ 0x600000-600004
    #     var2 @ 0x600004-600008
    #     var3 @ 0x600008-60000c
    #     var4 @ 0x60000c-600010
    # ======
    s = '''
		mov eax, [0x600004]
		neg eax
		cdq
		idiv DWORD PTR [0x600008]
		mov ebx, edx

		imul eax, [0x600000], -0x5

		cdq
		idiv ebx
		mov [0x60000c], eax
    '''
    print(s)
    r.send(s.encode())

def sol14():
	# math5: 32-bit signed arithmetic
    #     var3 = (var1 * -var2) / (var3 - ebx)
    #     note: overflowed part should be truncated
    # ======
    #     var1 @ 0x600000-600004
    #     var2 @ 0x600004-600008
    #     var3 @ 0x600008-60000c
    # ======
    s = '''
        mov eax, [0x600004]
        neg eax
        imul eax, [0x600000]
        sub [0x600008], ebx
        idiv eax, [0x600008]
        mov [0x600008], eax
    '''
    print(s)
    r.send(s.encode())

def sol15():
    # minicall: implement a minimal function call in the emulator
    # ===== THE CODE
    #     call   a
    #     jmp    exit

    # a:  ; function a - read ret-addr in rax
    #     pop    rax
    #     push   rax
    #     ret
    # exit:
    # ======
    # ======
    s = '''
        minicall:
        call a
        jmp exit

        a:
            pop rax
            push rax
            ret

        exit:
    '''
    print(s)
    r.send(s.encode())

def sol16():
	# mulbyshift: multiply val1 by 26 and store the result in val2
    # ======
    #     val1 @ 0x600000-600004
    #     val2 @ 0x600004-600008
    # ======
	s = '''
        mov eax, [0x600000]
        mov ebx, 26
        mul ebx
        mov [0x600004], eax
    '''
	print(s)
	r.send(s.encode())

def sol17():
	# posneg: test if registers are positive or negative.
    #     if ( eax >= 0 ) { var1 = 1 } else { var1 = -1 }
    #     if ( ebx >= 0 ) { var2 = 1 } else { var2 = -1 }
    #     if ( ecx >= 0 ) { var3 = 1 } else { var3 = -1 }
    #     if ( edx >= 0 ) { var4 = 1 } else { var4 = -1 }
    # ======
    #     var1 @ 0x600000-600004
    #     var2 @ 0x600004-600008
    #     var3 @ 0x600008-60000c
    #     var4 @ 0x60000c-600010
    # ======
	s = '''
        mov DWORD PTR [0x600000], 0x1
        cmp eax, 0x0
        jge non_neg_1 ; Jumps based on signed comparisons
        neg DWORD PTR [0x600000]
        non_neg_1:    
            mov DWORD PTR [0x600004], 0x1
            cmp ebx, 0x0
            jge non_neg_2
            neg DWORD PTR [0x600004]
        non_neg_2:
            mov DWORD PTR [0x600008], 0x1
            cmp ecx, 0x0
            jge non_neg_3
            neg DWORD PTR [0x600008]
        non_neg_3:
            mov DWORD PTR [0x60000c], 0x1
            cmp edx, 0x0
            jge non_neg_4
            neg DWORD PTR [0x60000c]
        non_neg_4:
    '''
	print(s)
	r.send(s.encode())

def sol18():
    # recur: implement a recursive function

    #    r(n) = 0, if n <= 0
    #         = 1, if n == 1
    #         = 2*r(n-1) + 3*r(n-2), otherwise

    #    please call r(21) and store the result in RAX
    # ======
    # ======
	s = 'please call r('
	p = r.recvuntil(s.encode()).decode()
	print(p)

	s = ') and store the result in RAX\n'
	p = r.recvuntil(s.encode()).decode()
	print(p)

	s = 'mov rdi, ' + p[:-len(s)] + '\n'
	s += '''
            call R
            jmp Exit
        R:
                enter 0x10, 0

                cmp rdi, 0x1
                jg C2
                je C1
            C0:
                mov rax, 0x0
                jmp End
            C1:
                mov rax, 0x1
                jmp End
            C2:
                dec rdi
                mov [rbp-0x8], rdi
                call R
                mov [rbp-0x10], rax

                mov rdi, [rbp-0x8]
                dec rdi
                call R

                imul rax, 0x3
                imul rbx, [rbp-0x10], 0x2
                add rax, rbx

            End:
                leave
                ret
        Exit:
	'''
	print(s)
	r.send(s.encode())

def sol19():
	# swapmem: swap the values in val1 and val2
    # ======
    #     val1 @ 0x600000-600008
    #     val2 @ 0x600008-600010
    # ======
	s = '''
        mov rcx, [0x600000]
        mov rdx, [0x600008]
        mov [0x600000], rdx
        mov [0x600008], rcx
    '''
	print(s)
	r.send(s.encode())

def sol20():
	# swapreg: swap the values in RAX and RBX
    # ======
    # ======
	s = '''
        mov rcx, rax
        mov rax, rbx
        mov rbx, rcx
    '''
	print(s)
	r.send(s.encode())

def sol21():
	# tolower: convert the single character in val1 to uppercase and store in val2
    # ======
    #       val1 @ 0x600000-600001
    #       val2 @ 0x600001-600002
    # ======
    s = '''
        mov al, [0x600000]
        and al, 0xdf
        mov [0x600001], al
    '''
    print(s)
    r.send(s.encode())
	
def sol22():
	# ul+lu: convert the alphabet in CH from upper to lower or from lower to upper
    # ======
    # ======
    s = '''
        add ch, 0x20
    '''
    print(s)
    r.send(s.encode())	
				
if __name__ == '__main__':
	if len(sys.argv) != 2:
		sys.exit('Usage: ' + sys.argv[0] + ' [chal]')
	chal = int(sys.argv[1])

	r = pwn.remote('up.zoolab.org', 2500 + chal)

	sol(chal)

	s = 'done:'
	print(s)
	r.sendline(s.encode())

	r.interactive()
	r.close()