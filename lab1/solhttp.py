from pwn import *

def get_ip_address(url):
    r = remote(url, 80)

    r.sendline(b"GET /ip HTTP/1.1")
    r.sendline(b"Host: " + url.encode('ascii'))
    r.sendline(b"Connection: close")
    r.sendline()

    # response_headers = r.recvuntil(b"\r\n\r\n").decode()
    # print(response_headers)

    response_body = r.recvall().decode()
    print(response_body)

    r.close()

if __name__ == "__main__":
    target_url = "ipinfo.io"

    get_ip_address(target_url)

# https://zhuanlan.zhihu.com/p/83373740
