from maat import *
from pathlib import Path
import pytest
m = MaatEngine(ARCH.ARM32)
# EOR R0, R0
# ADD R0, R0, #1
# MOV R1, R0
# ADD R0, R0, #10
buf = b'\x00\x00\x20\xe0\x01\x00\x80\xe2\x00\x10\xa0\xe1\x0a\x00\x80\xe2\x00\x40\x0f\xe1'
m.mem.map(0x100, 0xFFF, PERM.RWX)
m.mem.write(0x100, buf, len(buf))
m.cpu.R3 = 0xDEADBEEF
m.cpu.R4 = 0xDEADCAFE
print("PC = " + str(m.cpu.PC) + "\n*PC = " + str(m.mem.read(m.cpu.PC.as_int(), 4)))
print("R0 = " + str(m.cpu.R0.as_int()) + "\nR1 = " + str(m.cpu.R1.as_int()))
m.run_from(0x100, 1)
print("PC = " + str(m.cpu.PC) + "\n*PC = " + str(m.mem.read(m.cpu.PC.as_int(), 4)))
print("R0 = " + str(m.cpu.R0.as_int()) + "\nR1 = " + str(m.cpu.R1.as_int()))
assert m.cpu.R0.as_int() == 0
m.run(1)
print("PC = " + str(m.cpu.PC) + "\n*PC = " + str(m.mem.read(m.cpu.PC.as_int(), 4)))
print("R0 = " + str(m.cpu.R0.as_int()) + "\nR1 = " + str(m.cpu.R1.as_int()))
#assert m.cpu.R0.as_int() == 1
m.run(1)
print("PC = " + str(m.cpu.PC) + "\n*PC = " + str(m.mem.read(m.cpu.PC.as_int(), 4)))
print("R0 = " + str(m.cpu.R0.as_int()) + "\nR1 = " + str(m.cpu.R1.as_int()))
#assert m.cpu.R1.as_int() == 1
m.run(1);
print("PC = " + str(m.cpu.PC) + "\n*PC = " + str(m.mem.read(m.cpu.PC.as_int(), 4)))
print("R0 = " + str(m.cpu.R0.as_int()) + "\nR1 = " + str(m.cpu.R1.as_int())) 
m.run(1)
print("R0 = " + str(m.cpu.R0.as_int()) + "\nR1 = " + str(m.cpu.R1.as_int()) + "\nR4 = " + str(bin(m.cpu.R4.as_uint())) + "\nCPSR = " + str(bin(m.cpu.CPSR.as_uint())))
#assert m.cpu.R0.as_int() == 11