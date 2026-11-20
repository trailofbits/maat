import pytest

from maat import ARCH, OS, STOP, Cst, MaatEngine, Var


@pytest.mark.parametrize("source", ["register", "memory"])
@pytest.mark.parametrize("selector", range(4))
def test_shufpd(source, selector):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    dst = (0x11, 0x22)
    src = (0x33, 0x44)
    m.cpu.zmm0 = Cst(512, dst[0] | (dst[1] << 64))
    src_value = src[0] | (src[1] << 64)
    if source == "register":
        m.cpu.zmm1 = Cst(512, src_value)
        opcode = bytes.fromhex("66 0f c6 c1")  # SHUFPD XMM0, XMM1, imm8
    else:
        m.cpu.rax = 0x2000
        m.mem.write(0x2000, src_value.to_bytes(16, "little"))
        opcode = bytes.fromhex("66 0f c6 00")  # SHUFPD XMM0, [RAX], imm8
    m.mem.write(0x1000, opcode + bytes([selector]))

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert m.cpu.zmm0.as_uint() == dst[selector & 1] | (src[selector >> 1] << 64)


def test_int80_resumes_after_uname():
    m = MaatEngine(ARCH.X86, OS.LINUX)
    m.mem.map(0x1000, 0x3fff)
    m.mem.write(0x1000, bytes.fromhex("cd 80"))
    m.cpu.eax = 122  # i386 uname
    m.cpu.ebx = 0x2000
    m.cpu.esp = 0x3000

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert m.cpu.eax.as_uint() == 0
    assert m.mem.read(0x2000, 5).as_uint() == int.from_bytes(b"Linux", "little")
    assert m.cpu.eip.as_uint() == 0x1002


def test_pminub_symbolic_unsigned_lane():
    m = MaatEngine(ARCH.X86)
    m.mem.map(0x1000, 0x2fff)
    m.mem.write(0x1000, bytes.fromhex("0f da 00"))  # PMINUB MM0, [EAX]
    m.cpu.eax = 0x2000
    m.cpu.mm0 = 0x80
    m.mem.write(0x2000, Var(8, "lane"))

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    result = m.cpu.mm0
    assert result.is_symbolic(m.vars)
    for lane in (0x7f, 0xff):
        m.vars.set("lane", lane, 8)
        assert result.as_uint(m.vars) == min(0x80, lane)


def test_pslldq_falls_through():
    m = MaatEngine(ARCH.X86)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("66 0f 73 f8 01 41"))  # PSLLDQ XMM0, 1; INC ECX
    m.cpu.zmm0 = Cst(512, 1)
    m.cpu.ecx = 0

    assert m.run_from(0x1000, 2) == STOP.INST_COUNT
    assert m.cpu.zmm0.as_uint() == 0x100
    assert m.cpu.ecx.as_uint() == 1
    assert m.cpu.eip.as_uint() == 0x1006


@pytest.mark.parametrize("prefix", ["", "48"], ids=["legacy-format", "64-bit-format"])
def test_x64_fxsave_fxrstor_round_trip(prefix):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    m.mem.write(0x1000, bytes.fromhex(prefix + " 0f ae 00"))  # FXSAVE [RAX]
    m.mem.write(0x1010, bytes.fromhex(prefix + " 0f ae 08"))  # FXRSTOR [RAX]
    m.cpu.rax = 0x2000
    value = (0x12345678 << 64) | 0xabcdef01
    m.cpu.zmm0 = Cst(512, value)

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert m.mem.read(0x2000 + 160, 16).as_uint() == value
    m.cpu.zmm0 = Cst(512, 0)
    assert m.run_from(0x1010, 1) == STOP.INST_COUNT
    assert m.cpu.zmm0.as_uint() == value
