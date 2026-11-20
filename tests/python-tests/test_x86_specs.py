import pytest

from maat import ARCH, EVENT, OS, STOP, WHEN, Cst, MaatEngine, Var


@pytest.mark.parametrize("source", ["register", "same_register", "memory"])
@pytest.mark.parametrize("selector", range(4))
def test_shufpd(source, selector):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    dst = (0x11, 0x22)
    src = dst if source == "same_register" else (0x33, 0x44)
    m.cpu.zmm0 = Cst(512, dst[0] | (dst[1] << 64))
    src_value = src[0] | (src[1] << 64)
    if source == "register":
        m.cpu.zmm1 = Cst(512, src_value)
        opcode = bytes.fromhex("66 0f c6 c1")  # SHUFPD XMM0, XMM1, imm8
    elif source == "same_register":
        opcode = bytes.fromhex("66 0f c6 c0")  # SHUFPD XMM0, XMM0, imm8
    else:
        m.cpu.rax = 0x2000
        m.mem.write(0x2000, src_value.to_bytes(16, "little"))
        opcode = bytes.fromhex("66 0f c6 00")  # SHUFPD XMM0, [RAX], imm8
    m.mem.write(0x1000, opcode + bytes([selector]))

    reads = []

    def record_read(engine):
        access = engine.info.mem_access
        reads.append((access.addr.as_uint(), access.size))

    m.hooks.add(EVENT.MEM_R, WHEN.BEFORE, callbacks=[record_read])
    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert reads == ([(0x2000, 16)] if source == "memory" else [])
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


@pytest.mark.parametrize("count", [0, 1, 8, 9, 15, 16, 32, 255])
def test_pslldq_falls_through(count):
    m = MaatEngine(ARCH.X86)
    m.mem.map(0x1000, 0x1fff)
    # PSLLDQ XMM0, imm8; INC ECX
    m.mem.write(0x1000, bytes.fromhex("66 0f 73 f8") + bytes([count, 0x41]))
    value = (1 << 64) | 1
    m.cpu.zmm0 = Cst(512, value)
    m.cpu.ecx = 0

    assert m.run_from(0x1000, 2) == STOP.INST_COUNT
    assert m.cpu.zmm0.as_uint() == (value << (8 * count)) & ((1 << 128) - 1)
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


@pytest.mark.parametrize("arch", [ARCH.X86, ARCH.X64])
@pytest.mark.parametrize("equal", [False, True])
def test_cmpxchg_memory_falls_through(arch, equal):
    m = MaatEngine(arch)
    m.mem.map(0x1000, 0x2fff)
    m.mem.write(0x1000, bytes.fromhex("0f b1 0b 90"))  # CMPXCHG [EBX/RBX], ECX; NOP
    m.mem.write(0x2000, Cst(32, 1))
    if arch == ARCH.X64:
        m.cpu.rax, m.cpu.rbx, m.cpu.rcx = 1 if equal else 2, 0x2000, 3
    else:
        m.cpu.eax, m.cpu.ebx, m.cpu.ecx = 1 if equal else 2, 0x2000, 3

    assert m.run_from(0x1000, 2) == STOP.INST_COUNT
    pc = m.cpu.rip if arch == ARCH.X64 else m.cpu.eip
    acc = m.cpu.rax if arch == ARCH.X64 else m.cpu.eax
    assert pc.as_uint() == 0x1004
    assert acc.as_uint() == 1
    assert m.cpu.zf.as_uint() == equal
    assert m.mem.read(0x2000, 4).as_uint() == (3 if equal else 1)


@pytest.mark.parametrize("arch,width,opcode", [
    (ARCH.X86, 8, "0f b0"), (ARCH.X86, 16, "66 0f b1"),
    (ARCH.X64, 8, "0f b0"), (ARCH.X64, 16, "66 0f b1"), (ARCH.X64, 64, "48 0f b1"),
])
@pytest.mark.parametrize("memory", [False, True], ids=["register", "memory"])
def test_cmpxchg_symbolic_accumulator(arch, width, opcode, memory):
    m = MaatEngine(arch)
    m.mem.map(0x1000, 0x2fff)
    # Compare the accumulator with BL/BX/RBX or [EBX/RBX], with CL/CX/RCX as source.
    code = bytes.fromhex(opcode) + bytes([0x0b if memory else 0xcb])
    m.mem.write(0x1000, code + b"\x90")
    reg_width = 64 if arch == ARCH.X64 else 32
    if arch == ARCH.X64:
        m.cpu.rax = Var(reg_width, "acc")
        m.cpu.rbx, m.cpu.rcx = 0x2000 if memory else 7, 9
    else:
        m.cpu.eax = Var(reg_width, "acc")
        m.cpu.ebx, m.cpu.ecx = 0x2000 if memory else 7, 9
    if memory:
        m.mem.write(0x2000, Cst(width, 7))

    writes = []

    def record_write(engine):
        access = engine.info.mem_access
        writes.append((access.addr.as_uint(), access.size, access.value))

    m.hooks.add(EVENT.MEM_W, WHEN.BEFORE, callbacks=[record_write])
    assert m.run_from(0x1000, 2) == STOP.INST_COUNT
    assert (m.cpu.rip if arch == ARCH.X64 else m.cpu.eip).as_uint() == 0x1001 + len(code)
    if memory:
        assert [(addr, size) for addr, size, _ in writes] == [(0x2000, width // 8)]
        dest = m.mem.read(0x2000, width // 8)
    else:
        assert writes == []
        dest = m.cpu.rbx if arch == ARCH.X64 else m.cpu.ebx
    acc = m.cpu.rax if arch == ARCH.X64 else m.cpu.eax
    upper = 1 << width if width < reg_width else 0
    for old_acc, equal in ((upper | 7, True), (upper | 6, False)):
        m.vars.set("acc", old_acc, reg_width)
        assert acc.as_uint(m.vars) == upper | 7
        assert m.cpu.zf.as_uint(m.vars) == equal
        assert dest.as_uint(m.vars) == (9 if equal else 7)
        if memory:
            assert writes[0][2].as_uint(m.vars) == dest.as_uint(m.vars)


def test_cmpxchg_accumulator_is_destination():
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("48 0f b1 c8"))  # CMPXCHG RAX, RCX
    m.cpu.rax = Var(64, "acc")
    m.cpu.rcx = 9

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    m.vars.set("acc", 7, 64)
    assert m.cpu.rax.as_uint(m.vars) == 9
    assert m.cpu.zf.as_uint(m.vars) == 1


@pytest.mark.parametrize("width,opcode", [(32, "f0 0f b1 08"), (64, "f0 48 0f b1 08")])
@pytest.mark.parametrize("equal", [False, True])
def test_locked_cmpxchg_uses_original_address(width, opcode, equal):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    # LOCK CMPXCHG [RAX], ECX/RCX. Set upper bits to exercise the 32-bit failure path.
    address = 0x100002000
    m.mem.map(address, address + 0xfff)
    m.mem.write(0x1000, bytes.fromhex(opcode))
    old = (address & ((1 << width) - 1)) if equal else 7
    m.mem.write(address, Cst(width, old))
    m.cpu.rax, m.cpu.rcx = address, 9
    accesses = []

    def record_read(engine):
        access = engine.info.mem_access
        accesses.append(("read", access.addr.as_uint(), access.size))

    def record_write(engine):
        access = engine.info.mem_access
        accesses.append(("write", access.addr.as_uint(), access.size, access.value.as_uint()))

    m.hooks.add(EVENT.MEM_R, WHEN.BEFORE, callbacks=[record_read])
    m.hooks.add(EVENT.MEM_W, WHEN.BEFORE, callbacks=[record_write])
    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    result = 9 if equal else old
    assert accesses == [("read", address, width // 8), ("write", address, width // 8, result)]
    assert m.mem.read(address, width // 8).as_uint() == result
    assert m.cpu.rax.as_uint() == (address if equal else old)


@pytest.mark.parametrize("opcode,src", [("d3 e8", 0), ("0f ad d0", 0), ("0f ad d0", 1)])
@pytest.mark.parametrize("count", [0, 1, 32, 33])
@pytest.mark.parametrize("old_of", [0, 1])
def test_right_shift_overflow(opcode, src, count, old_of):
    m = MaatEngine(ARCH.X86)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex(opcode))  # SHR EAX,CL or SHRD EAX,EDX,CL
    m.cpu.eax, m.cpu.edx, m.cpu.ecx = 0x80000000, src, count
    m.cpu.of = old_of

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    shifted = count & 31
    assert m.cpu.eax.as_uint() == ((src << 31) | 0x40000000 if shifted else 0x80000000)
    assert m.cpu.of.as_uint() == (1 ^ src if shifted else old_of)


@pytest.mark.parametrize("prefix,reg", [("", "rcx"), ("44", "r9")])
def test_xchg_memory_clears_upper_register(prefix, reg):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    m.mem.write(0x1000, bytes.fromhex(prefix + " 87 0b"))
    m.cpu.rbx = 0x2000
    setattr(m.cpu, reg, 0xffffffff00000003)
    m.mem.write(0x2000, Cst(32, 1))

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert getattr(m.cpu, reg).as_uint() == 1
    assert m.mem.read(0x2000, 4).as_uint() == 3


@pytest.mark.parametrize("reg,modrm", [("zmm0", 0xc1), ("zmm7", 0xf9)])
def test_x86_vmovdqa_clears_full_destination(reg, modrm):
    m = MaatEngine(ARCH.X86)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("c5 f9 6f") + bytes([modrm]))
    setattr(m.cpu, reg, Cst(512, (1 << 512) - 1))
    m.cpu.zmm1 = Cst(512, (1 << 511) | 2)

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert getattr(m.cpu, reg).as_uint() == 2


@pytest.mark.parametrize("width,prefix", [(16, "66 f3"), (32, "f3"), (64, "f3 48")])
@pytest.mark.parametrize("same_register", [True, False])
def test_lzcnt(width, prefix, same_register):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x1fff)
    # LZCNT AX/EAX/RAX, AX/EAX/RAX or CX/ECX/RCX
    m.mem.write(0x1000, bytes.fromhex(prefix + " 0f bd") + bytes([0xc0 if same_register else 0xc1]))
    for value in (0, 1, 1 << (width - 1)):
        m.cpu.rax = value if same_register else 0
        m.cpu.rcx = value
        expected = width - value.bit_length()
        assert m.run_from(0x1000, 1) == STOP.INST_COUNT
        assert m.cpu.rax.as_uint() == expected
        assert m.cpu.cf.as_uint() == (value == 0)
        assert m.cpu.zf.as_uint() == (expected == 0)


def test_lzcnt_symbolic():
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("f3 48 0f bd c1"))  # LZCNT RAX, RCX
    m.cpu.rcx = Var(64, "source")

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    for value in (0, 1, 0x101, 1 << 63):
        m.vars.set("source", value, 64)
        assert m.cpu.rax.as_uint(m.vars) == 64 - value.bit_length()


@pytest.mark.parametrize("arch", [ARCH.X86, ARCH.X64])
@pytest.mark.parametrize("selector", [0, 1, 2])
def test_xgetbv(arch, selector):
    m = MaatEngine(arch)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("0f 01 d0"))  # XGETBV
    m.cpu.xcr0 = 0x1000002e7
    if arch == ARCH.X64:
        m.cpu.rax = m.cpu.rdx = (1 << 64) - 1
        m.cpu.rcx = selector
    else:
        m.cpu.eax = m.cpu.edx = 0xffffffff
        m.cpu.ecx = selector

    stop = m.run_from(0x1000, 1)
    low, high = (m.cpu.rax, m.cpu.rdx) if arch == ARCH.X64 else (m.cpu.eax, m.cpu.edx)
    if selector == 0:
        assert stop == STOP.INST_COUNT
        assert (low.as_uint(), high.as_uint()) == (0x2e7, 1)
    else:
        assert stop == STOP.UNSUPPORTED_INST
        assert low.as_uint() == high.as_uint() == (1 << (64 if arch == ARCH.X64 else 32)) - 1


@pytest.mark.parametrize("arch", [ARCH.X86, ARCH.X64])
@pytest.mark.parametrize("pop", [False, True])
@pytest.mark.parametrize("index", [0, 2])
@pytest.mark.parametrize("top", [3, 7])
def test_ffree_physical_tag(arch, pop, index, top):
    m = MaatEngine(arch)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes([0xdf if pop else 0xdd, 0xc0 + index]))
    other_bits = 0x8101
    m.cpu.fpusw = (top << 11) | other_bits
    m.cpu.fputw = 0x10
    m.cpu.st0, m.cpu.st1 = Cst(80, 10), Cst(80, 20)

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    tags = 0x10 | (3 << (2 * ((top + index) & 7)))
    if pop:
        tags |= 3 << (2 * top)
    assert m.cpu.fputw.as_uint() == tags
    assert m.cpu.fpusw.as_uint() == ((((top + pop) & 7) << 11) | other_bits)
    assert m.cpu.st0.as_uint() == (20 if pop else 10)


def test_ffree_after_stack_rotation():
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x1fff)
    # FINCSTP; FFREE ST(0); FDECSTP
    m.mem.write(0x1000, bytes.fromhex("d9 f7 dd c0 d9 f6"))
    m.cpu.fpusw = m.cpu.fputw = 0

    assert m.run_from(0x1000, 3) == STOP.INST_COUNT
    assert m.cpu.fputw.as_uint() == (3 << 2)
    assert m.cpu.fpusw.as_uint() == 0


def test_lzcnt_reads_memory_once():
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    m.mem.write(0x1000, bytes.fromhex("f3 48 0f bd 01"))  # LZCNT RAX, [RCX]
    m.cpu.rcx = 0x2000
    m.mem.write(0x2000, Cst(64, 0x101))
    reads = []

    def record_read(engine):
        reads.append(engine.info.mem_access.addr.as_uint())

    m.hooks.add(EVENT.MEM_R, WHEN.BEFORE, callbacks=[record_read])
    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    assert m.cpu.rax.as_uint() == 55
    assert reads == [0x2000]


def test_xgetbv_unresolved_selector():
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("0f 01 d0"))
    m.cpu.rcx = Var(64, "selector")

    assert m.run_from(0x1000, 1) == STOP.FATAL
    assert m.cpu.rip.as_uint() == 0x1000


@pytest.mark.parametrize("selector", [0, 1, 2, 3, 0xfe])
@pytest.mark.parametrize("source", ["register", "memory"])
def test_vpinsrd_lane(selector, source):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x2fff)
    lanes = [1, 2, 3, 4]
    m.cpu.zmm1 = Cst(512, sum(value << (32 * i) for i, value in enumerate(lanes)))
    m.cpu.zmm0 = Cst(512, (1 << 512) - 1)
    if source == "register":
        opcode = bytes.fromhex("c4 e3 71 22 c0")  # VPINSRD XMM0, XMM1, EAX, imm8
        m.cpu.rax = 9
    else:
        opcode = bytes.fromhex("c4 e3 71 22 00")  # VPINSRD XMM0, XMM1, [RAX], imm8
        m.cpu.rax = 0x2000
        m.mem.write(0x2000, Cst(32, 9))
    m.mem.write(0x1000, opcode + bytes([selector]))

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    lanes[selector & 3] = 9
    assert m.cpu.zmm0.as_uint() == sum(value << (32 * i) for i, value in enumerate(lanes))


@pytest.mark.parametrize("opcode", ["c5 f2 58 c2", "c5 f3 58 c2", "c5 f1 58 c2"],
                         ids=["vaddss", "vaddsd", "vaddpd"])
def test_unimplemented_avx_add_stops(opcode):
    m = MaatEngine(ARCH.X64)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex(opcode))
    m.cpu.zmm0 = Cst(512, (1 << 512) - 1)

    assert m.run_from(0x1000, 1) == STOP.UNSUPPORTED_INST
    assert m.info.addr == m.cpu.rip.as_uint() == 0x1000
    assert m.cpu.zmm0.as_uint() == (1 << 512) - 1


@pytest.mark.parametrize("arch,count", [(ARCH.X86, 8), (ARCH.X64, 16)])
def test_vzeroupper(arch, count):
    m = MaatEngine(arch)
    m.mem.map(0x1000, 0x1fff)
    m.mem.write(0x1000, bytes.fromhex("c5 f8 77"))
    upper = ((1 << 384) - 1) << 128
    for i in range(count):
        low = (1 << 127) | (i + 1)
        setattr(m.cpu, f"zmm{i}", Cst(512, upper | low))

    assert m.run_from(0x1000, 1) == STOP.INST_COUNT
    for i in range(count):
        assert getattr(m.cpu, f"zmm{i}").as_uint() == (1 << 127) | (i + 1)
