import maat


def test_symbolic_halfword_table_matches_concrete_reads():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x101F)
    table = (0x3412, 0x7856, 0xBC9A, 0xF0DE)
    for index, value in enumerate(table):
        engine.mem.write(0x1000 + 2 * index, value, 2)

    selector = maat.Var(64, "selector")
    address = maat.Cst(64, 0x1000) + (selector & 3) * 2
    selected = engine.mem.read(address, 2)
    context = maat.VarContext()

    for index, expected in enumerate(table):
        context.set("selector", index)
        assert selected.as_uint(context) == expected


def test_movzx_with_limited_odd_address_range():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.write(0x1000, bytes.fromhex("0f b6 00"))  # movzx eax, byte ptr [rax]
    engine.mem.write(0x1100, bytes(range(32)))
    engine.settings.symptr_limit_range = True
    engine.settings.symptr_max_range = 8
    address = maat.Cst(64, 0x1101) + (maat.Var(64, "index") & 15) * 2

    for index in range(16):
        engine.vars.set("index", index)
        engine.cpu.rax = address
        assert engine.run_from(0x1000, 1) == maat.STOP.INST_COUNT
        assert engine.cpu.rax.as_uint(engine.vars) == 1 + 2 * index
