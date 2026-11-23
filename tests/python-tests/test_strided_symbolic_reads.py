import maat
import pytest


@pytest.mark.parametrize("split_mapping", [False, True], ids=["one-map", "adjacent-maps"])
@pytest.mark.parametrize(
    ("base", "stride", "table"),
    [
        pytest.param(0x1FFC, 2, "11 22 33 44 55 66 77 88", id="aligned-halfwords"),
        pytest.param(0x1FFD, 2, "11 22 33 44 55 66 77 88", id="unaligned-halfwords"),
        pytest.param(
            0x1FFB, 4, "11 22 aa bb 33 44 cc dd 55 66 ee ff 77 88 99 aa",
            id="field-in-four-byte-record",
        ),
    ],
)
def test_strided_halfword_table(base, stride, table, split_mapping):
    engine = maat.MaatEngine(maat.ARCH.X64)
    if split_mapping:
        engine.mem.map(0x1000, 0x1FFF)
        engine.mem.map(0x2000, 0x2FFF)
    else:
        engine.mem.map(0x1000, 0x2FFF)
    for offset, byte in enumerate(bytes.fromhex(table)):
        engine.mem.write(base + offset, byte, 1)

    address = maat.Cst(64, base) + (maat.Var(64, "index") & 3) * stride
    selected = engine.mem.read(address, 2)
    context = maat.VarContext()
    values = []
    for index in range(4):
        context.set("index", index)
        values.append(selected.as_uint(context))
    assert values == [0x2211, 0x4433, 0x6655, 0x8877]


@pytest.fixture(params=["write-only", "unmapped"])
def partial_table(request, first_page_readable):
    engine = maat.MaatEngine(maat.ARCH.X64)
    pages = [
        (0x1000, 0x1FFD, "11 22 33", first_page_readable),
        (0x2000, 0x2000, "44 55 66 77 88", not first_page_readable),
    ]
    for page, start, data, readable in pages:
        if not readable and request.param == "unmapped":
            continue
        flags = maat.PERM.RW if readable else maat.PERM.W
        engine.mem.map(page, page + 0xFFF, flags=flags)
        engine.mem.write(start, bytes.fromhex(data))
    return engine


@pytest.mark.parametrize("first_page_readable", [False, True], ids=["upper-readable", "lower-readable"])
def test_strided_read_keeps_readable_entries(partial_table, first_page_readable):
    address = maat.Cst(64, 0x1FFD) + (maat.Var(64, "index") & 3) * 2
    selected = partial_table.mem.read(address, 2)
    context = maat.VarContext()
    # Index 1 crosses the boundary. Check only entries wholly on the readable page.
    readable_entries = [(0, 0x2211)] if first_page_readable else [(2, 0x6655), (3, 0x8877)]
    for index, expected in readable_entries:
        context.set("index", index)
        assert selected.as_uint(context) == expected


@pytest.mark.parametrize("first_page_readable", [False, True], ids=["upper-readable", "lower-readable"])
def test_strided_read_requires_a_readable_entry(partial_table, first_page_readable):
    # One halfword straddles the boundary and the other is wholly inaccessible.
    base = 0x1FFF if first_page_readable else 0x1FFD
    address = maat.Cst(64, base) + (maat.Var(64, "index") & 1) * 2
    with pytest.raises(RuntimeError):
        partial_table.mem.read(address, 2)


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
