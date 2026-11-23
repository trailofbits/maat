import maat
import pytest


def test_symbolic_pointer_read_keeps_candidates_across_segments():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x101F)
    engine.mem.map(0x2000, 0x201F)
    engine.mem.write(0x1000, 0x11, 1)
    engine.mem.write(0x2000, 0x22, 1)

    selector = maat.Var(64, "selector")
    address = maat.Cst(64, 0x1000) + ((selector & 1) * 0x1000)
    value = engine.mem.read(address, 1)
    context = maat.VarContext()

    for choice, expected in ((0, 0x11), (1, 0x22)):
        context.set("selector", choice)
        assert value.as_uint(context) == expected


@pytest.mark.parametrize("split_mapping", [False, True])
def test_symbolic_read_discards_write_only_candidates(split_mapping):
    engine = maat.MaatEngine(maat.ARCH.X64)
    if split_mapping:
        engine.mem.map(0x1000, 0x1FFF)
        engine.mem.map(0x2000, 0x2FFF)
    else:
        engine.mem.map(0x1000, 0x2FFF)
    engine.mem.write(0x1000, 0x11, 1)
    engine.mem.write(0x2000, 0x22, 1)
    engine.mem.map(0x1000, 0x1FFF, flags=maat.PERM.W)

    address = maat.Cst(64, 0x1000) + (maat.Var(64, "index") & 1) * 0x1000
    assert engine.mem.read(address, 1).as_uint() == 0x22
    engine.mem.map(0x2000, 0x2FFF, flags=maat.PERM.W)
    with pytest.raises(RuntimeError, match="No valid address"):
        engine.mem.read(address, 1)


def test_symbolic_read_checks_every_byte_inside_one_segment():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x2FFF)
    engine.mem.write(0x1FFE, bytes.fromhex("11 22 33"))
    engine.mem.map(0x2000, 0x2FFF, flags=maat.PERM.W)

    address = maat.Cst(64, 0x1FFE) + (maat.Var(64, "index") & 1)
    assert engine.mem.read(address, 2).as_uint() == 0x2211


def test_symbolic_write_on_write_only_page_is_excluded_from_read():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF, flags=maat.PERM.W)
    engine.mem.map(0x2000, 0x2FFF)
    engine.mem.write(0x2000, b"\x22" * 3)
    store = maat.Cst(64, 0x1FFF) + (maat.Var(64, "store") & 1)
    engine.mem.write(store, 0x55, 1)

    load = maat.Cst(64, 0x1FFF) + (maat.Var(64, "load") & 3)
    value = engine.mem.read(load, 1)
    context = maat.VarContext()
    for store_choice in range(2):
        context.set("store", store_choice)
        for load_choice in (1, 2, 3):
            context.set("load", load_choice)
            expected = engine.mem.read(0x1FFF + load_choice, 1)
            assert value.as_uint(context) == expected.as_uint(context)

    # The store touched only the denied byte. Every readable candidate still holds 0x22.
    context.set("store", 0)
    context.set("load", 0)
    assert value.as_uint(context) == 0x22


def test_symbolic_halfword_spanning_adjacent_pages():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.map(0x2000, 0x2FFF)
    engine.mem.write(0x1FFE, 0x44332211, 4)
    engine.mem.map(0x1000, 0x1FFF, flags=maat.PERM.R)

    selector = maat.Var(64, "selector")
    value = engine.mem.read(maat.Cst(64, 0x1FFE) + (selector & 3), 2)
    context = maat.VarContext()
    for choice in range(4):
        context.set("selector", choice)
        assert value.as_uint(context) == engine.mem.read(0x1FFE + choice, 2).as_uint()


def test_uniform_halfwords_stay_concrete_across_pages():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.map(0x2000, 0x2FFF)
    engine.mem.write(0x1FFE, b"\x5a" * 5)

    address = maat.Cst(64, 0x1FFE) + (maat.Var(64, "index") & 3)
    value = engine.mem.read(address, 2)
    assert not value.is_symbolic(engine.vars)
    assert value.as_uint() == 0x5A5A


@pytest.mark.parametrize("write_only_page", [0x1000, 0x2000])
def test_spanning_read_requires_both_pages_to_be_readable(write_only_page):
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.map(0x2000, 0x2FFF)
    engine.mem.write(0x1FFE, bytes.fromhex("11 22 33 44 55"))
    engine.mem.map(write_only_page, write_only_page + 0xFFF, flags=maat.PERM.W)

    choice = maat.Var(64, "index") & 1
    for start in (0x1FFE, 0x1FFF):
        with pytest.raises(RuntimeError, match="R flag"):
            engine.mem.read(start, 4)
    with pytest.raises(RuntimeError, match="No valid address"):
        engine.mem.read(maat.Cst(64, 0x1FFE) + choice, 4)

    # A rejected crossing must still leave a readable alternative intact.
    if write_only_page == 0x2000:
        start, readable = 0x1FFE, 0x1FFE
    else:
        start, readable = 0x1FFF, 0x2000
    value = engine.mem.read(maat.Cst(64, start) + choice, 2)
    assert value.as_uint() == engine.mem.read(readable, 2).as_uint()


def test_spanning_read_checks_permissions_inside_a_segment():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.map(0x2000, 0x3FFF)
    engine.mem.map(0x3000, 0x3FFF, flags=maat.PERM.W)

    # Both starts enter the second segment at a readable page and end in its write-only page.
    address = maat.Cst(64, 0x1FFE) + (maat.Var(64, "index") & 1)
    with pytest.raises(RuntimeError, match="No valid address"):
        engine.mem.read(address, 0x1003)
