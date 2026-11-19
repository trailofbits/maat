import importlib
import sys

import maat
import pytest


def test_native_type_slots():
    value = maat.Cst(8, 7)
    assert type(value) is maat.Value
    assert ((2 + value) << 1).as_uint() == 18
    assert isinstance(~((value < 8) & (value > 0)), maat.Constraint)
    with pytest.raises(TypeError):
        maat.Value()
    with pytest.raises(TypeError):
        maat.Value.extra_attribute = 1


def test_instance_releases_its_heap_type():
    value_type = maat.Value
    before = sys.getrefcount(value_type)
    values = [maat.Cst(8, i) for i in range(32)]
    del values
    after = sys.getrefcount(value_type)
    assert after == before


def test_requested_buffer_sizes(tmp_path):
    ctx = maat.VarContext()
    with pytest.raises(ValueError):
        ctx.new_concolic_buffer("buf", b"ab", elem_size=0)
    with pytest.raises(ValueError):
        ctx.new_concolic_buffer("buf", b"ab", nb_elems=2, elem_size=2)
    engine = maat.MaatEngine(maat.ARCH.X64, maat.OS.LINUX)
    source = tmp_path / "input"
    source.write_bytes(b"")
    fs = engine.env.fs
    assert fs.add_real_file(str(source), "/input")
    file = fs.get_file("/input")
    with pytest.raises(ValueError):
        file.write_buffer(b"ab", 0, 3)
    handle = fs.get_fa_by_handle(fs.new_fa("/input"))
    with pytest.raises(ValueError):
        handle.write_buffer(b"ab", 3)


def test_length_aware_buffer_arguments():
    ctx = maat.VarContext()
    ctx.new_concolic_buffer("buf", b"a\x00b", elem_size=1)
    assert ctx.get_as_buffer("buf") == b"a\x00b"
    assert maat.Var(8, "x").name == "x"
    assert maat.Var(size=8, name=b"y").name == "y"


def test_update_from_releases_context_type():
    target = maat.VarContext()
    source = maat.VarContext()
    context_type = type(target)
    before = sys.getrefcount(context_type)
    target.update_from(source)
    after = sys.getrefcount(context_type)
    assert after == before


def test_reimport_restores_original_exports(monkeypatch):
    value = maat.Cst(8, 7)
    arch, stats = maat.ARCH, maat.MaatStats
    monkeypatch.delattr(maat, "ARCH")
    monkeypatch.setattr(maat, "MaatStats", None)
    monkeypatch.delattr(maat, "Var")
    monkeypatch.delitem(sys.modules, "maat")
    fresh = importlib.import_module("maat")
    assert fresh is not maat
    assert fresh.ARCH is arch
    assert fresh.OS is maat.OS
    assert fresh.MaatStats is stats
    assert fresh.Var.__self__ is fresh
    assert fresh.Var(8, "x").name == "x"
    assert fresh.Value is type(value)
    assert (value + fresh.Cst(8, 1)).as_uint() == 8


def test_value_list_releases_wrappers():
    ctx = maat.VarContext()
    value_type = maat.Value
    before = sys.getrefcount(value_type)
    values = ctx.new_concolic_buffer("buf", b"abcd")
    assert len(values) == 4
    del values
    after = sys.getrefcount(value_type)
    assert after == before


def test_constraint_list_releases_wrappers():
    engine = maat.MaatEngine(maat.ARCH.X64)
    value = maat.Var(8, "x")
    engine.path.add(value == 1)
    constraint_type = maat.Constraint
    before = sys.getrefcount(constraint_type)
    constraints = engine.path.get_related_constraints(value)
    assert len(constraints) == 1
    del constraints
    after = sys.getrefcount(constraint_type)
    assert after == before
