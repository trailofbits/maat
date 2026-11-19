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
