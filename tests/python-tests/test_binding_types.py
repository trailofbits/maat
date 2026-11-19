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
