import sys
import weakref

import maat
import pytest


def engine_with_nops():
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.write(0x1000, b"\x90\x90")
    return engine


def test_duplicated_hooks_keep_callback_and_data():
    parent = engine_with_nops()
    calls = []

    class Payload:
        pass

    def record(engine, *args):
        calls.append((engine, args))

    data = Payload()
    callback_ref, data_ref = weakref.ref(record), weakref.ref(data)
    for kwargs in ({}, {"data": None}, {"data": data}):
        parent.hooks.add(
            maat.EVENT.EXEC, maat.WHEN.BEFORE, callbacks=[record], **kwargs
        )
    child = parent._duplicate(share={"mem"}, duplicate={"hooks"})
    del parent, record, data, kwargs
    assert callback_ref() is not None and data_ref() is not None
    assert child.run_from(0x1000, 1) == maat.STOP.INST_COUNT
    assert all(engine is child for engine, _ in calls)
    assert [args for _, args in calls] == [(), (None,), (data_ref(),)]
    calls.clear()
    del child
    assert callback_ref() is None and data_ref() is None


@pytest.mark.parametrize(
    ("result", "stop"),
    [
        (None, maat.STOP.INST_COUNT),
        (maat.ACTION.HALT, maat.STOP.HOOK),
        (maat.ACTION.ERROR, maat.STOP.FATAL),
        (9, maat.STOP.FATAL),
        ("bad", maat.STOP.FATAL),
    ],
)
def test_callback_actions(result, stop):
    engine = engine_with_nops()
    engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, callbacks=[lambda _: result])
    assert engine.run_from(0x1000, 1) == stop


def test_callback_exception(capfd, monkeypatch):
    # Printing the callback traceback sets these interpreter-wide attributes.
    for name in ("last_exc", "last_type", "last_value", "last_traceback"):
        monkeypatch.setattr(sys, name, None, raising=False)

    def fail(engine):
        raise ValueError("test callback failed")

    engine = engine_with_nops()
    engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, callbacks=[fail])
    assert engine.run_from(0x1000, 1) == maat.STOP.FATAL
    assert "ValueError: test callback failed" in capfd.readouterr().err
