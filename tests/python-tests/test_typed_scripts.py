from __future__ import annotations

from pathlib import Path

import maat
import pytest


def solve_for_output(
    solver: maat.Solver, output: maat.Value, target: int
) -> maat.VarContext:
    solver.add(output == target)
    assert solver.check()
    model = solver.get_model()
    assert isinstance(model, maat.VarContext)
    return model


@pytest.mark.skipif(not hasattr(maat, "Solver"), reason="requires a solver backend")
def test_symbolic_register_in_execution_hook() -> None:
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.write(0x1000, b"\x48\x83\xc0\x03")  # add rax, 3
    engine.cpu.rax = maat.Var(64, "input")
    observed: list[maat.Value] = []

    def after_instruction(current: maat.MaatEngine) -> None:
        observed.append(current.cpu.rax)

    engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.AFTER, callbacks=[after_instruction])
    assert engine.run_from(0x1000, 1) == maat.STOP.INST_COUNT
    (output,) = observed
    model = solve_for_output(maat.Solver(), output, 10)
    engine.vars.update_from(model)
    assert model.get("input") == 7
    assert engine.cpu.rax.as_uint() == 10


def call_contract(
    deployed: maat.MaatEngine, tx: maat.EVMTransaction
) -> maat.MaatEngine:
    runtime = deployed._duplicate(share={"mem", "vars", "path"})
    maat.new_evm_runtime(runtime, deployed)
    maat.contract(runtime).transaction = tx
    runtime.run()
    return runtime


def test_deployed_contract_getter() -> None:
    engine = maat.MaatEngine(maat.ARCH.EVM)
    path = (
        Path(__file__).resolve().parents[1] / "resources/smart_contracts/HelloWorld.bin"
    )
    engine.load(str(path), envp={"address": "123", "deployer": "456"})
    sender, zero = maat.Cst(160, 0x456), maat.Cst(256, 0)
    selector = bytes.fromhex("e21f37ce")  # message()
    tx = maat.EVMTransaction(
        sender,
        sender,
        0x123,
        zero,
        [maat.Cst(8, b) for b in selector],
        zero,
        maat.Cst(256, 100000),
    )
    runtime = call_contract(engine, tx)
    assert isinstance(runtime, maat.MaatEngine)
    completed = maat.contract(runtime).transaction
    assert isinstance(completed, maat.EVMTransaction) and completed.result is not None
    assert completed.result.type == maat.TX_RES.RETURN
    payload = b"".join(
        v.as_uint().to_bytes(v.size // 8, "big") for v in completed.result.return_data
    )
    offset = int.from_bytes(payload[:32], "big")
    size = int.from_bytes(payload[offset : offset + 32], "big")
    expected = b"Hello world" + b"!" * 55
    assert size == len(expected)
    assert payload[offset + 32 : offset + 32 + size] == expected


def test_saved_engine_state(tmp_path: Path) -> None:
    states: maat.SimpleStateManager = maat.SimpleStateManager(str(tmp_path))
    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.cpu.rax = 17
    states.enqueue_state(engine)
    engine.cpu.rax = 42
    assert states.dequeue_state(engine)
    assert engine.cpu.rax.as_uint() == 17
    assert not states.dequeue_state(engine)
