"""Emit script-visible results. Run with either the legacy or the candidate wheel."""

import json
import operator
from pathlib import Path
from tempfile import NamedTemporaryFile

import maat


def observations():
    results = {}
    value = maat.Var(64, "word")
    for op in (
        operator.eq,
        operator.ne,
        operator.lt,
        operator.le,
        operator.gt,
        operator.ge,
    ):
        for integer in (0, 2**63 - 1, 2**63, 2**64 - 1):
            results[f"compare/{op.__name__}/{integer:x}"] = str(op(value, integer))

    ctx = maat.VarContext()
    ctx.set("word", 7)
    for op in (
        operator.add,
        operator.sub,
        operator.mul,
        operator.floordiv,
        operator.truediv,
        operator.mod,
        operator.and_,
        operator.or_,
        operator.xor,
        operator.lshift,
        operator.rshift,
    ):
        for left, right, side in ((value, 2, "right"), (2, value, "left")):
            expr = op(left, right)
            results[f"arithmetic/{op.__name__}/{side}"] = [str(expr), expr.as_uint(ctx)]

    byte = maat.Var(8, "byte")
    ctx.set("byte", 0x81)
    for name, expr in (
        ("concat", maat.Concat(byte, byte)),
        ("extract", maat.Extract(byte, 7, 4)),
        ("sign_extend", maat.Sext(16, byte)),
        ("zero_extend", maat.Zext(16, byte)),
        ("ite_left", maat.ITE(maat.ULT(byte, 4), 0, byte)),
        ("ite_right", maat.ITE(maat.ULE(4, byte), byte, 0)),
        ("wide_constant", maat.Cst(128, 2**100 + 1)),
        ("string_constant", maat.Cst(128, "ffab", base=16)),
    ):
        results[f"value/{name}"] = [str(expr), expr.as_uint(ctx), expr.as_int(ctx)]

    for name, call in (
        ("small_string_constant", lambda: maat.Cst(32, "ffab", base=16)),
        ("invalid_string_constant", lambda: maat.Cst(128, "wat", base=16)),
        ("narrow_sext", lambda: maat.Sext(4, byte)),
        ("narrow_zext", lambda: maat.Zext(4, byte)),
    ):
        try:
            observed = str(call())
        except ValueError as exc:
            observed = [type(exc).__name__, str(exc)]
        results[f"value/{name}"] = observed

    copied = maat.VarContext()
    copied.update_from(ctx)
    copied.remove("byte")
    results["context/copy"] = [
        sorted(copied.contained_vars()),
        ctx.contains("byte"),
        copied.contains("byte"),
        copied.get("word"),
    ]

    # IEEE 754 single-precision 1.5, interpreted by the legacy Python method.
    ctx.set("float_bits", 0x3FC00000, 32)
    as_float = maat.Var(32, "float_bits").as_float(ctx)
    results["value/as_float"] = [type(as_float).__name__, as_float]

    if hasattr(maat, "Solver"):
        solver = maat.Solver()
        solver.timeout = 2**32 + 1000
        solver.add(value == 9)
        sat = solver.check()
        model_value = solver.get_model().get("word") if sat else None
        solver.add(value == 10)
        unsat = solver.check()
        solver.reset()
        results["solver"] = [solver.timeout, sat, model_value, unsat, solver.check()]

    for name, arch in (("x64", maat.ARCH.X64), ("evm", maat.ARCH.EVM)):
        engine = maat.MaatEngine(arch)
        ctx = engine.vars
        for width in (1, 2, 4, 8):
            prefix = f"buf{width}"
            buf = ctx.new_concolic_buffer(
                prefix, b"AB\xa3\xff\x80\x7f\x01\x00", elem_size=width
            )
            results[f"concolic/{name}/{width}"] = [
                [v.as_uint(ctx) for v in buf],
                ctx.get_as_buffer(prefix, width).hex(),
            ]

    engine = maat.MaatEngine(maat.ARCH.X64)
    engine.path.add(value < 5)
    engine.path.add(value != 0)
    for name, it in (
        ("all", engine.path.constraints()),
        ("matching", engine.path.get_constraints_containing({"word"})),
        ("empty", engine.path.get_constraints_containing({"other"})),
    ):
        results[f"path/{name}"] = [iter(it) is it, [str(v) for v in it], list(it)]

    for name in ("symptr_refine_timeout", "symptr_max_range"):
        for arg in (2**32 + 3, "bad"):
            try:
                setattr(engine.settings, name, arg)
                observed = getattr(engine.settings, name)
            except (OverflowError, RuntimeError, TypeError) as exc:
                observed = type(exc).__name__
            results[f"settings/{name}/{arg}"] = observed

    engine.cpu.rax = value
    engine.vars.set("word", 17)
    results["register"] = [engine.cpu.rax.name, engine.cpu.rax.as_uint()]
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.write(0x1000, b"abc", 2)
    engine.mem.write(0x1002, 0x2345, 2)
    results["memory"] = [v.as_uint() for v in engine.mem.read_buffer(0x1000, 4)]

    engine = maat.MaatEngine(maat.ARCH.X64, maat.OS.LINUX)
    fs = engine.env.fs
    with NamedTemporaryFile() as source:
        fs.add_real_file(source.name, "/input")
        file = fs.get_file("/input")
        handle = fs.get_fa_by_handle(fs.new_fa("/input"))
        for name, data in (
            ("values", [maat.Cst(8, 123), maat.Cst(8, 42)]),
            ("integers", [1, 255]),
            ("mixed", [maat.Cst(16, 0x1234), 0x5678]),
            ("bytes", b"a\x00b"),
        ):
            written = file.write_buffer(data, 0)
            results[f"file/{name}"] = [
                written,
                [v.as_uint() for v in file.read_buffer(0, written)],
            ]
        results["file/accessor"] = [
            handle.write_buffer([1, maat.Cst(8, 27)]),
            [v.as_uint() for v in file.read_buffer(0, 2)],
        ]

    # The HelloWorld constructor populates storage and returns the runtime code.
    engine = maat.MaatEngine(maat.ARCH.EVM)
    contract_file = (
        Path(__file__).resolve().parents[1] / "resources/smart_contracts/HelloWorld.bin"
    )
    engine.load(
        str(contract_file),
        envp={"address": "123", "deployer": "456", "no_run_init_bytecode": "1"},
    )
    contract = maat.contract(engine)
    engine.run()
    slots = contract.storage.used_slots()
    results["storage"] = [
        iter(slots) is slots,
        sorted([k.as_uint(), v.as_uint()] for k, v in slots),
        list(slots),
    ]
    tx_result = contract.transaction.result
    contract.result_from_last_call = tx_result
    results["transaction/result"] = [
        contract.result_from_last_call.type,
        contract.result_from_last_call.return_data_size,
    ]
    contract.result_from_last_call = None
    results["transaction/cleared"] = contract.result_from_last_call
    return results


if __name__ == "__main__":
    print(json.dumps(observations(), indent=2, sort_keys=True))
