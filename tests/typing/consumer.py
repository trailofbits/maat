from typing import assert_type

import maat

engine = maat.MaatEngine(maat.ARCH.X64)
value = maat.Var(size=8, name=memoryview(b"x"))
assert_type(value, maat.Value)
assert_type(maat.Concat(value, value), maat.Value)
assert_type(2 + value, maat.Value)
assert_type(value < 8, maat.Constraint)
assert_type(value == maat.Cst(8, 1), maat.Constraint)
assert_type(value != 2, maat.Constraint)
condition = value == 0
assert_type(maat.ULT(value, value), maat.Constraint)
assert_type(maat.ULT(value, 1), maat.Constraint)
assert_type(maat.ULT(1, value), maat.Constraint)
assert_type(maat.ULE(value, value), maat.Constraint)
assert_type(maat.ULE(value, 1), maat.Constraint)
assert_type(maat.ULE(1, value), maat.Constraint)
assert_type(maat.ITE(condition, value, value), maat.Value)
assert_type(maat.ITE(condition, value, 1), maat.Value)
assert_type(maat.ITE(condition, 1, value), maat.Value)
assert_type(engine.cpu.rax, maat.Value)
engine.cpu.rax = value
assert_type(engine.mem.read(0, 1), maat.Value)
assert_type(engine.get_inst_bytes(0), bytes)
solver = maat.Solver()
solver.add(value == 3)
model = solver.get_model()
if model is not None:
    assert_type(model.get("x"), int)

ctx = maat.VarContext()
assert_type(ctx.new_concolic_buffer("b", b"a", trailing_value=0), list[maat.Value])
assert_type(ctx.get_as_buffer("b"), bytes)
assert_type(value.is_symbolic(ctx), bool)
assert_type(value.as_float(ctx), int)
assert_type(engine.settings.force_simplify, bool)
assert_type(engine.info.stop, int)
assert_type(engine.env.fs.get_file("/input").read_buffer(0, 1), list[maat.Value])
for predicate in engine.path.constraints():
    assert_type(predicate, maat.Constraint)

contract = maat.contract(engine)
assert_type(contract, maat.EVMContract)
if contract.transaction is not None:
    assert_type(contract.transaction.recipient, int)
    assert_type(contract.transaction.data, list[maat.Value])

file = engine.env.fs.get_file("/input")
values: list[maat.Value] = [value]
numbers: list[int] = [42]
mixed: list[int | maat.Value] = [7, value]
assert_type(file.write_buffer(values, 0), int)
file.write_buffer(numbers, 0)
file.write_buffer(mixed, 0)
argv: list[bytes] = [b"hello"]
symbolic_argv: list[list[maat.Value]] = [values]
engine.load("program", args=argv)
engine.load("program", args=symbolic_argv)

child = engine._duplicate(share={"mem"}, duplicate={"hooks"})
assert_type(child.cpu.rax, maat.Value)
for predicate in engine.path.get_constraints_containing({"x"}):
    assert_type(predicate, maat.Constraint)
