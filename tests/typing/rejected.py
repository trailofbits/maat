from collections import UserDict

import maat

value = maat.Var(8, "x")
maat.Var("eight", "x")  # error
maat.Concat(1, value)  # error
maat.Concat(upper=value, lower=value)  # error
value.size = 2  # error
maat.Value()  # error
maat.MaatEngine()  # error
maat.Solver(0)  # error
maat.VarContext(0)  # error
maat.EVMTransaction()  # error
maat.SimpleStateManager()  # error
engine = maat.MaatEngine(maat.ARCH.X64)
engine.mem.map(arg0=0, arg1=0xFFF)  # error
value.is_symbolic(None)  # error
maat.ULT(1, 2)  # error
maat.ULE(2**80, 1)  # error
engine.load("program", envp=UserDict({"key": "value"}))  # error
maat.ITE(value == 0, 1, 2)  # error
maat.VarContext().new_concolic_buffer("x", b"a", trailing_value=None)  # error
wrong_items: list[str] = ["hello"]
engine.env.fs.get_file("/input").write_buffer(wrong_items, 0)  # error
engine.load("program", args=wrong_items)  # error
engine._duplicate(share="mem")  # error
engine._duplicate(duplicate=["hooks"])  # error
engine.path.get_constraints_containing(frozenset({"x"}))  # error


class DerivedValue(maat.Value):  # error
    pass
