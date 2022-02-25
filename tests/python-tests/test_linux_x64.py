from maat import *
from maat_test_config import LINUX_LIBS_64_DIR, X64_ELF_DIR
import pytest

def test_crackme1():
    """This tests the example we give in our dynamic symbolic execution tutorial.
       The target program computes a serial from the user input, and checks it against
       a hardcoded value. 

       This script hooks the conditional jump after the serial comparison and uses the
       solver to find the correct serial that leads to a jump to the "success" branch
    """

    m = MaatEngine(ARCH.X64, OS.LINUX)
    m.load(
        f"{X64_ELF_DIR}/crackme1",
        BIN.ELF64,
        base=0x4000000,
        libdirs=[LINUX_LIBS_64_DIR]
    )

    stdin = m.env.fs.get_fa_by_handle(0)
    buf = m.vars.new_concolic_buffer(
        "input",
        b'aaaaaaaa',
        nb_elems=8,
        elem_size=1,
        trailing_value=ord('\n')
    )
    stdin.write_buffer(buf)

    def solve_chall(m: MaatEngine):
        if m.info.addr != 0x040008b1:
            return
        s = Solver()
        s.add(m.info.branch.cond.invert())
        if s.check():
            model = s.get_model()
            m.vars.update_from(model)
        return ACTION.HALT

    m.hooks.add(EVENT.PATH, WHEN.BEFORE, callbacks=[solve_chall])
    m.run()

    assert m.vars.get_as_str("input") == "1bHt56z0"
