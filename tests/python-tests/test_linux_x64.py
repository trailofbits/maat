from maat import *
from pathlib import Path
import pytest

RESOURCES_DIR = Path(__file__).resolve().parent.parent / "resources"
LINUX_LIBS_64_DIR = f"{RESOURCES_DIR}/linux_libs_64/"
X64_ELF_DIR = f"{RESOURCES_DIR}/x64_elf"

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

    # NOTE: data argument is unnecessary but we use it to test
    # callback data in python 
    def solve_chall(m: MaatEngine, data):
        if m.info.addr != 0x040008b1:
            return
        s = Solver()
        s.add(m.info.branch.cond.invert())
        if s.check():
            model = s.get_model()
            m.vars.update_from(model)
        return ACTION.HALT

    m.hooks.add(EVENT.PATH, WHEN.BEFORE, callbacks=[solve_chall], data=None)
    m.run()

    assert m.vars.get_as_str("input") == b'1bHt56z0'
