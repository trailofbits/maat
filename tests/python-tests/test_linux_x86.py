from maat import *
from maat_test_config import LINUX_LIBS_64_DIR, X86_ELF_DIR
import pytest

def test_crackme_vm():
    """This solves a challenge by exploring all possible execution paths.
       The challenge asks for a password and checks it with obfuscated code. The
       obfuscation consists in a VM protection using Z80 opcodes.

       This script implements DFS path exploration using snapshots.
    """
    m = MaatEngine(ARCH.X86, OS.LINUX)
    m.load(f"{X86_ELF_DIR}/crackme_vm", BIN.ELF32, load_interp=False)

    snapshot_next = True
    def path_cb(m: MaatEngine):
        global snapshot_next
        if snapshot_next:
            m.take_snapshot()
        snapshot_next = True


    def explore(m: MaatEngine):
        global snapshot_next
        while m.run() == STOP.HOOK:
            while True:
                # Restore last snapshot and invert branch
                m.restore_snapshot(remove=True)
                s = Solver()
                for c in m.path.get_related_constraints(m.info.branch.cond):
                    s.add(c)
                if m.info.branch.taken:
                    s.add(m.info.branch.cond.invert())
                else:
                    s.add(m.info.branch.cond)
                if s.check():
                    m.vars.update_from(s.get_model())
                    snapshot_next = False
                    # print(f"Trying with input: {m.vars.get_as_str('input')}")
                    break

    # Exploration hooks
    m.hooks.add(EVENT.PATH, WHEN.BEFORE, name="path", callbacks=[path_cb])
    m.hooks.add(EVENT.EXEC, WHEN.BEFORE, name="fail", filter=0x8048411)

    # Scanf hook
    def scanf(m: MaatEngine):
        m.mem.write(0x8049a98, b'A'*30)
        m.mem.make_concolic(0x8049a98, 30, 1, "input")
        m.cpu.eax = 30
        m.info.addr = engine.mem.read(m.cpu.esp, 4).as_uint()
        m.cpu.esp += 4

    m.hooks.add(EVENT.EXEC, WHEN.BEFORE, name="scanf", filter=0x8048a6c, callbacks=[scanf])

    # Explore
    explore(m)

    assert m.vars.get_as_str("input") == "I_L0v3_Z80_Opcod3s_!"