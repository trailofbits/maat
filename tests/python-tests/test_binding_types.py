import importlib
import operator
import sys
from collections import UserDict
from pathlib import Path

import maat
import pytest

HELLO_WORLD = (
    Path(__file__).resolve().parents[1] / "resources/smart_contracts/HelloWorld.bin"
)


def test_native_type_slots():
    value = maat.Cst(8, 7)
    assert type(value) is maat.Value
    assert ((2 + value) << 1).as_uint() == 18
    assert isinstance(~((value < 8) & (value > 0)), maat.Constraint)
    with pytest.raises(TypeError):
        maat.Value()
    with pytest.raises(AttributeError):
        value.extra_attribute = 1


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


def test_length_aware_buffer_arguments():
    ctx = maat.VarContext()
    ctx.new_concolic_buffer("buf", b"a\x00b", elem_size=1)
    assert ctx.get_as_buffer("buf") == b"a\x00b"
    assert maat.Var(8, "x").name == "x"
    assert maat.Var(size=8, name=b"y").name == "y"


def test_update_from_releases_context_type():
    target = maat.VarContext()
    source = maat.VarContext()
    context_type = type(target)
    before = sys.getrefcount(context_type)
    target.update_from(source)
    after = sys.getrefcount(context_type)
    assert after == before


def test_reimport_restores_original_exports(monkeypatch):
    value = maat.Cst(8, 7)
    arch, stats = maat.ARCH, maat.MaatStats
    monkeypatch.delattr(maat, "ARCH")
    monkeypatch.setattr(maat, "MaatStats", None)
    monkeypatch.delattr(maat, "Var")
    monkeypatch.delitem(sys.modules, "maat")
    fresh = importlib.import_module("maat")
    assert fresh is not maat
    assert fresh.ARCH is arch
    assert fresh.OS is maat.OS
    assert fresh.MaatStats is stats
    assert fresh.Var(8, "x").name == "x"
    assert fresh.Value is type(value)
    assert (value + fresh.Cst(8, 1)).as_uint() == 8


def test_value_list_releases_wrappers():
    ctx = maat.VarContext()
    value_type = maat.Value
    before = sys.getrefcount(value_type)
    values = ctx.new_concolic_buffer("buf", b"abcd")
    assert len(values) == 4
    del values
    after = sys.getrefcount(value_type)
    assert after == before


def test_constraint_list_releases_wrappers():
    engine = maat.MaatEngine(maat.ARCH.X64)
    value = maat.Var(8, "x")
    engine.path.add(value == 1)
    constraint_type = maat.Constraint
    before = sys.getrefcount(constraint_type)
    constraints = engine.path.get_related_constraints(value)
    assert len(constraints) == 1
    del constraints
    after = sys.getrefcount(constraint_type)
    assert after == before


def test_contexts_and_symbolic_overloads():
    value = maat.Var(8, "v")
    ctx = maat.VarContext()
    assert value.is_symbolic(ctx)
    ctx.set("v", 9)
    assert value.as_uint(ctx) == 9
    with pytest.raises(RuntimeError):
        value.as_uint()
    with pytest.raises(TypeError):
        value.as_uint(None)
    assert maat.ITE(value == 9, value, 0).as_uint(ctx) == 9
    assert [
        x.as_uint(ctx) for x in ctx.new_concolic_buffer("buf", b"a", trailing_value=0)
    ] == [97, 0]
    with pytest.raises(TypeError):
        ctx.new_symbolic_buffer("buf", 1, trailing_value=None)


def test_engine_children_and_memory_overloads():
    engine = maat.MaatEngine(maat.ARCH.X64)
    cpu, mem = engine.cpu, engine.mem
    assert cpu is engine.cpu
    assert engine.info is engine.info
    engine.settings.force_simplify = []
    assert engine.settings.force_simplify is False
    engine.settings.force_simplify = 1
    assert engine.settings.force_simplify is True
    with pytest.raises(AttributeError):
        _ = engine.info.mem_access
    with pytest.raises(TypeError):
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, filter=None)
    engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, filter=[1, 3])
    mem.map(0x1000, 0x1FFF, flags=maat.PERM.RWX)
    mem.write(0x1001, 13, 1)
    mem.write(0x1000, b"ab", 1)
    mem.write(0x1002, maat.Cst(8, 7), 1, ignore_flags=False)
    assert [v.as_uint() for v in mem.read_buffer(0x1000, 3)] == [97, 13, 7]
    with pytest.raises(TypeError):
        mem.map(arg0=0x2000, arg1=0x2FFF)


def test_transaction_copy_and_optional_fields():
    amount = maat.Cst(256, 42)
    data = [maat.Cst(8, 1)]
    recipient = 2**155 + 5
    address = maat.Cst(160, 1)
    tx = maat.EVMTransaction(address, address, recipient, amount, data, amount, amount)
    assert tx.recipient == recipient
    assert tx.ret_offset is None
    assert tx.result is None
    with pytest.raises(TypeError):
        tx.data = [None]
    copied = tx.deepcopy()
    copied.data = []
    assert len(copied.data) == 0
    assert tx.data[0].as_uint() == 1


def test_bytes_input_uses_existing_storage():
    class NativeBytes(bytes):
        def __buffer__(self, flags):
            raise AssertionError("bytes inputs already provide their own storage")

    ctx = maat.VarContext()
    values = ctx.new_concolic_buffer("buf", NativeBytes(b"ab"), nb_elems=1)
    assert [v.as_uint(ctx) for v in values] == [ord("a")]


def test_engine_option_sets():
    engine = maat.MaatEngine(maat.ARCH.X64)
    child = engine._duplicate(share={"mem"}, duplicate={"hooks"})
    engine.mem.map(0x1000, 0x1FFF)
    engine.mem.write(0x1000, 42, 1)
    assert child.mem.read(0x1000, 1).as_uint() == 42
    assert list(engine.path.get_constraints_containing({"word"})) == []

    for invalid in ("mem", ["mem"], frozenset({"mem"})):
        with pytest.raises(TypeError):
            engine._duplicate(share=invalid)
        with pytest.raises(TypeError):
            engine._duplicate(duplicate=invalid)
        with pytest.raises(TypeError):
            engine.path.get_constraints_containing(invalid)
    with pytest.raises(RuntimeError):
        engine._duplicate(share={1})
    with pytest.raises(RuntimeError):
        engine.path.get_constraints_containing({1})


def test_runtime_uses_source_contract_storage():
    source = maat.MaatEngine(maat.ARCH.EVM)
    other = source._duplicate()
    path = str(HELLO_WORLD)
    source.load(path, envp={"address": "123", "deployer": "456"})
    other.load(
        path, envp={"address": "789", "deployer": "456", "no_run_init_bytecode": "1"}
    )

    def slots(engine):
        return {
            key.as_uint(): value.as_uint()
            for key, value in maat.contract(engine).storage.used_slots()
        }

    expected = slots(source)
    assert expected and not slots(other)
    for args in ((), (None,), (other.process.pid,)):
        child = source._duplicate()
        maat.new_evm_runtime(child, source, *args)
        assert slots(child) == expected


def test_help_describes_bound_operations():
    settings = type(maat.MaatEngine(maat.ARCH.X64).settings)
    assert settings.force_simplify.__doc__
    assert maat.EVMContract.outgoing_transaction.__doc__
    lines = (maat.Value.as_uint.__doc__ or "").splitlines()
    assert any(line.strip() and not line.startswith("as_uint(") for line in lines)


def test_borrowed_engine_views_keep_the_owner_alive():
    engine = maat.MaatEngine(maat.ARCH.X64)
    cpu = engine.cpu
    cpu.rax = 17
    del engine
    assert cpu.rax.as_uint() == 17


def test_class_monkey_patch(monkeypatch):
    monkeypatch.setattr(maat.Value, "extra_attribute", 7, raising=False)
    assert maat.Cst(8, 3).extra_attribute == 7


def load_hello_world():
    engine = maat.MaatEngine(maat.ARCH.EVM)
    engine.load(
        str(HELLO_WORLD),
        envp={"address": "123", "deployer": "456", "no_run_init_bytecode": "1"},
    )
    return engine


def test_storage_iterator_keeps_storage_alive():
    engine = load_hello_world()
    engine.run()
    storage = maat.contract(engine).storage
    expected = {k.as_uint(): v.as_uint() for k, v in storage.used_slots()}
    assert expected
    slots = storage.used_slots()
    del storage, engine
    assert iter(slots) is slots
    assert {k.as_uint(): v.as_uint() for k, v in slots} == expected
    with pytest.raises(StopIteration):
        next(slots)


@pytest.mark.parametrize(
    ("field", "other_field"),
    [("transaction", "outgoing_transaction"), ("outgoing_transaction", "transaction")],
)
def test_transaction_view_follows_contract_field(field, other_field):
    engine = load_hello_world()
    contract = maat.contract(engine)
    original = contract.transaction.deepcopy()
    original.data = [maat.Cst(8, 17)]
    setattr(contract, field, original)
    view = getattr(contract, field)

    other = original.deepcopy()
    other.data = [maat.Cst(8, 99)]
    setattr(contract, other_field, other)
    other_view = getattr(contract, other_field)

    replacement = original.deepcopy()
    replacement.data = [maat.Cst(8, 42)]
    assert [item.as_uint() for item in view.data] == [17]
    setattr(contract, field, replacement)
    assert [item.as_uint() for item in view.data] == [42]
    assert [item.as_uint() for item in other_view.data] == [99]
    setattr(contract, field, None)
    with pytest.raises(AttributeError):
        _ = view.data
    assert [item.as_uint() for item in other_view.data] == [99]


def test_retained_transaction_result():
    engine = load_hello_world()
    engine.run()
    contract = maat.contract(engine)
    contract.result_from_last_call = contract.transaction.result
    saved = contract.result_from_last_call
    expected = [v.as_uint() for v in saved.return_data]
    contract.result_from_last_call = None
    assert saved.type == maat.TX_RES.RETURN
    assert [v.as_uint() for v in saved.return_data] == expected


@pytest.mark.parametrize("flags", [-1, (1 << 80) | maat.PERM.R])
def test_map_masks_permission_bits(flags):
    engine = maat.MaatEngine(maat.ARCH.X64)

    class Index:
        def __index__(self):
            return flags

    for addr, argument in ((0x1000, flags), (0x2000, Index())):
        engine.mem.map(addr, addr + 0xFFF, flags=argument)
        if flags & maat.PERM.W:
            engine.mem.write(addr, 42, 1)
            assert engine.mem.read(addr, 1).as_uint() == 42
        else:
            engine.mem.write(addr, 17, 1, ignore_flags=True)
            assert engine.mem.read(addr, 1).as_uint() == 17
            with pytest.raises(RuntimeError):
                engine.mem.write(addr, 42, 1)


@pytest.mark.parametrize("integer", [1, 2**80])
def test_integer_only_constraints_require_a_symbolic_operand(integer):
    condition = maat.Var(8, "v") == 0
    for function, args in ((maat.ULT, ()), (maat.ULE, ()), (maat.ITE, (condition,))):
        with pytest.raises(ValueError):
            function(*args, integer, 2)


def test_variable_context_names_reject_embedded_nul():
    ctx = maat.VarContext()
    name = "a\0b"
    for method, args in (
        (ctx.set, (4,)),
        (ctx.get, ()),
        (ctx.remove, ()),
        (ctx.contains, ()),
        (ctx.get_as_str, ()),
        (ctx.get_as_buffer, ()),
        (ctx.new_symbolic_buffer, (1,)),
    ):
        with pytest.raises(ValueError):
            method(name, *args)
    with pytest.raises(TypeError):
        ctx.new_concolic_buffer(name, b"a")
    assert ctx.contained_vars() == []


def test_loader_dictionary_arguments():
    class DictSubclass(dict):
        pass

    path = str(HELLO_WORLD)
    options = {"address": "123", "deployer": "456", "no_run_init_bytecode": "1"}
    for dictionary in (dict, DictSubclass):
        engine = maat.MaatEngine(maat.ARCH.EVM)
        engine.load(path, envp=dictionary(options), virtual_fs=dictionary())
        assert maat.contract(engine).address.as_uint() == 0x123
    for args in (
        {"envp": UserDict(options)},
        {"envp": options, "virtual_fs": UserDict()},
    ):
        with pytest.raises(TypeError):
            engine.load(path, **args)


@pytest.mark.parametrize("compare", [operator.lt, operator.eq])
@pytest.mark.parametrize("bits, signed", [(2**63, -(2**63)), (2**64 - 1, -1)])
def test_symbolic_comparison_accepts_full_word(compare, bits, signed):
    ctx = maat.VarContext()
    word = maat.Var(64, "word")
    result = maat.ITE(compare(word, bits), maat.Cst(8, 1), 0)
    for concrete in (-(2**63), -2, -1, 0):
        ctx.set("word", concrete)
        assert result.as_uint(ctx) == int(compare(concrete, signed))


@pytest.mark.parametrize(
    ("arch", "expected"), [(maat.ARCH.X64, 0x41), (maat.ARCH.EVM, 0xFFC5)]
)
def test_concrete_values_for_multibyte_concolic_elements(arch, expected):
    engine = maat.MaatEngine(arch)
    ctx = engine.vars
    # The concrete assignment is eight bits. EVM packs B one bit above A,
    # giving 0xC5, which sign-extends to 0xFFC5 in the 16-bit element.
    (value,) = ctx.new_concolic_buffer("buf", b"AB", elem_size=2)
    assert value.as_uint(ctx) == expected
