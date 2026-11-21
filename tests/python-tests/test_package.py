import ast
import os
from pathlib import Path

import maat


def test_typed_package():
    package = Path(maat.__file__).parent
    if os.name == "posix":
        assert Path(maat._native.__file__).name == "_native.abi3.so"
    assert (package / "py.typed").is_file()
    declarations = ast.parse((package / "_native.pyi").read_text()).body
    functions = [node for node in declarations if isinstance(node, ast.FunctionDef)]
    solver_enabled = os.environ.get("MAAT_TEST_NO_SOLVER") != "1"
    assert hasattr(maat, "Solver") == solver_enabled
    assert (
        any(
            isinstance(node, ast.ClassDef) and node.name == "Solver"
            for node in declarations
        )
        == solver_enabled
    )
    for name in ("ULT", "ULE", "ITE"):
        assert any(fn.name == name and ast.get_docstring(fn) for fn in functions)
