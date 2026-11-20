"""Compare the installed runtime and its generated declarations with the legacy API."""

import ast
import json
import os
from pathlib import Path

import maat
from inventory import inventory


def baseline():
    expected = json.loads(Path(__file__).with_name("baseline.json").read_text())
    if os.environ.get("MAAT_TEST_NO_SOLVER") == "1":
        del expected["exports"]["Solver"]
        del expected["members"]["Solver"]
    return expected


def test_runtime_api():
    assert inventory() == baseline()


def test_generated_api():
    package = Path(maat.__file__).parent
    stub = ast.parse((package / "_native.pyi").read_text())
    exports = {}
    classes = {}
    for node in stub.body:
        if isinstance(node, ast.ClassDef):
            classes[node.name.lstrip("_")] = node
            if node.name.startswith("_"):
                continue
            constants = {
                n.target.id: ast.literal_eval(n.value)
                for n in node.body
                if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
            }
            exports[node.name] = constants or "class"
        elif isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            exports[node.name] = "function"
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            exports[node.target.id] = "instance"

    expected = baseline()
    assert exports == expected["exports"]
    for name, members in expected["members"].items():
        declared = {}
        for method in classes[name].body:
            if isinstance(method, ast.FunctionDef):
                is_property = any(
                    isinstance(d, ast.Name) and d.id == "property"
                    for d in method.decorator_list
                )
                if is_property:
                    declared[method.name] = "attribute"
                else:
                    declared.setdefault(method.name, "method")
        # The stub makes native construction and dynamic register access explicit.
        del declared["__init__"]
        if name == "CPU":
            del declared["__getattr__"], declared["__setattr__"]
        assert declared == members, name


def test_legacy_behavior():
    from behavior import observations

    expected = Path(__file__).with_name("legacy_behavior.json")
    reference = json.loads(expected.read_text())
    if os.environ.get("MAAT_TEST_NO_SOLVER") == "1":
        del reference["solver"]
    assert observations() == reference
