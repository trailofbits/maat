"""Preserve call restrictions omitted by nanobind 3.1's stub generator."""

import ast
import importlib
import re
import sys
import types
from pathlib import Path


def finish(source: str, module) -> str:
    lines = source.splitlines(keepends=True)
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef):
            cls = getattr(module, node.name)
            if type(cls).__name__ == "nb_type":
                try:
                    type("_SubclassProbe", (cls,), {})
                except TypeError:
                    lines[node.lineno - 1] = "@final\n" + lines[node.lineno - 1]
            # Nanobind installs a rejecting tp_init on classes with no constructor.
            # Without this declaration checkers inherit object()'s zero-arg constructor.
            if type(cls).__name__ == "nb_type" and isinstance(
                vars(cls).get("__init__"), types.WrapperDescriptorType
            ):
                after = (
                    node.body[0].end_lineno if ast.get_docstring(node) else node.lineno
                )
                lines[after - 1] += (
                    "\n    def __init__(self, _: Never, /) -> None: ...\n\n"
                )
            functions = node.body
        else:
            functions = [node]
        for fn in functions:
            if not isinstance(fn, ast.FunctionDef):
                continue
            if (
                isinstance(fn.returns, ast.Name)
                and fn.returns.id == "Never"
                and any(
                    isinstance(dec, ast.Name) and dec.id == "overload"
                    for dec in fn.decorator_list
                )
            ):
                for i in range(fn.decorator_list[0].lineno - 1, fn.end_lineno):
                    lines[i] = ""
                continue
            # Nanobind names unnamed arguments arg0, arg1, ... in metadata.
            # For mixed positional/keyword signatures it currently omits '/'.
            args = fn.args.args
            if not fn.args.posonlyargs:
                unnamed = [a for a in args if re.fullmatch(r"arg\d+", a.arg)]
                if unnamed:
                    last = args.index(unnamed[-1])
                    if last + 1 < len(args):
                        next_arg = args[last + 1]
                        line = lines[next_arg.lineno - 1]
                        lines[next_arg.lineno - 1] = (
                            line[: next_arg.col_offset]
                            + "/, "
                            + line[next_arg.col_offset :]
                        )
            # Maat deliberately returns a symbolic predicate for equality.
            if (
                isinstance(node, ast.ClassDef)
                and node.name == "Value"
                and fn.name in {"__eq__", "__ne__"}
            ):
                lines[fn.lineno - 1] = (
                    lines[fn.lineno - 1].rstrip() + "  # type: ignore[override]\n"
                )
    imports = (
        "final"
        if re.search(r"^from typing import .*\bNever\b", source, re.MULTILINE)
        else "Never, final"
    )
    return f"from typing import {imports}\n" + "".join(lines)


if __name__ == "__main__":
    source, dest = map(Path, sys.argv[1:3])
    sys.path.insert(0, str(dest.parent.parent))
    result = finish(source.read_text(), importlib.import_module("maat._native"))
    ast.parse(result)
    dest.write_text(result)
