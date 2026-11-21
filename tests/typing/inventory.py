"""Capture the public, script-visible API of an installed Maat build."""

import inspect
import json
import sys
import types

import maat


def inventory():
    exports = {}
    classes = {
        c.__name__.lstrip("_"): c
        for c in object.__subclasses__()
        if c.__module__ in {"maat", "maat._native"}
    }
    if hasattr(maat, "_native"):
        classes = {
            name.lstrip("_"): obj
            for name, obj in vars(maat._native).items()
            if isinstance(obj, type) and type(obj).__name__ == "nb_type"
        }
    for name, value in vars(maat).items():
        if name.startswith("_"):
            continue
        if isinstance(value, type) and value not in classes.values():
            exports[name] = {
                k: v for k, v in vars(value).items() if not k.startswith("_")
            }
        elif isinstance(value, type):
            exports[name] = "class"
        elif callable(value):
            exports[name] = "function"
        else:
            exports[name] = "instance"

    members = {}
    for name, cls in classes.items():
        surface = {}
        for key, value in vars(cls).items():
            if key.startswith("__") and key not in {
                "__repr__",
                "__str__",
                "__iter__",
                "__next__",
                "__eq__",
                "__ne__",
                "__lt__",
                "__le__",
                "__gt__",
                "__ge__",
                "__hash__",
                "__add__",
                "__sub__",
                "__mul__",
                "__radd__",
                "__rsub__",
                "__rmul__",
                "__and__",
                "__rand__",
                "__or__",
                "__ror__",
                "__xor__",
                "__rxor__",
                "__neg__",
                "__invert__",
                "__lshift__",
                "__rlshift__",
                "__rshift__",
                "__rrshift__",
                "__truediv__",
                "__rtruediv__",
                "__floordiv__",
                "__rfloordiv__",
                "__mod__",
                "__rmod__",
            }:
                continue
            if isinstance(
                value,
                (types.MemberDescriptorType, types.GetSetDescriptorType, property),
            ):
                surface[key] = "attribute"
            elif (
                callable(value)
                or isinstance(value, (staticmethod, classmethod))
                or inspect.ismethoddescriptor(value)
            ):
                surface[key] = "method"
        members[name] = surface
    return {"exports": exports, "members": members}


if __name__ == "__main__":
    json.dump(inventory(), sys.stdout, indent=2, sort_keys=True)
    print()
