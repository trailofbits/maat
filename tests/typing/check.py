"""Check the installed distribution using the three consumer type checkers."""

import importlib
import re
import subprocess
import sys
from pathlib import Path


def check_stubtest():
    # inspect sees nanobind's metaclass and callable objects, but cannot read
    # their signatures. Accept only these specific reflection diagnostics.
    native = importlib.import_module("maat._native")
    run = subprocess.run(
        [sys.executable, "-m", "mypy.stubtest", "maat", "--concise"],
        check=False,
        text=True,
        capture_output=True,
    )
    if not run.returncode:
        return
    lines = run.stdout.splitlines()
    if run.returncode != 1 or not lines or run.stderr:
        raise SystemExit(run.stdout + run.stderr)
    for line in lines:
        path, _, message = line.partition(" ")
        if not path.startswith("maat._native."):
            raise SystemExit(line)
        obj = native
        for component in path.split(".")[2:]:
            obj = getattr(obj, component)
        if (
            type(obj) is type(native.Value)
            and message == "is inconsistent, metaclass differs"
        ):
            continue
        if type(obj) is type(native.Concat):
            if message == "is not a function":
                continue
            if (
                message == "is inconsistent, stub is a staticmethod but runtime is not"
                and path.count(".") == 3
            ):
                continue
            if (
                message == 'is inconsistent, stub does not have *args parameter "args"'
                and all("()" in signature for signature, _, _ in obj.__nb_signature__)
            ):
                continue
        raise SystemExit(line)
    print(
        f"stubtest reported only the {len(lines)} known nanobind reflection diagnostics."
    )


def main():
    tests = Path(__file__).resolve().parent
    check_stubtest()
    python = sys.executable
    bin_dir = Path(python).parent
    checkers = [
        [bin_dir / "ty", "check", "--python", python, "--output-format", "concise"],
        [
            bin_dir / "mypy",
            "--strict",
            "--no-incremental",
            "--python-executable",
            python,
        ],
        [bin_dir / "pyright", "--pythonpath", python],
    ]
    for checker in checkers:
        subprocess.run(
            [
                *checker,
                tests / "consumer.py",
                tests.parent / "python-tests/test_typed_scripts.py",
            ],
            check=True,
        )
        rejected = tests / "rejected.py"
        expected = {
            i
            for i, line in enumerate(rejected.read_text().splitlines(), 1)
            if line.endswith("# error")
        }
        run = subprocess.run(
            [*checker, rejected], check=False, capture_output=True, text=True
        )
        output = run.stdout + run.stderr
        found = {int(n) for n in re.findall(r"rejected\.py:(\d+):", output)}
        if run.returncode != 1 or found != expected:
            raise SystemExit(
                f"{checker[0].name}: expected {expected}, saw {found}\n{output}"
            )
        print(
            f"{checker[0].name} rejected all {len(found)} invalid calls and assignments."
        )


if __name__ == "__main__":
    main()
