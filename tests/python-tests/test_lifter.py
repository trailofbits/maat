import pytest

from maat import ARCH, MaatEngine


def test_legacy_sla_reports_format_error(tmp_path, monkeypatch):
    (tmp_path / "EVM.pspec").write_text("<processor_spec/>")
    (tmp_path / "EVM.sla").write_text("<sleigh/>")
    monkeypatch.setenv("MAAT_SLEIGH_DIR", str(tmp_path))

    with pytest.raises(RuntimeError, match=r"EVM\.sla: Missing SLA format header"):
        MaatEngine(ARCH.EVM)
