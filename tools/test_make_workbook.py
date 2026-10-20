"""Tests for the workbook generator (run with: pytest tools)."""

import pytest
from make_workbook import ROOT, strip_solutions

SOURCE = '''\
class Header:
    def serialize(self) -> bytes:
        """Docstrings stay."""
        # BEGIN SOLUTION ch02
        return b"solution two"
        # END SOLUTION


def mine(header):
    prefix = header.serialize()  # provided code stays
    # BEGIN SOLUTION ch03
    return prefix + b"solution three"
    # END SOLUTION
'''


def test_stubs_chapters_from_the_start_chapter_on():
    workbook = strip_solutions(SOURCE, from_chapter=1)
    assert "solution" not in workbook
    assert 'raise NotImplementedError("chapter 2 exercise: Header.serialize")' in workbook
    assert 'raise NotImplementedError("chapter 3 exercise: mine")' in workbook
    assert '"""Docstrings stay."""' in workbook and "provided code stays" in workbook
    compile(workbook, "workbook", "exec")


def test_keeps_solutions_of_earlier_chapters_without_markers():
    workbook = strip_solutions(SOURCE, from_chapter=3)
    assert 'return b"solution two"' in workbook
    assert "solution three" not in workbook
    assert "BEGIN SOLUTION" not in workbook and "END SOLUTION" not in workbook


@pytest.mark.parametrize(
    "broken",
    [
        "def f():\n    # BEGIN SOLUTION ch01\n    return 1\n",
        "def f():\n    return 1\n    # END SOLUTION\n",
        "def f():\n    # BEGIN SOLUTION ch01\n    # BEGIN SOLUTION ch01\n    # END SOLUTION\n",
        "# BEGIN SOLUTION ch01\nx = 1\n# END SOLUTION\n",
        "def f():\n    # BEGIN SOLUTION ch99\n    return 1\n    # END SOLUTION\n",
    ],
)
def test_rejects_malformed_markers(broken):
    with pytest.raises(ValueError):
        strip_solutions(broken, from_chapter=1)


def test_every_reference_module_has_well_formed_markers():
    for path in sorted((ROOT / "tinybitcoin").glob("*.py")):
        for chapter in range(1, 14):
            compile(strip_solutions(path.read_text(), chapter, str(path)), str(path), "exec")
