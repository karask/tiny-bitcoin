#!/usr/bin/env python3
"""Check that the course can be taken one chapter at a time (run this in CI).

For every chapter N, build the workbook that starts at N and check that

* every earlier chapter's tests pass, so no chapter secretly needs a later one, and
* chapter N's own tests fail, so the chapter really is left to the student.

Also check that a workbook with every exercise stubbed still imports, and
that one with everything solved passes the whole suite.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from make_workbook import CHAPTERS, make_workbook


def run_pytest(workbook: Path, *args: str) -> int:
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args]
    return subprocess.run(command, cwd=workbook, capture_output=True, check=False).returncode


def test_files(workbook: Path, chapters: range) -> list[str]:
    return [
        str(path.relative_to(workbook))
        for chapter in chapters
        for path in sorted((workbook / "tests").glob(f"test_ch{chapter:02d}_*.py"))
    ]


def check(workbook: Path, chapter: int) -> list[str]:
    problems = []
    stubbed = make_workbook(workbook, chapter)
    if chapter in CHAPTERS and stubbed == 0:
        problems.append("no exercises left")
    if chapter == 1 and run_pytest(workbook, "--collect-only") != 0:
        problems.append("the fully stubbed workbook does not import")
    earlier = test_files(workbook, range(1, chapter))
    if earlier and run_pytest(workbook, *earlier) != 0:
        problems.append("tests of earlier chapters fail")
    if chapter in CHAPTERS:
        own = test_files(workbook, range(chapter, chapter + 1))
        if not own:
            problems.append("no test file")
        elif run_pytest(workbook, *own) != 1:  # 1 means "some tests failed"
            problems.append("its own tests do not fail as they should")
    return problems


def main() -> int:
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        for chapter in [*CHAPTERS, 13]:
            workbook = Path(tmp) / f"from-chapter-{chapter}"
            workbook.mkdir()
            problems = check(workbook, chapter)
            label = "everything solved" if chapter == 13 else f"starting at chapter {chapter}"
            print(f"{'FAIL' if problems else 'ok  '}  workbook {label}"
                  + (f": {'; '.join(problems)}" if problems else ""))
            failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
