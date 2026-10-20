#!/usr/bin/env python3
"""Generate a student workbook from the reference implementation.

tinybitcoin/ is the single source of truth. Every exercise is a region

        # BEGIN SOLUTION ch05
        ...the reference solution...
        # END SOLUTION

inside a function. This script copies the course and replaces each region
from the chosen chapter on with `raise NotImplementedError(...)`. Earlier
chapters keep their solutions, so a student who falls behind can restart
from any chapter with working code underneath:

    python tools/make_workbook.py workbook             # start at chapter 1
    python tools/make_workbook.py workbook --chapter 8 # chapters 1-7 solved
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "tinybitcoin"
STUDENT_FILES = ["README.md", "pyproject.toml", "docs", "tests", PACKAGE]
CHAPTERS = range(1, 13)

BEGIN = re.compile(r"^(?P<indent>[ ]*)# BEGIN SOLUTION ch(?P<chapter>\d\d)[ ]*$")
END = re.compile(r"^[ ]*# END SOLUTION[ ]*$")
DEF = re.compile(r"^(?P<indent>[ ]*)def (?P<name>\w+)")
CLASS = re.compile(r"^(?P<indent>[ ]*)class (?P<name>\w+)")


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def exercise_name(lines: list[str], start: int, where: str) -> str:
    """The (qualified) name of the function a solution region sits in."""
    region_indent = indent_of(lines[start])
    for i in range(start - 1, -1, -1):
        match = DEF.match(lines[i])
        if match and len(match["indent"]) < region_indent:
            name = match["name"]
            for line in reversed(lines[:i]):
                cls = CLASS.match(line)
                if cls and len(cls["indent"]) < len(match["indent"]):
                    return f"{cls['name']}.{name}"
            return name
    raise ValueError(f"{where}: a solution region must be inside a function")


def strip_solutions(source: str, from_chapter: int, where: str = "<source>") -> str:
    """Stub out the solution regions of chapters >= from_chapter, unwrap the others."""
    lines = source.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        begin = BEGIN.match(lines[i])
        if END.match(lines[i]):
            raise ValueError(f"{where}:{i + 1}: END SOLUTION without BEGIN SOLUTION")
        if not begin:
            out.append(lines[i])
            i += 1
            continue
        end = i + 1
        while end < len(lines) and not END.match(lines[end]):
            if BEGIN.match(lines[end]):
                raise ValueError(f"{where}:{end + 1}: nested BEGIN SOLUTION")
            end += 1
        if end == len(lines):
            raise ValueError(f"{where}:{i + 1}: BEGIN SOLUTION without END SOLUTION")
        chapter = int(begin["chapter"])
        if chapter not in CHAPTERS:
            raise ValueError(f"{where}:{i + 1}: unknown chapter {chapter}")
        name = exercise_name(lines, i, f"{where}:{i + 1}")
        if chapter >= from_chapter:
            message = f"chapter {chapter} exercise: {name}"
            out.append(f'{begin["indent"]}raise NotImplementedError("{message}")\n')
        else:
            out.extend(lines[i + 1 : end])
        i = end + 1
    return "".join(out)


def make_workbook(destination: Path, from_chapter: int = 1) -> int:
    """Write a workbook to `destination`; return the number of stubbed exercises."""
    for name in STUDENT_FILES:
        source = ROOT / name
        target = destination / name
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(source, target)
    stubbed = 0
    for path in sorted((destination / PACKAGE).glob("*.py")):
        original = path.read_text()
        workbook = strip_solutions(original, from_chapter, str(path.relative_to(destination)))
        stubbed += workbook.count("raise NotImplementedError(\"chapter ")
        path.write_text(workbook)
    (destination / "WORKBOOK.md").write_text(
        f"# Your tiny-bitcoin workbook\n\n"
        f"This copy starts at chapter {from_chapter}. Chapters before it are already solved;\n"
        f"the {stubbed} exercises from chapter {from_chapter} on raise NotImplementedError.\n\n"
        f"Read the chapter in docs/course.md, fill in the functions it names, and run\n\n"
        f"    pytest tests/test_ch{from_chapter:02d}_*.py\n\n"
        f"until it passes. Then move on to the next chapter.\n"
    )
    return stubbed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("destination", type=Path, help="directory to create, e.g. workbook")
    parser.add_argument("--chapter", type=int, default=1, choices=list(CHAPTERS) + [13],
                        help="first chapter left as exercises (13 = everything solved)")
    parser.add_argument("--force", action="store_true", help="replace an existing directory")
    args = parser.parse_args()

    destination = args.destination.resolve()
    protected = {ROOT, *ROOT.parents, *(ROOT / name for name in [*STUDENT_FILES, "tools", ".git"])}
    if destination in protected:
        sys.exit(f"refusing to overwrite {destination}: choose a new directory, e.g. workbook")
    if destination.exists():
        if not args.force:
            sys.exit(f"{destination} already exists (use --force to replace it)")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    stubbed = make_workbook(destination, args.chapter)
    print(f"Wrote {destination}: {stubbed} exercises, starting at chapter {args.chapter}.")


if __name__ == "__main__":
    main()
