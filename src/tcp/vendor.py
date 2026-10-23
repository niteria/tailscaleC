#!/usr/bin/env python3
"""Refresh/check selected lwIP sources, preserving non-code text verbatim."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

COMMIT = "77dcd25a72509eb83f72b033d219b1d40cd8eb95"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    commit = subprocess.check_output(
        ["git", "-C", str(args.checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != COMMIT:
        parser.error(f"expected lwIP commit {COMMIT}, got {commit}")
    here = Path(__file__).resolve().parent
    names = re.findall(r"^#define (\w+) tsc_lwip_", (here / "port/namespace.h").read_text(), re.M)
    # Keep quoted strings, character constants, // and /* comments unchanged.
    tokens = re.compile(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|\b('
        + "|".join(map(re.escape, names)) + r")\b"
    )
    differences = []
    for target in sorted((here / "lwip").rglob("*")):
        if target.suffix not in (".c", ".h"):
            continue
        source = args.checkout / "src" / target.relative_to(here / "lwip")
        content = tokens.sub(
            lambda match: "tsc_lwip_" + match[1] if match[1] else match[0],
            source.read_text(),
        )
        if target.read_text() != content:
            differences.append(str(target.relative_to(here)))
            if not args.check:
                target.write_text(content)
    license_source = (args.checkout / "COPYING").read_bytes()
    license_target = here / "lwip/LICENSE"
    if license_target.read_bytes() != license_source:
        differences.append("lwip/LICENSE")
        if not args.check:
            license_target.write_bytes(license_source)
    if args.check and differences:
        print("Vendored source differs: " + ", ".join(differences), file=sys.stderr)
        return 1
    print("lwIP source and namespace verified" if args.check else f"Refreshed {len(differences)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
