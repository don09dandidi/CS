#!/usr/bin/env python3
"""Fills a LaTeX report template (<<key>> / <<section.key>> placeholders) with the
values from a results.json file produced by a lab script.

Usage: python3 common/fill_report.py lab5/raport_lab5.tpl.tex lab5/results.json lab5/raport_lab5.tex
"""
import json
import re
import sys


def ascii_table(msg: str) -> str:
    chars = " & ".join("\\textvisiblespace" if c == " " else c for c in msg)
    hexes = " & ".join(f"{ord(c):02X}" for c in msg)
    decs = " & ".join(str(ord(c)) for c in msg)
    return f"Char & {chars} \\\\\nDec & {decs} \\\\\nHex & {hexes} \\\\"


def main(tpl_path: str, json_path: str, out_path: str) -> None:
    data = json.load(open(json_path, encoding="utf-8"))
    aliases = {"eg": "elgamal"}
    tpl = open(tpl_path, encoding="utf-8").read()

    def value(key: str):
        if key == "ascii_table":
            return ascii_table(data["message"])
        if key == "m_bits":
            return int(data["m"]).bit_length()
        if key == "P":
            return data["elgamal"]["p"]
        node = data
        for part in key.split("."):
            node = node[aliases.get(part, part)]
        return node

    out = re.sub(r"<<([\w.]+)>>", lambda mo: str(value(mo.group(1))), tpl)
    open(out_path, "w", encoding="utf-8").write(out)


if __name__ == "__main__":
    main(*sys.argv[1:4])
