#!/usr/bin/env python3
"""Slepi src/*.lua + miner/main.lua do jednoho souboru miner.lua pro executor.

Kazdy modul se vlozi jako long-bracket string a nacte pres loadstring, takze
zustane `local` a neunikne do globalniho prostredi executoru.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ORDER = [("blake2b", "blake"), ("aes", "aes"), ("argon2", "argon2"),
         ("superscalar", "ss"), ("rx", "rx")]
OUT = ROOT / "miner.lua"


def wrap(name: str, local_name: str) -> str:
    src = (ROOT / "src" / f"{name}.lua").read_text()
    if "]==]" in src:
        raise SystemExit(f"{name}.lua obsahuje ']==]' — zvol jiny delimiter")
    return f"local {local_name} = __mod([==[\n{src}]==], '{local_name}')\n"


def main() -> int:
    parts = [
        "-- miner.lua — GENEROVANY SOUBOR, needituj primo (viz miner/main.lua + tools/bundle.py)",
        "-- RandomX v1 (rx/0) miner pro Roblox executor pres lokalni WS bridge.",
        "",
        "local __mod = function(src, name)",
        "\tlocal f = (loadstring or load)(src, '=' .. name)",
        "\tassert(f, 'modul se nenacetl: ' .. name)",
        "\treturn f()",
        "end",
        "",
    ]
    parts += [wrap(*n) for n in ORDER]
    main_src = (ROOT / "miner" / "main.lua").read_text()

    # miner.test.lua vraci M misto spusteni, aby sel testovat pres require
    test = list(parts)
    test.append("\n" + main_src)
    tpath = ROOT / "miner.test.lua"
    ttext = "\n".join(test)
    tpath.write_text(ttext)

    # executor varianta: za `return M` uz Luau nic necte, takze ho odstranime
    head, _, _ = main_src.rpartition("return M")
    parts.append("\n" + head + "\n" + (ROOT / "miner" / "entry.lua").read_text())
    text = "\n".join(parts)
    OUT.write_text(text)
    print(f"{OUT} — {len(text)} B, {text.count(chr(10)) + 1} radku")
    print(f"{tpath} — testovaci varianta (vraci M)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
