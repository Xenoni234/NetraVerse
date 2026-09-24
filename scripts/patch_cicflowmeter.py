"""Patch the installed cicflowmeter 0.5.0 argument-order bug (idempotent).

`cicflowmeter/sniffer.py` `main()` calls `create_sniffer(...)` passing
`args.fields` and `args.verbose` *positionally*, so `verbose` (a bool) lands in
the `fields` parameter and the tool crashes with
``AttributeError: 'bool' object has no attribute 'split'`` on first packet setup.

This rewrites the call to pass `fields=`/`verbose=` by keyword. Run once after
`pip install cicflowmeter` (or after rebuilding the venv):

    python scripts/patch_cicflowmeter.py
"""

from __future__ import annotations

import pathlib
import sys

OLD = """    sniffer, session = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.fields,
        args.verbose,
    )"""

NEW = """    sniffer, session = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        fields=args.fields,
        verbose=args.verbose,
    )"""


def main() -> int:
    try:
        import cicflowmeter.sniffer as sniffer_mod
    except ImportError:
        print("cicflowmeter is not installed in this environment.")
        return 1
    path = pathlib.Path(sniffer_mod.__file__)
    text = path.read_text()
    if NEW in text:
        print(f"already patched: {path}")
        return 0
    if OLD not in text:
        print(f"pattern not found (version changed?): {path} — inspect manually.")
        return 2
    path.write_text(text.replace(OLD, NEW))
    print(f"patched: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
