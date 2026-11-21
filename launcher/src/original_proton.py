#!/usr/bin/env python3
# Runs the original Proton from its overlay mount but records the original location in config_info.
import builtins
import io
import os
import runpy
import sys

ORIGINAL = "__ORIGINAL__"

script = sys.argv[1]
view = os.path.dirname(script) + "/"
shown = ORIGINAL + "/"
real_open = builtins.open


class Writer:
    def __init__(self, handle):
        self.handle = handle

    def write(self, text):
        return self.handle.write(text.replace(view, shown))

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.handle.close()


def open_translated(file, mode="r", *args, **kwargs):
    handle = real_open(file, mode, *args, **kwargs)
    if (
        not isinstance(file, (str, os.PathLike))
        or os.path.basename(file) != "config_info"
        or "b" in mode
        or "+" in mode
    ):
        return handle
    if "w" in mode:
        return Writer(handle)
    if "r" in mode:
        with handle:
            text = handle.read()
        # An older launcher wrote the overlay path; an empty file makes Proton rewrite it.
        return io.StringIO("" if view in text else text.replace(shown, view))
    return handle


sys.argv = sys.argv[1:]
sys.path[0] = os.path.dirname(os.path.realpath(script))
builtins.open = open_translated
runpy.run_path(script, run_name="__main__")
