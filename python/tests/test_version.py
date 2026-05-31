#!/usr/bin/env python3
"""Smoke test: library_version matches package __version__."""

import sys

import uacryptex

v = uacryptex.library_version()
if v != uacryptex.__version__:
    print(f"expected {uacryptex.__version__}, got {v}", file=sys.stderr)
    sys.exit(1)

print(f"OK: {v}")
