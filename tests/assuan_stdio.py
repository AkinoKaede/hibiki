"""Shared stdio helpers for the deterministic Assuan test servers."""
import sys


def emit(line):
    sys.stdout.buffer.write(line + b'\n')
    sys.stdout.buffer.flush()


def esc(data):
    return data.replace(b'%', b'%25').replace(b'\r', b'%0D').replace(b'\n', b'%0A')
