"""Backwards-compatible facade over the split state modules.

The real logic now lives in :mod:`paths`, :mod:`ownership`, :mod:`storage` and
:mod:`state`. New code should import those directly; this module re-exports the
public functions so older ``profile.<fn>`` call sites keep working.
"""
from .ownership import chown_user, ensure_dirs
from .storage import (clear, count, list_all, load, read_json, remove, save,
                      write_json)
from .state import set_default

__all__ = [
    "chown_user", "ensure_dirs", "clear", "count", "list_all", "load",
    "read_json", "remove", "save", "write_json", "set_default",
]
