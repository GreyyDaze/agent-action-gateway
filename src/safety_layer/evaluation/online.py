"""Compatibility shim. Canonical module: safety_layer.eval.online."""
import importlib as _importlib  # noqa: E402

from safety_layer.eval.online import *  # noqa: F401,F403,E402

_canonical = _importlib.import_module("safety_layer.eval.online")  # noqa: E402

def __getattr__(name):  # noqa: E402
    return getattr(_canonical, name)
