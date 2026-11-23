"""Compatibility shim. Canonical module: safety_layer.policy.stop_rules."""
import importlib as _importlib  # noqa: E402

from safety_layer.policy.stop_rules import *  # noqa: F401,F403,E402

_canonical = _importlib.import_module("safety_layer.policy.stop_rules")  # noqa: E402

def __getattr__(name):  # noqa: E402
    return getattr(_canonical, name)
