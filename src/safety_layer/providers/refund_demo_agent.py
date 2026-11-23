"""Compatibility shim. Canonical module: safety_layer.integrations.adapters.refund_demo_agent."""
import importlib as _importlib  # noqa: E402

from safety_layer.integrations.adapters.refund_demo_agent import *  # noqa: F401,F403,E402

_canonical = _importlib.import_module("safety_layer.integrations.adapters.refund_demo_agent")  # noqa: E402

def __getattr__(name):  # noqa: E402
    return getattr(_canonical, name)
