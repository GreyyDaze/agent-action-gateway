"""Run defaults, in one place.

Re-exported from ``runtime.session`` (the historical home) so existing callers
keep working, while new code imports from here.
"""
from safety_layer.runtime.session import DEFAULT_FUSE_LIMITS

__all__ = ["DEFAULT_FUSE_LIMITS"]
