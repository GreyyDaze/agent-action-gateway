"""The single config loader.

Re-exports ``load_route_policy`` from ``cli`` (where it historically lived) so
there is one documented import point. Both paths return the same object.
"""
from agent_action_gateway.cli import load_route_policy

__all__ = ["load_route_policy"]
