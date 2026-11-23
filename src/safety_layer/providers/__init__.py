"""In-process action adapters — legacy escape hatch.

This package was the original external boundary. It is now the **in-process
tool path only**: the callable a wrapped agent tool invokes. Credential custody
for HTTP actions has moved to ``safety_layer.credential.credentials`` and the
egress policy to ``safety_layer.credential.egress``.

Why keep it:

- ``ExternalActionProvider`` is the dispatch interface ``core.enforcement``
  calls from the wrapper. Removing it would break the enforced in-process path.
- Some credentials cannot be swapped as placeholders — a request that must be
  **signed** locally (SigV4, HMAC, webhook signatures) needs the real secret in
  the tool process. Those tools belong here, wrapped by ``ctx.tool``.

What NOT to do:

- Do not add a new per-vendor adapter here for ordinary bearer-token HTTP APIs.
  Put a ``CredentialRule`` + a route in the gateway instead — one config line,
  no vendor-specific class.
- Do not read a vendor key from the agent's environment in a new adapter. That
  is the boundary this package is being retired from.
"""

from __future__ import annotations
