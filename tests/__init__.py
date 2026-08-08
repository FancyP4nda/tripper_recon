"""Test suite for tripper_recon.

Every test in this package runs offline. The tool is passive-only by design, and a test that
reaches the network would both violate that constraint and make the suite non-deterministic.
HTTP is mocked with respx; nothing else opens a socket.
"""

from __future__ import annotations
