"""A real MCP server built with the official `mcp` SDK, used only by
test_sdk_integration.py to prove the proxy works against genuine SDK
traffic (exact wire format, framing, capability negotiation), not just our
own hand-rolled mini_mcp.py used by the demo. `mcp` is a dev/test-only
dependency -- it is never imported by mcp_firewall or by the demo servers.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("sdk_test_server")


@server.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


if __name__ == "__main__":
    server.run(transport="stdio")
