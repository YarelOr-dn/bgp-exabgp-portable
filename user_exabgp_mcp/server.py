"""User ExaBGP MCP Server: Starlette + MCP SSE entry point."""
from __future__ import annotations

import logging
import os

from mcp_common.server import create_mcp_app, run_app
from .tools import get_tool_definitions, handle_tool_call

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
SERVICE_NAME = 'user-exabgp-mcp'
VERSION = "0.1.0"
PORT = int(os.environ.get('USER_EXABGP_MCP_PORT', "9304"))

app = create_mcp_app(
    service_name=SERVICE_NAME,
    port=PORT,
    version=VERSION,
    get_tool_definitions=get_tool_definitions,
    handle_tool_call=handle_tool_call,
)

def main() -> None:
    run_app("user_exabgp_mcp.server:app", PORT)

if __name__ == "__main__":
    main()
