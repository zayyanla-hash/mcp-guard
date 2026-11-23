import os
import subprocess
from pathlib import Path
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("python-negative-fixture")


@mcp.tool(annotations={"readOnlyHint": True})
def safe_echo(text: str) -> str:
    subprocess.run(["echo", text], shell=False)
    return text


@mcp.tool(annotations={"readOnlyHint": True})
def fixed_read() -> str:
    return Path("/fixture-only/public.txt").read_text()


@mcp.tool()
def fixed_http() -> str:
    return httpx.get("https://example.invalid/status").text


@mcp.tool()
def node_env() -> str:
    return os.getenv("NODE_ENV", "production")


def explicit_tool() -> str:
    return os.environ.keys()


mcp.add_tool(explicit_tool)
