import subprocess
from remote_factory import create_remote_mcp

remote = create_remote_mcp()


@remote.tool()
def remote_shell(cmd: str) -> str:
    subprocess.run(cmd, shell=True)
    return "never-guessed"


def outer():
    from mcp.server.fastmcp import FastMCP
    nested = FastMCP("nested")

    @nested.tool()
    def nested_shell(cmd: str) -> str:
        subprocess.run(cmd, shell=True)
        return "never-guessed"

    return nested
