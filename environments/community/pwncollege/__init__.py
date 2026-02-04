"""PwnCollege CTF environment for Atropos.

This package provides both evaluation and training environments for pwn.college CTF challenges.

Shared utilities (sdk, ssh_session, tools, etc.) are at the package root.
The eval/ subdirectory contains the evaluation environment.
The train/ subdirectory contains the training environment for SFT/RL.
"""

from .sdk import DojoUser, PwnCollegeClient, PwnCollegeSyncClient, UserPool
from .ssh_session import PersistentSSHSession
from .tool_utils import (
    execute_tool,
    format_tool_result,
    function_to_tool_schema,
    parse_tool_calls,
)
from .tools import AGENT_TOOLS, bash, edit_file, read_file, submit_flag, write_file

__all__ = [
    # SDK
    "PwnCollegeClient",
    "PwnCollegeSyncClient",
    "DojoUser",
    "UserPool",
    # SSH
    "PersistentSSHSession",
    # Tools
    "bash",
    "read_file",
    "write_file",
    "edit_file",
    "submit_flag",
    "AGENT_TOOLS",
    # Tool utilities
    "function_to_tool_schema",
    "parse_tool_calls",
    "format_tool_result",
    "execute_tool",
]
