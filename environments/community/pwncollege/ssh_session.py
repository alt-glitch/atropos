"""Persistent SSH session manager using asyncssh."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

import asyncssh

if TYPE_CHECKING:
    from sdk import DojoUser


@dataclass
class CommandResult:
    """Result of executing a command via SSH."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


class PersistentSSHSession:
    """Maintains a persistent shell session over SSH.

    State persists across commands (cd, environment variables, etc.).
    Uses UUID delimiters to detect command completion.
    """

    def __init__(
        self,
        host: str,
        port: int = 2222,
        timeout: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._conn: asyncssh.SSHClientConnection | None = None
        self._process: asyncssh.SSHClientProcess | None = None
        self._user: DojoUser | None = None

    async def connect(self, user: DojoUser) -> None:
        """Establish SSH connection with ed25519 key."""
        self._user = user

        try:
            # Connect using the user's SSH key
            self._conn = await asyncssh.connect(
                self.host,
                port=self.port,
                username="hacker",  # pwncollege uses 'hacker' as the username
                client_keys=[str(user.ssh_key_path)],
                known_hosts=None,  # Skip host key verification for CTF environment
            )
        except Exception as e:
            raise RuntimeError(f"Failed to connect via SSH: {e}") from e

        try:
            # Create a persistent bash shell
            self._process = await self._conn.create_process(
                "/bin/bash",
                stdin=asyncssh.PIPE,
                stdout=asyncssh.PIPE,
                stderr=asyncssh.PIPE,
            )
        except Exception as e:
            await self._conn.close()
            self._conn = None
            raise RuntimeError(f"Failed to create shell process: {e}") from e

        # Wait for shell to be ready by sending a simple command
        ready_marker = f"__READY_{uuid.uuid4().hex}__"
        try:
            self._process.stdin.write(f"echo {ready_marker}\n")
            await self._process.stdin.drain()
        except Exception as e:
            await self.close()
            raise RuntimeError(f"Failed to send ready command: {e}") from e

        # Read until we see the ready marker
        output = ""
        while ready_marker not in output:
            try:
                chunk = await asyncio.wait_for(
                    self._process.stdout.read(4096),
                    timeout=self.timeout,
                )
                if not chunk:
                    # Connection closed unexpectedly
                    await self.close()
                    raise RuntimeError(
                        f"SSH session closed unexpectedly during init. Output: {output[:500]}"
                    )
                output += chunk
            except asyncio.TimeoutError:
                await self.close()
                raise RuntimeError("SSH session failed to initialize (timeout)")

    async def execute(
        self,
        command: str,
        timeout: float | None = None,
    ) -> CommandResult:
        """Execute command in persistent shell.

        State persists across calls (cd, env vars, etc.).
        """
        if self._process is None:
            raise RuntimeError("SSH session not connected")

        timeout = timeout or self.timeout

        # Generate unique delimiter
        delimiter = f"__DONE_{uuid.uuid4().hex}__"
        exit_code_marker = f"__EXIT_{uuid.uuid4().hex}__"

        # Build command that captures exit code and marks completion
        # Redirect stderr to stdout for combined output, capture exit code separately
        wrapped_cmd = (
            f"{{ {command}; }} 2>&1\n"
            f"echo {exit_code_marker}$?\n"
            f"echo {delimiter}\n"
        )

        self._process.stdin.write(wrapped_cmd)
        await self._process.stdin.drain()

        # Read until we see the delimiter
        output = ""
        timed_out = False

        try:
            while delimiter not in output:
                chunk = await asyncio.wait_for(
                    self._process.stdout.read(4096),
                    timeout=timeout,
                )
                if not chunk:
                    break
                output += chunk
        except asyncio.TimeoutError:
            timed_out = True
            # Send Ctrl+C to try to terminate the command
            self._process.stdin.write("\x03\n")
            await self._process.stdin.drain()

        # Parse exit code from output
        exit_code = -1
        if exit_code_marker in output:
            try:
                marker_pos = output.index(exit_code_marker)
                code_start = marker_pos + len(exit_code_marker)
                code_end = output.index("\n", code_start)
                exit_code = int(output[code_start:code_end].strip())
                # Remove the exit code line from output
                output = output[:marker_pos] + output[code_end + 1 :]
            except (ValueError, IndexError):
                pass

        # Remove the delimiter from output
        if delimiter in output:
            output = output[: output.index(delimiter)]

        # Clean up output (remove trailing newlines, etc.)
        stdout = output.strip()

        return CommandResult(
            stdout=stdout,
            stderr="",  # stderr is combined with stdout
            exit_code=exit_code,
            timed_out=timed_out,
        )

    async def close(self) -> None:
        """Close SSH connection."""
        if self._process is not None:
            try:
                self._process.stdin.write("exit\n")
                await asyncio.wait_for(self._process.stdin.drain(), timeout=2.0)
            except Exception:
                pass  # Ignore errors during cleanup
            try:
                self._process.close()
            except Exception:
                pass
            self._process = None

        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

        self._user = None

    async def __aenter__(self) -> PersistentSSHSession:
        return self

    async def __aexit__(self, *_args) -> None:
        await self.close()
