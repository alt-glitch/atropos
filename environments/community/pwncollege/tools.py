"""Tool implementations for pwn.college CTF evaluation.

Each tool function takes a PersistentSSHSession (or PwnCollegeClient) as its
first argument, followed by the tool-specific parameters. This enables
dependency injection and makes testing easier.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sdk import PwnCollegeClient
    from ssh_session import PersistentSSHSession

# Token guardrails - prevent context overflow from large outputs
MAX_OUTPUT_LENGTH = 30000  # Max chars for command output (middle truncation)
MAX_FILE_SIZE = 256 * 1024  # 256KB max file size for read_file
MAX_LINES_TO_READ = 2000  # Default line limit for read_file
MAX_LINE_LENGTH = 2000  # Truncate individual lines longer than this
MAX_EDIT_FILE_SIZE = 30000  # Max file size for edit_file operations

TRUNCATED_MESSAGE = (
    "\n<NOTE>Output truncated. Use more specific commands or "
    "read_file with offset/limit to see remaining content.</NOTE>"
)


def truncate_output(content: str, max_length: int = MAX_OUTPUT_LENGTH) -> str:
    """Truncate content from middle if it exceeds max_length.

    Preserves start and end of output which typically contain the most
    useful information (command start, final results/errors).
    """
    if len(content) <= max_length:
        return content

    half = max_length // 2
    start = content[:half]
    end = content[-half:]
    middle_lines = content[half:-half].count("\n")

    return f"{start}\n\n... [{middle_lines} lines truncated] ...\n\n{end}"


def truncate_lines(content: str, max_line_length: int = MAX_LINE_LENGTH) -> str:
    """Truncate individual lines that exceed max_line_length."""
    lines = content.split("\n")
    truncated = []
    for line in lines:
        if len(line) > max_line_length:
            truncated.append(line[:max_line_length] + "... [line truncated]")
        else:
            truncated.append(line)
    return "\n".join(truncated)


async def bash(session: PersistentSSHSession, command: str) -> str:
    """Execute a bash command on the challenge container.

    Args:
        command: Shell command to execute. State persists across calls
                 (cd, environment variables, background processes).

    Returns:
        Command output (stdout and stderr combined), truncated if too large.
    """
    result = await session.execute(command)

    output = result.stdout

    # Apply token guardrails - truncate from middle if too large
    was_truncated = len(output) > MAX_OUTPUT_LENGTH
    output = truncate_output(output)

    if result.timed_out:
        output += "\n[Command timed out]"
    if result.exit_code != 0:
        output += f"\n[Exit code: {result.exit_code}]"
    if was_truncated:
        output += TRUNCATED_MESSAGE

    return output


async def read_file(
    session: PersistentSSHSession,
    file_path: str,
    offset: int = 1,
    limit: int | None = None,
) -> str:
    """Read contents of a file.

    Args:
        file_path: Path to the file to read.
        offset: Line number to start reading from (1-indexed).
        limit: Maximum number of lines to read (default: 2000).

    Returns:
        File contents with line numbers.
    """
    quoted_path = shlex.quote(file_path)

    # Check file size first if no limit specified
    if limit is None:
        size_cmd = f"stat -c%s {quoted_path} 2>/dev/null || stat -f%z {quoted_path}"
        size_result = await session.execute(size_cmd)
        if size_result.exit_code == 0:
            try:
                file_size = int(size_result.stdout.strip())
                if file_size > MAX_FILE_SIZE:
                    return (
                        f"Error: File is {file_size // 1024}KB, exceeds "
                        f"{MAX_FILE_SIZE // 1024}KB limit. "
                        f"Use offset and limit parameters to read specific portions, "
                        f"or use bash with head/tail/grep for targeted reads."
                    )
            except ValueError:
                pass  # Could not parse size, proceed anyway

    # Apply default line limit if not specified
    effective_limit = limit if limit is not None else MAX_LINES_TO_READ

    # Build command with proper quoting
    end_line = offset + effective_limit - 1
    cmd = f"sed -n '{offset},{end_line}p' {quoted_path} | nl -ba -v {offset}"

    result = await session.execute(cmd)

    if result.exit_code != 0:
        return f"Error reading file: {result.stdout}"

    output = result.stdout

    # Truncate long individual lines
    output = truncate_lines(output)

    # Add note if we applied default limit
    if limit is None and output.count("\n") >= MAX_LINES_TO_READ - 1:
        output += (
            f"\n\n[Showing first {MAX_LINES_TO_READ} lines. "
            f"Use offset/limit parameters to read more.]"
        )

    return output


async def write_file(
    session: PersistentSSHSession,
    file_path: str,
    content: str,
) -> str:
    """Write content to a file (creates or overwrites).

    Args:
        file_path: Path to the file to write.
        content: Content to write to the file.

    Returns:
        Confirmation message.
    """
    # Escape content for heredoc
    # Use a unique delimiter that won't appear in the content
    delimiter = "EOF_WRITE_FILE_MARKER"
    while delimiter in content:
        delimiter += "_X"

    quoted_path = shlex.quote(file_path)

    # Use heredoc to write content
    cmd = f"cat > {quoted_path} << '{delimiter}'\n{content}\n{delimiter}"

    result = await session.execute(cmd)

    if result.exit_code != 0:
        return f"Error writing file: {result.stdout}"

    return f"Successfully wrote {len(content)} bytes to {file_path}"


async def edit_file(
    session: PersistentSSHSession,
    file_path: str,
    old_string: str,
    new_string: str,
) -> str:
    """Edit a file by replacing old_string with new_string.

    Args:
        file_path: Path to the file to edit.
        old_string: Exact string to find and replace.
        new_string: String to replace with.

    Returns:
        Confirmation message or error.
    """
    quoted_path = shlex.quote(file_path)

    # Check file size first - reject files too large to reliably edit
    size_cmd = f"stat -c%s {quoted_path} 2>/dev/null || stat -f%z {quoted_path}"
    size_result = await session.execute(size_cmd)
    if size_result.exit_code == 0:
        try:
            file_size = int(size_result.stdout.strip())
            if file_size > MAX_EDIT_FILE_SIZE:
                return (
                    f"Error: File is {file_size} bytes, exceeds {MAX_EDIT_FILE_SIZE} byte limit "
                    f"for edit operations. Use bash with sed for large file edits, or "
                    f"read_file with offset/limit to view specific sections first."
                )
        except ValueError:
            pass  # Could not parse size, proceed anyway

    # First, check if the file contains the old_string
    check_cmd = f"grep -F {shlex.quote(old_string)} {quoted_path}"
    check_result = await session.execute(check_cmd)

    if check_result.exit_code != 0:
        return f"Error: String not found in {file_path}"

    # Read the file
    read_result = await session.execute(f"cat {quoted_path}")
    if read_result.exit_code != 0:
        return f"Error reading file: {read_result.stdout}"

    original_content = read_result.stdout

    # Double-check size after reading (in case stat failed)
    if len(original_content) > MAX_EDIT_FILE_SIZE:
        return (
            f"Error: File content is {len(original_content)} chars, exceeds "
            f"{MAX_EDIT_FILE_SIZE} char limit. Use bash with sed for large file edits."
        )

    # Count occurrences
    count = original_content.count(old_string)
    if count == 0:
        return f"Error: String not found in {file_path}"
    if count > 1:
        return (
            f"Error: String appears {count} times in {file_path}. "
            "Please provide a more specific string to ensure only one match."
        )

    # Perform the replacement
    new_content = original_content.replace(old_string, new_string, 1)

    # Write the new content
    write_result = await write_file(session, file_path, new_content)

    if "Error" in write_result:
        return write_result

    return f"Successfully replaced string in {file_path}"


async def submit_flag(
    client: PwnCollegeClient,
    dojo: str,
    module: str,
    challenge: str,
    flag: str,
) -> tuple[str, bool]:
    """Submit a flag for verification.

    Args:
        flag: The flag string (format: pwn.college{...}).

    Returns:
        Tuple of (message, is_correct).
    """
    try:
        response = await client.submit_flag(
            dojo=dojo,
            module=module,
            challenge=challenge,
            flag=flag,
        )

        is_correct = response.get("success", False)
        if is_correct:
            return "Flag accepted! Challenge solved.", True
        else:
            message = response.get("message", "Flag incorrect")
            return f"Flag rejected: {message}", False
    except Exception as e:
        return f"Error submitting flag: {e}", False


# Tools available to the agent (for schema generation)
# Note: submit_flag is handled specially since it needs the client, not session
AGENT_TOOLS = [bash, read_file, write_file, edit_file]
