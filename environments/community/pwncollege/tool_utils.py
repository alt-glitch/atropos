"""Tool schema conversion and parsing utilities."""

from __future__ import annotations

import ast
import inspect
import json
import re
from typing import Any, Callable, get_type_hints


def _python_type_to_json_schema(py_type: type) -> dict[str, Any]:
    """Map Python type hints to JSON schema types."""
    if py_type is str:
        return {"type": "string"}
    elif py_type is int:
        return {"type": "integer"}
    elif py_type is float:
        return {"type": "number"}
    elif py_type is bool:
        return {"type": "boolean"}
    elif py_type is list:
        return {"type": "array"}
    elif py_type is dict:
        return {"type": "object"}
    elif py_type is type(None):
        return {"type": "null"}
    else:
        # For complex types, default to string
        return {"type": "string"}


def _parse_docstring(docstring: str) -> tuple[str, dict[str, str]]:
    """Parse docstring to extract description and parameter descriptions.

    Returns:
        Tuple of (main description, {param_name: param_description})
    """
    if not docstring:
        return "", {}

    lines = docstring.strip().split("\n")

    # Extract main description (everything before Args:)
    description_lines = []
    param_section = False
    args_started = False
    params: dict[str, str] = {}
    current_param: str | None = None
    current_desc: list[str] = []

    for line in lines:
        stripped = line.strip()

        if stripped.lower().startswith("args:"):
            args_started = True
            param_section = True
            continue

        if stripped.lower().startswith(("returns:", "raises:", "yields:", "examples:")):
            # Save current param if any
            if current_param and current_desc:
                params[current_param] = " ".join(current_desc).strip()
            param_section = False
            break

        if not args_started:
            description_lines.append(stripped)
        elif param_section:
            # Check if this is a new parameter
            param_match = re.match(r"^(\w+)\s*(?:\([^)]*\))?:\s*(.*)$", stripped)
            if param_match:
                # Save previous param
                if current_param and current_desc:
                    params[current_param] = " ".join(current_desc).strip()
                current_param = param_match.group(1)
                current_desc = [param_match.group(2)] if param_match.group(2) else []
            elif current_param and stripped:
                # Continuation of previous param description
                current_desc.append(stripped)

    # Save last param
    if current_param and current_desc:
        params[current_param] = " ".join(current_desc).strip()

    # Join description, taking first paragraph
    description = " ".join(description_lines).strip()
    # First paragraph only
    if "\n\n" in description:
        description = description.split("\n\n")[0]

    return description, params


def function_to_tool_schema(func: Callable) -> dict[str, Any]:
    """Convert async function to OpenAI tool schema.

    Extracts:
    - name from func.__name__
    - description from docstring (first paragraph)
    - parameters from type hints + docstring Args section
    """
    name = func.__name__
    docstring = inspect.getdoc(func) or ""
    description, param_docs = _parse_docstring(docstring)

    # Get function signature and type hints
    sig = inspect.signature(func)
    try:
        hints = get_type_hints(func)
    except Exception:
        hints = {}

    # Build parameters schema
    properties: dict[str, Any] = {}
    required: list[str] = []

    # Skip first two parameters (session/client dependencies)
    params_to_skip = {"session", "client", "self", "cls"}

    for param_name, param in sig.parameters.items():
        if param_name in params_to_skip:
            continue

        # Get type from hints or default to string
        param_type = hints.get(param_name, str)

        # Handle Optional types
        if hasattr(param_type, "__origin__"):
            origin = getattr(param_type, "__origin__", None)
            args = getattr(param_type, "__args__", ())
            if origin is type(None) or (args and type(None) in args):
                # Optional type - get the actual type
                actual_types = [a for a in args if a is not type(None)]
                param_type = actual_types[0] if actual_types else str

        prop = _python_type_to_json_schema(param_type)

        # Add description from docstring
        if param_name in param_docs:
            prop["description"] = param_docs[param_name]

        properties[param_name] = prop

        # Check if required (no default value)
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def tools_to_system_prompt_block(tools: list[Callable]) -> str:
    """Convert list of tool functions to <tools>...</tools> XML block."""
    schemas = [function_to_tool_schema(func) for func in tools]
    tools_json = json.dumps(schemas, indent=2)
    return f"<tools>\n{tools_json}\n</tools>"


def normalize_tool_call_json(raw: str) -> str | None:
    """Normalize Python dict/JSON to canonical JSON format.

    Handles both JSON and Python literal syntax via ast.literal_eval fallback.
    This is safe because ast.literal_eval only parses literal values
    (strings, numbers, tuples, lists, dicts, booleans, None) - it does NOT
    execute arbitrary code.

    Returns None if parsing fails.
    """
    raw = raw.strip()

    # Try standard JSON first
    try:
        obj = json.loads(raw)
        return json.dumps(obj, separators=(",", ":"))
    except json.JSONDecodeError:
        pass

    # Try Python literal (handles single quotes, True/False, None, etc.)
    # ast.literal_eval is safe - it only parses literal values, not arbitrary code
    try:
        obj = ast.literal_eval(raw)
        return json.dumps(obj, separators=(",", ":"))
    except (ValueError, SyntaxError):
        pass

    # Try fixing common issues
    try:
        # Replace Python-style booleans and None
        fixed = raw
        fixed = re.sub(r"\bTrue\b", "true", fixed)
        fixed = re.sub(r"\bFalse\b", "false", fixed)
        fixed = re.sub(r"\bNone\b", "null", fixed)
        # Replace single quotes with double quotes (simple cases)
        fixed = re.sub(r"'([^']*)':", r'"\1":', fixed)
        fixed = re.sub(r":\s*'([^']*)'", r':"\1"', fixed)

        obj = json.loads(fixed)
        return json.dumps(obj, separators=(",", ":"))
    except json.JSONDecodeError:
        pass

    return None


def parse_tool_calls(text: str) -> list[dict] | None:
    """Extract <tool_call>...</tool_call> blocks and return parsed JSON.

    Returns:
        List of parsed tool call dicts, or None if no valid tool calls found.
    """
    # Find all tool_call blocks
    pattern = r"<tool_call>\s*([\s\S]*?)\s*</tool_call>"
    matches = re.findall(pattern, text, flags=re.IGNORECASE)

    if not matches:
        return None

    tool_calls = []
    for raw in matches:
        normalized = normalize_tool_call_json(raw)
        if normalized is None:
            # Skip invalid tool calls
            continue
        try:
            parsed = json.loads(normalized)
            tool_calls.append(parsed)
        except json.JSONDecodeError:
            continue

    return tool_calls if tool_calls else None


def extract_think_block(text: str) -> str | None:
    """Extract content from <think>...</think> block.

    Returns the content inside the think block, or None if not found.
    """
    pattern = r"<think>([\s\S]*?)</think>"
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else None


def has_think_block(text: str) -> bool:
    """Check if text contains a <think>...</think> block."""
    return bool(re.search(r"<think>[\s\S]*?</think>", text, flags=re.IGNORECASE))


def validate_response(text: str, expect_tool_calls: bool = True) -> bool:
    """Validate response has proper <think> blocks and tool call format.

    Args:
        text: The response text to validate.
        expect_tool_calls: Whether tool calls are expected in this response.

    Returns:
        True if response is valid, False otherwise.
    """
    # Must start with <think> block
    if not re.match(r"^\s*<think>", text, flags=re.IGNORECASE):
        return False

    # Must have exactly one <think> block
    think_blocks = re.findall(r"<think>[\s\S]*?</think>", text, flags=re.IGNORECASE)
    if len(think_blocks) != 1:
        return False

    # Check tool calls
    has_tool_calls = bool(
        re.search(r"<tool_call>[\s\S]*?</tool_call>", text, flags=re.IGNORECASE)
    )

    if expect_tool_calls and not has_tool_calls:
        return False

    if has_tool_calls:
        # Validate that tool calls can be parsed
        tool_calls = parse_tool_calls(text)
        if tool_calls is None:
            return False

    return True


def format_tool_result(tool_name: str, result: str) -> str:
    """Format tool result for inclusion in conversation."""
    return f"<tool_response>\n[{tool_name}]\n{result}\n</tool_response>"


async def execute_tool(
    ssh_session,
    client,
    data_item: dict,
    tool_call: dict,
) -> tuple[str, bool]:
    """Execute a tool call and return (formatted_result, is_solved).

    This shared function is used by both eval and train environments.

    Args:
        ssh_session: PersistentSSHSession for executing shell commands.
        client: PwnCollegeClient for flag submission.
        data_item: Challenge data containing dojo_id, module_id, challenge_id.
        tool_call: Parsed tool call dict with 'name' and 'arguments'.

    Returns:
        Tuple of (formatted result string, whether challenge was solved).
    """
    # Import here to avoid circular imports
    from .tools import bash, edit_file, read_file, submit_flag, write_file

    name = tool_call.get("name", "")
    args = tool_call.get("arguments", {})

    if name == "bash":
        command = args.get("command", "")
        result = await bash(ssh_session, command)
        return format_tool_result("bash", result), False

    elif name == "read_file":
        file_path = args.get("file_path", "")
        offset = int(args.get("offset", 1))
        limit = args.get("limit")
        if limit is not None:
            limit = int(limit)
        result = await read_file(ssh_session, file_path, offset, limit)
        return format_tool_result("read_file", result), False

    elif name == "write_file":
        file_path = args.get("file_path", "")
        content = args.get("content", "")
        result = await write_file(ssh_session, file_path, content)
        return format_tool_result("write_file", result), False

    elif name == "edit_file":
        file_path = args.get("file_path", "")
        old_string = args.get("old_string", "")
        new_string = args.get("new_string", "")
        result = await edit_file(ssh_session, file_path, old_string, new_string)
        return format_tool_result("edit_file", result), False

    elif name == "submit_flag":
        flag = args.get("flag", "")
        result, is_correct = await submit_flag(
            client,
            data_item["dojo_id"],
            data_item["module_id"],
            data_item["challenge_id"],
            flag,
        )
        return format_tool_result("submit_flag", result), is_correct

    else:
        return format_tool_result("error", f"Unknown tool: {name}"), False
