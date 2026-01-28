#!/usr/bin/env python3
"""Generate HTML viewer for pwn.college CTF rollouts."""

import html
import json
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
TEMPLATE_FILE = SCRIPT_DIR / "viewer_template.html"


def parse_assistant_content(content: str) -> dict:
    """Extract think blocks and tool calls from assistant message."""
    think_match = re.search(r"<think>([\s\S]*?)</think>", content)
    tool_match = re.search(r"<tool_call>\s*([\s\S]*?)\s*</tool_call>", content)

    # Get remaining text (after think/tool_call blocks)
    remaining = content
    if think_match:
        remaining = remaining.replace(think_match.group(0), "")
    if tool_match:
        remaining = remaining.replace(tool_match.group(0), "")
    remaining = remaining.strip()

    return {
        "think": think_match.group(1).strip() if think_match else None,
        "tool_call": tool_match.group(1).strip() if tool_match else None,
        "text": remaining if remaining else None,
    }


def format_json_with_syntax(json_str: str) -> str:
    """Format JSON string with syntax highlighting spans."""
    try:
        parsed = json.loads(json_str)
        formatted = json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        formatted = json_str

    # Apply syntax highlighting
    def highlight(match):
        text = match.group(0)
        if text.startswith('"') and text.endswith('":'):
            # Key
            return f'<span class="json-key">{html.escape(text)}</span>'
        elif text.startswith('"'):
            # String value
            return f'<span class="json-string">{html.escape(text)}</span>'
        elif text in ("true", "false"):
            return f'<span class="json-boolean">{text}</span>'
        elif text == "null":
            return f'<span class="json-null">{text}</span>'
        elif re.match(r"^-?\d+\.?\d*$", text):
            return f'<span class="json-number">{text}</span>'
        return html.escape(text)

    # Match JSON tokens
    result = re.sub(
        r'"[^"\\]*(?:\\.[^"\\]*)*":|"[^"\\]*(?:\\.[^"\\]*)*"|true|false|null|-?\d+\.?\d*',
        highlight,
        formatted,
    )
    return result


def create_message_html(msg: dict, index: int) -> str:
    """Generate HTML for a single message."""
    role = msg.get("role", "unknown")
    content = msg.get("content", "")

    if role == "assistant":
        parsed = parse_assistant_content(content)
        parts = []

        # Think block (collapsed by default)
        if parsed["think"]:
            think_escaped = html.escape(parsed["think"])
            parts.append(
                f"""
                <div class="think-block collapsed" onclick="toggleCollapsed(this)">
                    <div class="think-header">Thinking</div>
                    <div class="think-content">{think_escaped}</div>
                </div>
            """
            )

        # Tool call with syntax highlighting
        if parsed["tool_call"]:
            try:
                tool_json = json.loads(parsed["tool_call"])
                tool_name = tool_json.get("name", "unknown")
                formatted_json = format_json_with_syntax(parsed["tool_call"])
            except json.JSONDecodeError:
                tool_name = "tool_call"
                formatted_json = html.escape(parsed["tool_call"])

            parts.append(
                f"""
                <div class="tool-call">
                    <div class="tool-call-header">{html.escape(tool_name)}</div>
                    <div class="tool-call-body">{formatted_json}</div>
                </div>
            """
            )

        # Regular text
        if parsed["text"]:
            parts.append(
                f"""
                <div class="assistant-text">{html.escape(parsed["text"])}</div>
            """
            )

        content_html = (
            "\n".join(parts) if parts else f"<pre>{html.escape(content)}</pre>"
        )

        return f"""
            <div class="message assistant" data-index="{index}">
                <div class="message-header">Assistant</div>
                <div class="message-content">{content_html}</div>
            </div>
        """

    elif role == "system":
        # System prompt - collapsed by default
        return f"""
            <div class="message system collapsed" data-index="{index}">
                <div class="message-header">System Prompt</div>
                <div class="message-content">{html.escape(content)}</div>
                <button class="expand-btn" onclick="toggleCollapsed(this.parentElement)">
                    Toggle
                </button>
            </div>
        """

    elif role == "tool":
        # Tool result
        tool_name = msg.get("name", "tool")
        is_long = len(content) > 500
        collapsed_class = "collapsed" if is_long else ""
        expand_btn = "<button class='expand-btn' onclick='toggleCollapsed(this.parentElement)'>Toggle</button>"

        return f"""
            <div class="message tool {collapsed_class}" data-index="{index}">
                <div class="message-header">Tool Result: {html.escape(tool_name)}</div>
                <div class="message-content">{html.escape(content)}</div>
                {expand_btn if is_long else ""}
            </div>
        """

    else:
        # User message
        return f"""
            <div class="message user" data-index="{index}">
                <div class="message-header">User</div>
                <div class="message-content">{html.escape(content)}</div>
            </div>
        """


def create_challenge_html(challenge: dict, index: int) -> str:
    """Generate HTML for a single challenge rollout."""
    solved = challenge.get("solved", False)
    status_class = "solved" if solved else "unsolved"
    status_icon = "✅" if solved else "❌"

    dojo = challenge.get("dojo", "")
    module = challenge.get("module", "")
    challenge_name = challenge.get("challenge_name", "Unknown")
    challenge_id = challenge.get("challenge_id", "")
    num_turns = challenge.get("num_turns", 0)
    difficulty = challenge.get("difficulty", 0)

    # Build messages HTML
    messages_html = ""
    for i, msg in enumerate(challenge.get("messages", [])):
        messages_html += create_message_html(msg, i)

    return f"""
    <details class="challenge {status_class}" data-dojo="{html.escape(dojo)}"
             data-module="{html.escape(module)}" data-solved="{str(solved).lower()}"
             data-index="{index}">
        <summary>
            <span class="status-icon">{status_icon}</span>
            <span class="challenge-name">{html.escape(challenge_name)}</span>
            <span class="challenge-meta">
                <span class="meta-item">{html.escape(module)}</span>
                <span class="meta-item">{num_turns} turns</span>
                <span class="meta-item">Difficulty: {difficulty}</span>
            </span>
            <span class="expand-icon">&#9654;</span>
        </summary>
        <div class="challenge-content">
            <div class="challenge-info">
                <span><strong>Dojo:</strong> {html.escape(dojo)}</span>
                <span><strong>Module:</strong> {html.escape(module)}</span>
                <span><strong>Challenge ID:</strong> {html.escape(challenge_id)}</span>
                <span><strong>Difficulty:</strong> {difficulty}</span>
            </div>
            <div class="messages">
                {messages_html}
            </div>
        </div>
    </details>
    """


def generate_stats(challenges: list) -> dict:
    """Calculate summary statistics."""
    total = len(challenges)
    solved = sum(1 for c in challenges if c.get("solved"))
    by_module = {}

    for c in challenges:
        mod = c.get("module", "Unknown")
        if mod not in by_module:
            by_module[mod] = {"total": 0, "solved": 0}
        by_module[mod]["total"] += 1
        if c.get("solved"):
            by_module[mod]["solved"] += 1

    return {"total": total, "solved": solved, "by_module": by_module}


def generate_html(input_path: str, output_path: str | None = None):
    """Generate HTML viewer from JSONL rollouts.

    Args:
        input_path: Path to JSONL file with rollout data
        output_path: Optional output path for HTML (defaults to same name with .html extension)
    """
    input_filepath = Path(input_path)
    output_filepath = (
        Path(output_path) if output_path else input_filepath.with_suffix(".html")
    )

    # Load template
    if not TEMPLATE_FILE.exists():
        raise FileNotFoundError(f"Template file not found: {TEMPLATE_FILE}")
    template = TEMPLATE_FILE.read_text()

    # Load and parse rollouts
    challenges = []
    with open(input_filepath) as f:
        for line in f:
            if line.strip():
                challenges.append(json.loads(line))

    if not challenges:
        raise ValueError(f"No challenges found in {input_filepath}")

    # Generate HTML
    stats = generate_stats(challenges)
    challenges_html = "\n".join(
        create_challenge_html(c, i) for i, c in enumerate(challenges)
    )

    # Calculate accuracy
    accuracy = round((stats["solved"] / stats["total"]) * 100) if stats["total"] else 0
    unsolved = stats["total"] - stats["solved"]

    # Populate template using string replacement (avoids conflicts with CSS braces)
    final_html = (
        template.replace("%%TITLE%%", f"CTF Rollouts - {input_filepath.name}")
        .replace("%%STATS_JSON%%", json.dumps(stats))
        .replace("%%TOTAL%%", str(stats["total"]))
        .replace("%%SOLVED%%", str(stats["solved"]))
        .replace("%%UNSOLVED%%", str(unsolved))
        .replace("%%ACCURACY%%", str(accuracy))
        .replace("%%CHALLENGES_HTML%%", challenges_html)
    )

    output_filepath.write_text(final_html)
    print(f"Generated: {output_filepath.absolute()}")
    print(f"Stats: {stats['solved']}/{stats['total']} solved ({accuracy}%)")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate HTML viewer for pwn.college CTF rollouts"
    )
    parser.add_argument("input_path", help="Path to JSONL file with rollout data")
    parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        default=None,
        help="Output path for HTML (defaults to same name with .html extension)",
    )

    args = parser.parse_args()
    generate_html(args.input_path, args.output_path)
