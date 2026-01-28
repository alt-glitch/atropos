"""
pwn.college Evaluation Environment for Atropos

This environment evaluates models on pwn.college's CTF (Capture The Flag) cybersecurity challenges.

Each module houses several challenge containers, flag checker and problem statements.

The base environment currently expects the Dojo (and within it, the modules) to be hosted:
https://github.com/alt-glitch/dojo/blob/master/docs/deployment.md

Read the README.md for more hosting information.

The model is provided tools to interact with each challenge container via persistent SSH,
similar to terminal bench as well as submit flags, and optionally restart the container.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from prompts import SUBMIT_FLAG_TOOL, SYSTEM_PROMPT_TEMPLATE, USER_PROMPT_TEMPLATE
from sdk import DojoUser, PwnCollegeClient, PwnCollegeSyncClient, UserPool
from ssh_session import PersistentSSHSession
from tool_utils import (
    format_tool_result,
    function_to_tool_schema,
    parse_tool_calls,
)
from tools import AGENT_TOOLS, bash, edit_file, read_file, submit_flag, write_file

from atroposlib.envs.eval import EvalBase
from atroposlib.envs.server_handling.server_baseline import APIServerConfig
from atroposlib.envs.server_handling.server_manager import ServerManager

# Difficulty tiers by dojo
DOJO_DIFFICULTY = {
    "linux-luminarium": 0,
    "computing-101": 0,
    "playing-with-programs": 0,
    "intro-to-cybersecurity": 1,
    "program-security": 2,
    "system-security": 3,
    "software-exploitation": 4,
}


def _build_tools_block() -> str:
    """Build the tools XML block for the system prompt."""
    schemas = [function_to_tool_schema(func) for func in AGENT_TOOLS]
    schemas.append(SUBMIT_FLAG_TOOL)
    return "<tools>\n" + json.dumps(schemas, indent=2) + "\n</tools>"


class PwnCollegeEval(EvalBase):
    """Evaluates models on pwn.college CTF challenges."""

    def __init__(
        self,
        base_url: str = "https://zephyr.tail119aa7.ts.net/",
        ssh_host: str = "zephyr.tail119aa7.ts.net",
        ssh_port: int = 2222,
        max_turns: int = 20,
        max_tokens: int = 4096,
        max_eval_items: int = -1,
        difficulty_filter: int = -1,
        dojo_filter: str | None = None,
        module_filter: str | None = None,
        challenge_filter: str | None = None,
        num_users: int = 4,
        ssh_timeout: float = 30.0,
        eval_dir: str | None = None,
        **kwargs,
    ):
        self.base_url = base_url
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.max_eval_items = max_eval_items
        self.difficulty_filter = difficulty_filter
        self.dojo_filter = dojo_filter
        self.module_filter = module_filter
        self.challenge_filter = challenge_filter
        self.num_users = num_users
        self.ssh_timeout = ssh_timeout
        self.eval_dir = eval_dir
        self.pool: UserPool | None = None
        self.client: PwnCollegeClient | None = None

        # Pre-build tools block for system prompt
        self.tools_block = _build_tools_block()

        super().__init__(**kwargs)

    def setup_data(self) -> list:
        """Fetch all challenges from the dojo API and return as list."""
        rows: list[dict[str, Any]] = []

        with PwnCollegeSyncClient(self.base_url) as client:
            dojos_response = client.list_dojos()
            dojos = dojos_response.get("dojos", [])

            print(f"Found {len(dojos)} dojos")

            for dojo in dojos:
                dojo_id = dojo.get("id", "")
                dojo_name = dojo.get("name", "")
                dojo_description = dojo.get("description", "")
                difficulty = DOJO_DIFFICULTY.get(dojo_id, -1)

                # Apply dojo filter
                if self.dojo_filter and dojo_id != self.dojo_filter:
                    continue

                print(f"  Processing dojo: {dojo_id} (difficulty={difficulty})")

                try:
                    modules_response = client.list_modules(dojo_id)
                except Exception as e:
                    print(f"    Failed to get modules for {dojo_id}: {e}")
                    continue

                modules = modules_response.get("modules", [])

                for module in modules:
                    module_id = module.get("id", "")
                    module_name = module.get("name", "")
                    module_description = module.get("description", "")
                    challenges = module.get("challenges", [])

                    # Apply module filter
                    if self.module_filter and module_id != self.module_filter:
                        continue

                    # Build section header mapping from unified_items
                    unified_items = module.get("unified_items", [])
                    challenge_to_section: dict[str, str] = {}
                    current_section = ""

                    for item in unified_items:
                        item_type = item.get("item_type", "")
                        if item_type == "resource" and item.get("type") == "header":
                            current_section = item.get("name") or current_section
                        elif item_type == "challenge":
                            challenge_to_section[item.get("id", "")] = current_section

                    for idx, challenge in enumerate(challenges):
                        challenge_id = challenge.get("id", "")
                        challenge_name = challenge.get("name", "")
                        challenge_description = challenge.get("description", "")
                        required = challenge.get("required", False)
                        section_header = challenge_to_section.get(challenge_id, "")

                        # Apply challenge filter
                        if (
                            self.challenge_filter
                            and challenge_id != self.challenge_filter
                        ):
                            continue

                        # Infer category from dojo/module names
                        combined = f"{dojo_name} {module_name}".lower()
                        category = "misc"
                        categories = {
                            "pwn": ["pwn", "exploit", "buffer", "overflow", "rop"],
                            "web": ["web", "xss", "sql", "injection", "csrf"],
                            "crypto": ["crypto", "cipher", "rsa", "aes", "hash"],
                            "reverse": ["reverse", "reversing", "binary"],
                            "forensics": ["forensic", "memory", "disk"],
                            "misc": ["misc", "welcome", "intro", "hello"],
                        }
                        for cat, keywords in categories.items():
                            if any(kw in combined for kw in keywords):
                                category = cat
                                break

                        # Build system prompt with tools
                        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
                            tools_block=self.tools_block
                        )

                        # Build user prompt for this challenge
                        user_prompt = USER_PROMPT_TEMPLATE.format(
                            module_name=module_name,
                            challenge_name=challenge_name,
                            challenge_description=challenge_description
                            or "No description provided.",
                        )
                        initial_messages = [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ]

                        row = {
                            "dojo_id": dojo_id,
                            "module_id": module_id,
                            "challenge_id": challenge_id,
                            "dojo_name": dojo_name,
                            "dojo_description": dojo_description,
                            "module_name": module_name,
                            "module_description": module_description,
                            "section_header": section_header,
                            "challenge_name": challenge_name,
                            "challenge_description": challenge_description,
                            "challenge_index": idx,
                            "required": required,
                            "difficulty": difficulty,
                            "category": category,
                            "initial_messages": initial_messages,
                        }
                        rows.append(row)

        print(f"Total challenges: {len(rows)}")

        # Apply filters
        if self.difficulty_filter >= 0:
            rows = [r for r in rows if r["difficulty"] == self.difficulty_filter]
        if self.max_eval_items > 0:
            rows = rows[: self.max_eval_items]

        return rows

    async def _execute_tool(
        self,
        ssh_session: PersistentSSHSession,
        user: DojoUser,
        data_item: dict,
        tool_call: dict,
        client: PwnCollegeClient,
    ) -> tuple[str, bool]:
        """Execute tool and return (result_string, is_solved)."""
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

            # Login as user to submit flag
            await client.login(user.username, user.password)
            result, is_correct = await submit_flag(
                client,
                data_item["dojo_id"],
                data_item["module_id"],
                data_item["challenge_id"],
                flag,
            )
            await client.logout()

            return format_tool_result("submit_flag", result), is_correct

        else:
            return format_tool_result("error", f"Unknown tool: {name}"), False

    async def _run_challenge_loop(
        self,
        server: ServerManager,
        user: DojoUser,
        data_item: dict,
        client: PwnCollegeClient,
    ) -> tuple[bool, list[dict]]:
        """Multi-turn loop with persistent SSH and tool calling."""
        messages = list(data_item["initial_messages"])
        ssh_session = PersistentSSHSession(
            self.ssh_host, self.ssh_port, self.ssh_timeout
        )

        try:
            await ssh_session.connect(user)
        except Exception as e:
            # SSH connection failed - this usually means the dojo's SSH routing
            # isn't configured properly. Return early with error info.
            error_msg = f"SSH connection failed: {e}"
            messages.append({"role": "system", "content": error_msg})
            return False, messages

        try:
            for _ in range(self.max_turns):
                # 1. Get model response
                response = await server.chat_completion(
                    messages=messages,
                    max_tokens=self.max_tokens,
                    temperature=0.7,
                )
                assistant_content = response.choices[0].message.content or ""
                messages.append({"role": "assistant", "content": assistant_content})

                # 2. Parse tool calls
                tool_calls = parse_tool_calls(assistant_content)
                if tool_calls is None:
                    # No valid tool calls
                    # Check if model found a flag but didn't use submit_flag
                    if "pwn.college{" in assistant_content:
                        # Try to extract and submit the flag
                        import re

                        flag_match = re.search(
                            r"pwn\.college\{[^}]+\}", assistant_content
                        )
                        if flag_match:
                            flag = flag_match.group(0)
                            await client.login(user.username, user.password)
                            result, is_correct = await submit_flag(
                                client,
                                data_item["dojo_id"],
                                data_item["module_id"],
                                data_item["challenge_id"],
                                flag,
                            )
                            await client.logout()
                            messages.append(
                                {
                                    "role": "user",
                                    "content": f"Auto-submitted flag: {result}",
                                }
                            )
                            if is_correct:
                                return True, messages
                    continue

                # 3. Execute each tool call (usually just one per turn)
                tool_results = []
                for tc in tool_calls:
                    result, solved = await self._execute_tool(
                        ssh_session, user, data_item, tc, client
                    )
                    tool_results.append(result)
                    if solved:
                        messages.append(
                            {"role": "user", "content": "\n\n".join(tool_results)}
                        )
                        return True, messages

                # 4. Add tool results to messages
                messages.append({"role": "user", "content": "\n\n".join(tool_results)})

        finally:
            await ssh_session.close()

        return False, messages

    async def run_item(
        self, server: ServerManager, data_item: dict
    ) -> tuple[dict, list]:
        """Evaluate model on a single challenge with tool use."""
        challenge_id = f"{data_item['dojo_id']}/{data_item['module_id']}/{data_item['challenge_id']}"

        # These are guaranteed non-None when called from __call__
        assert self.pool is not None

        # Create a separate client for this challenge to avoid session conflicts
        client = PwnCollegeClient(self.base_url)

        solved = False
        messages = list(data_item["initial_messages"])

        try:
            async with self.pool.acquire(challenge_id) as user:
                # Login and start challenge
                await client.login(user.username, user.password)
                await client.start_challenge(
                    dojo=data_item["dojo_id"],
                    module=data_item["module_id"],
                    challenge=data_item["challenge_id"],
                    practice=False,
                )

                # Set SSH key for this session (may already be set)
                try:
                    await client.set_ssh_key(user.ssh_pubkey)
                except Exception:
                    pass  # SSH key might already be set
                await client.logout()

                # Wait for container to be ready
                # Note: SSH routing to containers depends on proper dojo configuration.
                # If SSH fails with "No active challenge session", the server's
                # /opt/sshd/auth.py may need configuration to route SSH keys to containers.
                await asyncio.sleep(5)

                # Run challenge loop (pass client for submit_flag)
                try:
                    solved, messages = await self._run_challenge_loop(
                        server, user, data_item, client
                    )
                except (BrokenPipeError, ConnectionError, OSError) as e:
                    messages.append({"role": "system", "content": f"SSH error: {e}"})
                    solved = False
                except Exception as e:
                    # Catch context length and other API errors
                    error_msg = str(e)
                    if (
                        "context_length_exceeded" in error_msg
                        or "too many tokens" in error_msg.lower()
                    ):
                        messages.append(
                            {
                                "role": "system",
                                "content": "Context length exceeded - challenge aborted",
                            }
                        )
                    else:
                        messages.append(
                            {"role": "system", "content": f"Error: {error_msg[:200]}"}
                        )
                    solved = False

                # Stop challenge container
                try:
                    await client.login(user.username, user.password)
                    await client.stop_challenge()
                    await client.logout()
                except Exception:
                    pass  # Best effort cleanup
        finally:
            await client.close()

        # Build metrics
        metrics = {
            "accuracy": 1.0 if solved else 0.0,
        }

        # Build sample for logging (as a single-item list to match EvalBase interface)
        sample = {
            "challenge_id": challenge_id,
            "challenge_name": data_item["challenge_name"],
            "dojo": data_item["dojo_name"],
            "module": data_item["module_name"],
            "difficulty": data_item["difficulty"],
            "category": data_item["category"],
            "solved": solved,
            "num_turns": len([m for m in messages if m["role"] == "assistant"]),
            "messages": messages,
        }

        return metrics, sample

    async def __call__(self, server_manager: ServerManager):
        """Initialize pool, run eval with limited concurrency, cleanup."""
        from tqdm.asyncio import tqdm_asyncio

        self.client = PwnCollegeClient(self.base_url)
        self.pool = UserPool(num_users=self.num_users)

        # Semaphore limits concurrent challenges to num_users
        semaphore = asyncio.Semaphore(self.num_users)

        async def run_with_semaphore(item):
            async with semaphore:
                try:
                    return await self.run_item(server_manager, item)
                except Exception as e:
                    # Return failed result instead of raising
                    dojo = item.get("dojo_id", "?")
                    module = item.get("module_id", "?")
                    chall = item.get("challenge_id", "?")
                    challenge_id = f"{dojo}/{module}/{chall}"
                    print(f"Challenge {challenge_id} failed: {e}")
                    return (
                        {"accuracy": 0.0},
                        {
                            "challenge_id": challenge_id,
                            "solved": False,
                            "error": str(e)[:200],
                            "messages": [],
                        },
                    )

        try:
            print(f"Initializing user pool with {self.num_users} users...")
            await self.pool.initialize(self.client)
            print(
                f"User pool initialized. Running evaluation on {len(self.data)} challenges..."
            )

            # Run with limited concurrency (exceptions caught in run_with_semaphore)
            task_coros = [run_with_semaphore(item) for item in self.data]
            task_results = await tqdm_asyncio.gather(*task_coros)

            # Aggregate results
            all_metrics = {}
            all_samples = []
            for metrics, sample in task_results:
                for k, v in metrics.items():
                    if k not in all_metrics:
                        all_metrics[k] = []
                    all_metrics[k].append(v)
                all_samples.append(sample)

            # Average metrics
            avg_metrics = {k: sum(v) / len(v) for k, v in all_metrics.items()}

            # Save samples if eval_dir specified
            if self.eval_dir:
                import json
                from datetime import datetime
                from pathlib import Path

                # Create timestamped subdirectory to avoid overwriting
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                eval_path = Path(self.eval_dir) / timestamp
                eval_path.mkdir(parents=True, exist_ok=True)

                samples_file = eval_path / "samples.jsonl"
                with open(samples_file, "w") as f:
                    for sample in all_samples:
                        f.write(json.dumps(sample) + "\n")

                with open(eval_path / "metrics.json", "w") as f:
                    json.dump(avg_metrics, f, indent=2)

                # Generate HTML viewer
                try:
                    from rollout_viewer import generate_html

                    generate_html(str(samples_file))
                    print(f"Generated HTML viewer: {eval_path / 'samples.html'}")
                except ImportError:
                    pass  # Viewer not available

                print(f"Saved {len(all_samples)} samples to {eval_path}")

            return avg_metrics

        finally:
            await self.pool.shutdown()
            await self.client.close()


async def main():
    """Run the PwnCollege evaluation."""
    import os

    parser = argparse.ArgumentParser(description="PwnCollege CTF Evaluation")
    parser.add_argument(
        "--server-url",
        type=str,
        default="https://api.openai.com/v1",
        help="OpenAI-compatible server URL",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="gpt-4o",
        help="Model name to use",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key (defaults to OPENAI_API_KEY env var)",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default="https://zephyr.tail119aa7.ts.net/",
        help="Dojo API base URL",
    )
    parser.add_argument(
        "--ssh-host",
        type=str,
        default="zephyr.tail119aa7.ts.net",
        help="SSH host for challenge containers",
    )
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=2222,
        help="SSH port for challenge containers",
    )
    parser.add_argument(
        "--max-eval-items",
        type=int,
        default=-1,
        help="Maximum number of challenges to evaluate (-1 for all)",
    )
    parser.add_argument(
        "--difficulty",
        type=int,
        default=-1,
        help="Filter by difficulty level (-1 for all)",
    )
    parser.add_argument(
        "--dojo",
        type=str,
        default=None,
        help="Filter by dojo ID",
    )
    parser.add_argument(
        "--module",
        type=str,
        default=None,
        help="Filter by module ID",
    )
    parser.add_argument(
        "--challenge",
        type=str,
        default=None,
        help="Filter by challenge ID",
    )
    parser.add_argument(
        "--num-users",
        type=int,
        default=4,
        help="Number of parallel users in pool",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=20,
        help="Maximum turns per challenge",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=4096,
        help="Maximum tokens per response",
    )
    parser.add_argument(
        "--eval-dir",
        type=str,
        default=None,
        help="Directory to save evaluation results (creates timestamped subdirectory)",
    )

    args = parser.parse_args()

    # Create evaluation environment
    eval_env = PwnCollegeEval(
        base_url=args.base_url,
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port,
        max_turns=args.max_turns,
        max_tokens=args.max_tokens,
        max_eval_items=args.max_eval_items,
        difficulty_filter=args.difficulty,
        dojo_filter=args.dojo,
        module_filter=args.module,
        challenge_filter=args.challenge,
        num_users=args.num_users,
        eval_dir=args.eval_dir,
    )

    # Get API key from args or environment
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: API key required. Set OPENAI_API_KEY or use --api-key")
        return

    # Create server manager
    server_manager = ServerManager(
        configs=[
            APIServerConfig(
                api_key=api_key,
                base_url=args.server_url,
                model_name=args.model_name,
                health_check=False,
            ),
        ]
    )

    return await eval_env(server_manager)


if __name__ == "__main__":
    asyncio.run(main())
