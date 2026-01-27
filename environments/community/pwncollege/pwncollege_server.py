"""
pwn.college Evaluation Environment for Atropos

This environment evaluates models on pwn.college's CTF (Capture The Flag) cybersecurity challenges.

Each module houses several challenge containers, flag checker and problem statements.

The base environment currently expects the Dojo (and within it, the modules) to be hosted:
https://github.com/alt-glitch/dojo/blob/master/docs/deployment.md

Read the README.md for more hosting information.

The model is provided tools to interact with each challenge container, similar to terminal
bench as well as submit flags, and optionally restart the container.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from sdk import DojoUser, PwnCollegeClient, PwnCollegeSyncClient, UserPool
from tools import TOOLS

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


class PwnCollegeEval(EvalBase):
    """Evaluates models on pwn.college CTF challenges."""

    def __init__(
        self,
        base_url: str = "https://zephyr.tail119aa7.ts.net/",
        max_turns: int = 20,
        max_tokens: int = 4096,
        max_eval_items: int = -1,
        difficulty_filter: int = -1,
        num_users: int = 4,
        ssh_timeout: float = 30.0,
        **kwargs,
    ):
        self.base_url = base_url
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.max_eval_items = max_eval_items
        self.difficulty_filter = difficulty_filter
        self.num_users = num_users
        self.ssh_timeout = ssh_timeout
        self.pool: UserPool | None = None
        self.client: PwnCollegeClient | None = None

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

                        # Build initial messages for this challenge
                        user_prompt = USER_PROMPT_TEMPLATE.format(
                            module_name=module_name,
                            challenge_name=challenge_name,
                            challenge_description=challenge_description
                            or "No description provided.",
                        )
                        initial_messages = [
                            {"role": "system", "content": SYSTEM_PROMPT},
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

    async def _ssh_command(self, user: DojoUser, command: str) -> str:
        """Execute a command via SSH on the challenge container."""
        # TODO: Implement SSH command execution
        ...

    async def _execute_tool(
        self,
        user: DojoUser,
        data_item: dict,
        tool_name: str,
        tool_args: dict,
    ) -> tuple[str, bool]:
        """Execute a tool call and return (result, is_flag_correct)."""
        if tool_name == "ssh_command":
            command = tool_args.get("command", "")
            result = await self._ssh_command(user, command)
            return result, False

        elif tool_name == "submit_flag":
            flag = tool_args.get("flag", "")
            assert self.client is not None
            try:
                # Login as user to submit flag
                await self.client.login(user.username, user.password)
                response = await self.client.submit_flag(
                    dojo=data_item["dojo_id"],
                    module=data_item["module_id"],
                    challenge=data_item["challenge_id"],
                    flag=flag,
                )
                await self.client.logout()

                is_correct = response.get("success", False)
                if is_correct:
                    return "Flag accepted! Challenge solved.", True
                else:
                    message = response.get("message", "Flag incorrect")
                    return f"Flag rejected: {message}", False
            except Exception as e:
                return f"Error submitting flag: {e}", False

        else:
            return f"Unknown tool: {tool_name}", False

    async def _run_challenge_loop(
        self,
        server: ServerManager,
        user: DojoUser,
        data_item: dict,
    ) -> tuple[bool, list[dict]]:
        """Run multi-turn challenge loop with tool use. Returns (solved, messages)."""
        # Copy initial messages to avoid mutating the original
        messages = list(data_item["initial_messages"])

        solved = False
        turn = 0

        while turn < self.max_turns and not solved:
            turn += 1

            # Get model response
            response = await server.chat_completion(
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                max_tokens=self.max_tokens,
                temperature=0.7,
            )

            choice = response.choices[0]
            assistant_message = choice.message

            # Build assistant message dict
            assistant_dict: dict[str, Any] = {"role": "assistant"}
            if assistant_message.content:
                assistant_dict["content"] = assistant_message.content
            if assistant_message.tool_calls:
                assistant_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in assistant_message.tool_calls
                ]

            messages.append(assistant_dict)

            # Check for tool calls
            if not assistant_message.tool_calls:
                # No tool calls - check if model is done
                if choice.finish_reason == "stop":
                    break
                continue

            # Execute each tool call
            for tool_call in assistant_message.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                result, is_correct = await self._execute_tool(
                    user, data_item, tool_name, tool_args
                )

                # Add tool response
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result,
                    }
                )

                if is_correct:
                    solved = True
                    break

        return solved, messages

    async def run_item(
        self, server: ServerManager, data_item: dict
    ) -> tuple[dict, list]:
        """Evaluate model on a single challenge with tool use."""
        challenge_id = f"{data_item['dojo_id']}/{data_item['module_id']}/{data_item['challenge_id']}"

        # These are guaranteed non-None when called from __call__
        assert self.pool is not None
        assert self.client is not None

        async with self.pool.acquire(challenge_id) as user:
            # Login and start challenge
            await self.client.login(user.username, user.password)
            await self.client.start_challenge(
                dojo=data_item["dojo_id"],
                module=data_item["module_id"],
                challenge=data_item["challenge_id"],
                practice=False,
            )

            # Set SSH key for this session
            await self.client.set_ssh_key(user.ssh_pubkey)
            await self.client.logout()

            # Run challenge loop
            solved, messages = await self._run_challenge_loop(server, user, data_item)

            # Stop challenge container
            await self.client.login(user.username, user.password)
            await self.client.stop_challenge()
            await self.client.logout()

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
        """Initialize pool, run eval, cleanup."""
        self.client = PwnCollegeClient(self.base_url)
        self.pool = UserPool(num_users=self.num_users)

        try:
            print(f"Initializing user pool with {self.num_users} users...")
            await self.pool.initialize(self.client)
            print(
                f"User pool initialized. Running evaluation on {len(self.data)} challenges..."
            )
            return await super().__call__(server_manager)
        finally:
            await self.pool.shutdown()
            await self.client.close()


async def main():
    """Run the PwnCollege evaluation."""

    parser = argparse.ArgumentParser(description="PwnCollege CTF Evaluation")
    parser.add_argument(
        "--server-url",
        type=str,
        default="http://localhost:8000/v1",
        help="OpenAI-compatible server URL",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default=None,
        help="Model name to use",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default="https://zephyr.tail119aa7.ts.net/",
        help="Dojo API base URL",
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
        help="Directory to save evaluation results",
    )

    args = parser.parse_args()

    # Create evaluation environment
    eval_env = PwnCollegeEval(
        base_url=args.base_url,
        max_turns=args.max_turns,
        max_tokens=args.max_tokens,
        max_eval_items=args.max_eval_items,
        difficulty_filter=args.difficulty,
        num_users=args.num_users,
        eval_dir=args.eval_dir,
    )

    # Create server manager
    server_manager = ServerManager(
        configs=[
            APIServerConfig(
                api_key="x",
                base_url=args.server_url,
                model_name=args.model_name,
                health_check=False,
            ),
        ]
    )

    return await eval_env(server_manager)


if __name__ == "__main__":
    asyncio.run(main())
