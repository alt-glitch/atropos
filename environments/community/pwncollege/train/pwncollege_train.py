"""
pwn.college Training Environment for Atropos

This BaseEnv generates SFT/RL training data by having models solve pwn.college CTF challenges.
Trajectories are collected with token-level tracking via ManagedServer.

Usage:
    # Generate SFT data
    python pwncollege_train.py process \
        --env.data_path_to_save_groups sft_data.jsonl \
        --env.total_steps 100 \
        --env.group_size 1 \
        --env.dojo_filter "linux-luminarium" \
        --openai.base_url https://api.openai.com/v1 \
        --openai.model_name gpt-4o
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, List, Optional, Tuple, Union

from pydantic import Field

from atroposlib.envs.base import (
    APIServerConfig,
    BaseEnv,
    BaseEnvConfig,
    Item,
    ScoredDataGroup,
)

from ..prompts import SUBMIT_FLAG_TOOL, SYSTEM_PROMPT_TEMPLATE, USER_PROMPT_TEMPLATE
from ..sdk import DojoUser, PwnCollegeClient, PwnCollegeSyncClient, UserPool
from ..ssh_session import PersistentSSHSession
from ..tool_utils import (
    execute_tool,
    function_to_tool_schema,
    parse_tool_calls,
)
from ..tools import AGENT_TOOLS, submit_flag

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


class PwnCollegeTrainConfig(BaseEnvConfig):
    """Configuration for PwnCollege training environment."""

    # Dojo connection settings
    base_url: str = Field(
        default="https://zephyr.tail119aa7.ts.net/",
        description="Dojo API base URL",
    )
    ssh_host: str = Field(
        default="zephyr.tail119aa7.ts.net",
        description="SSH host for challenge containers",
    )
    ssh_port: int = Field(
        default=2222,
        description="SSH port for challenge containers",
    )
    ssh_timeout: float = Field(
        default=30.0,
        description="SSH command timeout in seconds",
    )

    # Challenge settings
    max_turns: int = Field(
        default=20,
        description="Maximum turns per challenge",
    )
    num_users: int = Field(
        default=4,
        description="Number of parallel users in pool (limits concurrency)",
    )

    # Challenge filters
    difficulty_filter: int = Field(
        default=-1,
        description="Filter by difficulty level (-1 for all)",
    )
    dojo_filter: Optional[str] = Field(
        default=None,
        description="Filter by dojo ID (e.g., 'linux-luminarium')",
    )
    module_filter: Optional[str] = Field(
        default=None,
        description="Filter by module ID (e.g., 'hello')",
    )
    challenge_filter: Optional[str] = Field(
        default=None,
        description="Filter by challenge ID",
    )


class PwnCollegeTrain(BaseEnv):
    """Training environment for pwn.college CTF challenges.

    Generates SFT/RL trajectories with token-level tracking using ManagedServer.
    Each challenge runs in an isolated SSH container with persistent state.
    """

    name = "pwncollege"
    env_config_cls = PwnCollegeTrainConfig

    def __init__(
        self,
        config: PwnCollegeTrainConfig,
        server_configs: List[APIServerConfig],
        slurm: bool = False,
        testing: bool = False,
    ):
        super().__init__(config, server_configs, slurm, testing)
        self.config: PwnCollegeTrainConfig = config  # type narrowing

        # Pre-build tools block for system prompt
        self.tools_block = _build_tools_block()

        # Will be initialized in setup()
        self.train: list = []
        self.pool: Optional[UserPool] = None
        self.iter = 0

        # Track metrics
        self.solve_rate_buffer: list[float] = []

    @classmethod
    def config_init(cls) -> Tuple[PwnCollegeTrainConfig, List[APIServerConfig]]:
        """Initialize default configuration."""
        env_config = PwnCollegeTrainConfig(
            tokenizer_name="Qwen/Qwen2.5-7B-Instruct",
            group_size=1,  # One trajectory per challenge (SSH container limited)
            use_wandb=True,
            max_num_workers_per_node=4,
            rollout_server_url="http://localhost:8000",
            total_steps=1000,
            steps_per_eval=50,
            max_token_length=16384,
            inference_weight=1.0,
            wandb_name="pwncollege",
            include_messages=True,
        )
        server_configs = [
            APIServerConfig(
                model_name="Qwen/Qwen2.5-7B-Instruct",
                base_url="http://localhost:9001/v1",
                api_key="x",
                num_max_requests_at_once=4,
            ),
        ]
        return env_config, server_configs

    def _load_challenges(self) -> list[dict[str, Any]]:
        """Fetch all challenges from the dojo API."""
        rows: list[dict[str, Any]] = []

        with PwnCollegeSyncClient(self.config.base_url) as client:
            dojos_response = client.list_dojos()
            dojos = dojos_response.get("dojos", [])

            print(f"Found {len(dojos)} dojos")

            for dojo in dojos:
                dojo_id = dojo.get("id", "")
                dojo_name = dojo.get("name", "")
                dojo_description = dojo.get("description", "")
                difficulty = DOJO_DIFFICULTY.get(dojo_id, -1)

                # Apply dojo filter
                if self.config.dojo_filter and dojo_id != self.config.dojo_filter:
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
                    if (
                        self.config.module_filter
                        and module_id != self.config.module_filter
                    ):
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
                            self.config.challenge_filter
                            and challenge_id != self.config.challenge_filter
                        ):
                            continue

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
                            "initial_messages": initial_messages,
                        }
                        rows.append(row)

        print(f"Total challenges loaded: {len(rows)}")

        # Apply difficulty filter
        if self.config.difficulty_filter >= 0:
            rows = [r for r in rows if r["difficulty"] == self.config.difficulty_filter]
            print(f"After difficulty filter: {len(rows)} challenges")

        return rows

    async def setup(self):
        """Load challenges and initialize user pool."""
        self.train = self._load_challenges()

        if not self.train:
            raise RuntimeError("No challenges found matching filters")

        # Initialize user pool with a temporary client
        async with PwnCollegeClient(self.config.base_url) as client:
            self.pool = UserPool(num_users=self.config.num_users)
            print(f"Initializing user pool with {self.config.num_users} users...")
            await self.pool.initialize(client)
            print("User pool initialized")

    async def get_next_item(self) -> Item:
        """Return next challenge item."""
        item = self.train[self.iter % len(self.train)]
        self.iter += 1
        return item

    async def _run_challenge_loop(
        self,
        ssh_session: PersistentSSHSession,
        user: DojoUser,
        data_item: dict,
        client: PwnCollegeClient,
    ) -> Tuple[bool, list[dict]]:
        """Run multi-turn challenge loop.

        Args:
            ssh_session: Persistent SSH session for tool execution.
            user: DojoUser for this challenge.
            data_item: Challenge data.
            client: PwnCollegeClient for flag submission.

        Returns:
            Tuple of (solved, messages).
        """
        messages = list(data_item["initial_messages"])

        for _ in range(self.config.max_turns):
            # Get model response
            response = await self.server.chat_completion(
                messages=messages,
                max_tokens=4096,
                temperature=0.7,
            )
            assistant_content = response.choices[0].message.content or ""
            messages.append({"role": "assistant", "content": assistant_content})

            # Parse tool calls
            tool_calls = parse_tool_calls(assistant_content)
            if tool_calls is None:
                # No valid tool calls - check for flag in response
                if "pwn.college{" in assistant_content:
                    flag_match = re.search(r"pwn\.college\{[^}]+\}", assistant_content)
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

            # Execute each tool call
            tool_results = []
            for tc in tool_calls:
                # Login for flag submission if needed
                if tc.get("name") == "submit_flag":
                    await client.login(user.username, user.password)

                result, solved = await execute_tool(ssh_session, client, data_item, tc)

                if tc.get("name") == "submit_flag":
                    await client.logout()

                tool_results.append(result)
                if solved:
                    messages.append(
                        {"role": "user", "content": "\n\n".join(tool_results)}
                    )
                    return True, messages

            # Add tool results to messages
            messages.append({"role": "user", "content": "\n\n".join(tool_results)})

        return False, messages

    def _tokenize_messages(self, messages: list[dict]) -> Tuple[list[int], list[int]]:
        """Tokenize messages and create masks for SFT.

        For SFT, we mask (set to -100) everything except assistant responses.

        Returns:
            Tuple of (tokens, masks).
        """
        # Use chat template to get full token sequence
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )
        tokens = self.tokenizer.encode(text, add_special_tokens=False)

        # For SFT: create masks where assistant content is unmasked
        # Simple approach: tokenize with and without last assistant turn to find boundaries
        masks = [-100] * len(tokens)  # Start with all masked

        # Find assistant message boundaries by tokenizing incrementally
        current_pos = 0
        for i, msg in enumerate(messages):
            # Tokenize up to and including this message
            partial_text = self.tokenizer.apply_chat_template(
                messages[: i + 1],
                tokenize=False,
                add_generation_prompt=False,
            )
            partial_tokens = self.tokenizer.encode(
                partial_text, add_special_tokens=False
            )
            end_pos = len(partial_tokens)

            # If this is an assistant message, unmask it
            if msg.get("role") == "assistant":
                for j in range(current_pos, min(end_pos, len(masks))):
                    masks[j] = tokens[j] if j < len(tokens) else -100

            current_pos = end_pos

        return tokens, masks

    async def collect_trajectories(
        self, item: Item
    ) -> Tuple[
        Union[Optional[ScoredDataGroup], List[Optional[ScoredDataGroup]]], List[Item]
    ]:
        """Collect trajectory for a single challenge.

        Since each challenge requires an exclusive SSH container, group_size should be 1.
        Concurrency is controlled by the user pool size.
        """
        assert self.pool is not None, "Pool not initialized"

        challenge_id = f"{item['dojo_id']}/{item['module_id']}/{item['challenge_id']}"

        # Create client for this challenge
        client = PwnCollegeClient(self.config.base_url)

        solved = False
        messages: list[dict] = []

        try:
            async with self.pool.acquire(challenge_id) as user:
                # Start challenge container
                await client.login(user.username, user.password)
                await client.start_challenge(
                    dojo=item["dojo_id"],
                    module=item["module_id"],
                    challenge=item["challenge_id"],
                    practice=False,
                )
                try:
                    await client.set_ssh_key(user.ssh_pubkey)
                except Exception:
                    pass  # Key might already be set
                await client.logout()

                # Wait for container
                await asyncio.sleep(5)

                # Create SSH session
                ssh_session = PersistentSSHSession(
                    self.config.ssh_host,
                    self.config.ssh_port,
                    self.config.ssh_timeout,
                )

                try:
                    await ssh_session.connect(user)
                    solved, messages = await self._run_challenge_loop(
                        ssh_session, user, item, client
                    )
                except (BrokenPipeError, ConnectionError, OSError) as e:
                    print(f"SSH error for {challenge_id}: {e}")
                    messages = list(item["initial_messages"])
                    messages.append({"role": "system", "content": f"SSH error: {e}"})
                except Exception as e:
                    print(f"Error in challenge {challenge_id}: {e}")
                    messages = list(item["initial_messages"])
                    messages.append(
                        {"role": "system", "content": f"Error: {str(e)[:200]}"}
                    )
                finally:
                    await ssh_session.close()

                # Stop challenge container
                try:
                    await client.login(user.username, user.password)
                    await client.stop_challenge()
                    await client.logout()
                except Exception:
                    pass

        finally:
            await client.close()

        # Track solve rate
        self.solve_rate_buffer.append(1.0 if solved else 0.0)

        # Build ScoredDataGroup
        score = 1.0 if solved else 0.0

        # Tokenize messages for SFT format
        tokens, masks = self._tokenize_messages(messages)

        # Create logprobs placeholder (1.0 for masked, 0.0 for unmasked)
        logprobs = [1.0 if m == -100 else 0.0 for m in masks]

        # Skip if no valid tokens
        if not tokens:
            return None, []

        scored_data: ScoredDataGroup = {
            "tokens": [tokens],
            "masks": [masks],
            "scores": [score],
            "inference_logprobs": [logprobs],
            "messages": [messages] if self.config.include_messages else None,
            "advantages": None,
            "ref_logprobs": None,
            "generation_params": None,
            "group_overrides": {
                "challenge_id": challenge_id,
                "challenge_name": item["challenge_name"],
                "dojo": item["dojo_name"],
                "module": item["module_name"],
                "difficulty": item["difficulty"],
                "solved": solved,
            },
            "overrides": None,
            "images": None,
        }

        return scored_data, []

    async def evaluate(self, *args, **kwargs):
        """Run evaluation on a subset of challenges."""
        # Calculate solve rate from buffer
        if self.solve_rate_buffer:
            solve_rate = sum(self.solve_rate_buffer) / len(self.solve_rate_buffer)
            print(
                f"Solve rate: {solve_rate:.2%} ({len(self.solve_rate_buffer)} challenges)"
            )
            self.solve_rate_buffer = []

    async def wandb_log(self, wandb_metrics: Optional[dict] = None):
        """Log metrics to wandb."""
        if wandb_metrics is None:
            wandb_metrics = {}

        # Add solve rate if available
        if self.solve_rate_buffer:
            wandb_metrics["train/solve_rate"] = sum(self.solve_rate_buffer) / len(
                self.solve_rate_buffer
            )

        await super().wandb_log(wandb_metrics)


if __name__ == "__main__":
    PwnCollegeTrain.cli()
