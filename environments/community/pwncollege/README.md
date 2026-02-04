## About This Environment

This environment evaluates and trains models on pwn.college's CTF (Capture The Flag) cybersecurity challenges. Similar to [SWE-bench](https://www.swebench.com/) for coding, pwn.college provides a standardized benchmark for security/hacking capabilities.

Models interact with challenge containers via persistent SSH sessions, using tools to execute commands, read/write files, and submit flags. Each challenge has a verifiable flag that confirms successful completion.


## Directory Structure

```
pwncollege/
├── eval/
│   └── pwncollege_eval.py    # Evaluation environment
├── train/
│   └── pwncollege_train.py   # Training environment (SFT/RL data generation)
├── sdk.py                    # Dojo API client
├── ssh_session.py            # Persistent SSH session manager
├── tools.py                  # Agent tools (bash, read_file, etc.)
├── tool_utils.py             # Tool parsing utilities
├── prompts.py                # System/user prompt templates
└── keys/                     # Auto-generated SSH keys for user pool
```

## Prerequisites

### 1. Dojo Server

You need a pwn.college dojo server. Options:

- Use the public [pwn.college](https://pwn.college) (limited API access)
- Self-host: https://github.com/pwncollege/dojo

### 2. Environment Variables

```bash
export OPENAI_API_KEY="sk-..."  # For OpenAI models
# Or configure local server via CLI flags
```

### 3. Dependencies

```bash
pip install httpx asyncssh
```

## Evaluation

Evaluate model performance on CTF challenges.

```bash
cd environments/community/pwncollege/eval

# Run on a specific dojo/module
uv run python pwncollege_eval.py \
    --dojo linux-luminarium \
    --module hello \
    --num-users 4 \
    --max-turns 20 \
    --eval-dir ./eval_results

# With custom model
uv run python pwncollege_eval.py \
    --server-url https://api.openai.com/v1 \
    --model-name gpt-4o \
    --api-key "sk-..." \
    --dojo linux-luminarium \
    --max-eval-items 10

# Filter by difficulty (0=easy, 4=hard)
uv run python pwncollege_eval.py \
    --difficulty 0 \
    --max-eval-items 20
```

### Eval CLI Options

| Flag               | Default                             | Description                       |
| ------------------ | ----------------------------------- | --------------------------------- |
| `--server-url`     | `https://api.openai.com/v1`         | OpenAI-compatible API URL         |
| `--model-name`     | `gpt-4o`                            | Model to evaluate                 |
| `--api-key`        | `$OPENAI_API_KEY`                   | API key                           |
| `--base-url`       | `https://zephyr.tail119aa7.ts.net/` | Dojo server URL                   |
| `--ssh-host`       | `zephyr.tail119aa7.ts.net`          | SSH host for containers           |
| `--ssh-port`       | `2222`                              | SSH port                          |
| `--dojo`           | None                                | Filter by dojo ID                 |
| `--module`         | None                                | Filter by module ID               |
| `--challenge`      | None                                | Filter by challenge ID            |
| `--difficulty`     | `-1`                                | Filter by difficulty (-1 = all)   |
| `--max-eval-items` | `-1`                                | Max challenges to eval (-1 = all) |
| `--num-users`      | `4`                                 | Parallel SSH containers           |
| `--max-turns`      | `20`                                | Max turns per challenge           |
| `--max-tokens`     | `4096`                              | Max tokens per response           |
| `--eval-dir`       | None                                | Save results to directory         |

### Output

Results are saved to `--eval-dir` with:

- `samples.jsonl` - Per-challenge results with full message history
- `metrics.json` - Aggregate metrics (accuracy, etc.)
- `samples.html` - Interactive viewer

## Training (SFT Data Generation)

Generate SFT training data from model rollouts.

```bash
cd environments/community/pwncollege/train

# Generate SFT data with GPT-4o
uv run python -m environments.community.pwncollege.train.pwncollege_train process \
    --env.data_path_to_save_groups sft_data.jsonl \
    --env.total_steps 100 \
    --env.group_size 1 \
    --env.dojo_filter linux-luminarium \
    --env.module_filter hello \
    --env.num_users 4 \
    --env.use_wandb false \
    --openai.model_name gpt-4o \
    --openai.base_url https://api.openai.com/v1 \
    --openai.api_key "sk-..."

# With local vLLM/SGLang server
uv run python -m environments.community.pwncollege.train.pwncollege_train process \
    --env.data_path_to_save_groups sft_data.jsonl \
    --env.total_steps 50 \
    --env.dojo_filter linux-luminarium \
    --openai.base_url http://localhost:9001/v1 \
    --openai.model_name Qwen/Qwen2.5-7B-Instruct
```

### Train CLI Options

| Flag                             | Default | Description                        |
| -------------------------------- | ------- | ---------------------------------- |
| `--env.data_path_to_save_groups` | None    | Output JSONL path                  |
| `--env.total_steps`              | `1000`  | Number of challenges to run        |
| `--env.group_size`               | `1`     | Rollouts per challenge (keep at 1) |
| `--env.dojo_filter`              | None    | Filter by dojo ID                  |
| `--env.module_filter`            | None    | Filter by module ID                |
| `--env.challenge_filter`         | None    | Filter by challenge ID             |
| `--env.difficulty_filter`        | `-1`    | Filter by difficulty               |
| `--env.num_users`                | `4`     | Parallel SSH containers            |
| `--env.max_turns`                | `20`    | Max turns per challenge            |
| `--env.use_wandb`                | `true`  | Enable W&B logging                 |
| `--openai.model_name`            | Model   | Model name                         |
| `--openai.base_url`              | URL     | Server URL                         |
| `--openai.api_key`               | Key     | API key                            |

### Output Format

The JSONL output contains `ScoredDataGroup` entries:

```json
{
  "tokens": [[...]],
  "masks": [[...]],
  "scores": [1.0],
  "messages": [[{"role": "system", ...}, {"role": "user", ...}, ...]],
  "inference_logprobs": [[...]],
  "group_overrides": {
    "challenge_id": "linux-luminarium/hello/hello",
    "challenge_name": "Intro to Commands",
    "solved": true
  }
}
```

- `tokens` - Tokenized conversation
- `masks` - `-100` for prompts/tools, token IDs for assistant responses (SFT training)
- `scores` - `1.0` if solved, `0.0` otherwise
- `messages` - Full conversation history

## Agent Tools

The model has access to these tools via XML tool calls:

| Tool          | Description                                         |
| ------------- | --------------------------------------------------- |
| `bash`        | Execute shell command (state persists across calls) |
| `read_file`   | Read file with line numbers                         |
| `write_file`  | Create/overwrite file                               |
| `edit_file`   | Replace string in file                              |
| `submit_flag` | Submit flag for verification                        |

### Tool Call Format

```xml
<tool_call>
{"name": "bash", "arguments": {"command": "ls -la /challenge"}}
</tool_call>
```

## Difficulty Tiers

| Dojo                     | Difficulty |
| ------------------------ | ---------- |
| `linux-luminarium`       | 0 (Easy)   |
| `computing-101`          | 0          |
| `playing-with-programs`  | 0          |
| `intro-to-cybersecurity` | 1          |
| `program-security`       | 2          |
| `system-security`        | 3          |
| `software-exploitation`  | 4 (Hard)   |

## SDK Reference

For programmatic dojo interaction:

```python
from environments.community.pwncollege import PwnCollegeClient, UserPool

async with PwnCollegeClient("https://dojo.example.com") as client:
    await client.login("user", "password")
    await client.start_challenge("linux-luminarium", "hello", "hello")
    # ... SSH and solve ...
    result = await client.submit_flag("linux-luminarium", "hello", "hello", "pwn.college{...}")
    await client.stop_challenge()
```

See `sdk.py` for full API.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Atropos Trainer                        │
│                    (GRPO, PPO, etc.)                        │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ trajectories (tokens, masks, scores)
                              │
┌─────────────────────────────────────────────────────────────┐
│                   PwnCollegeTrain (BaseEnv)                 │
│  - Manages user pool (parallel SSH sessions)                │
│  - Runs multi-turn challenge loops                          │
│  - Tokenizes conversations for SFT                          │
└─────────────────────────────────────────────────────────────┘
         │                              │
         │ chat_completion              │ tool execution
         ▼                              ▼
┌─────────────────┐           ┌─────────────────────┐
│   LLM Server    │           │   Dojo Server       │
│ (OpenAI/vLLM)   │           │ (pwn.college API)   │
└─────────────────┘           └─────────────────────┘
                                        │
                                        │ SSH
                                        ▼
                              ┌─────────────────────┐
                              │ Challenge Container │
                              │  (bash, files, etc) │
                              └─────────────────────┘
```

## Contributing

This is a community environment. Contributions welcome!

See the [community environments guide](../README.md) for contribution guidelines.
