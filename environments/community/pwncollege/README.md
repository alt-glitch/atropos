# pwncollege SDK

Minimal SDK for programmatic interaction with a pwncollege dojo server.

## Installation

```bash
pip install httpx
```

## Usage

### Sync Client

```python
from sdk import PwnCollegeSyncClient

with PwnCollegeSyncClient("http://localhost:8000") as client:
    # Register a new user
    client.register("hacker", "hacker@example.com", "password123")

    # Or login to existing account
    client.login("hacker", "password123")

    # Set SSH key for container access
    with open("~/.ssh/id_ed25519.pub") as f:
        client.set_ssh_key(f.read())

    # List available dojos
    dojos = client.list_dojos()
    print(dojos["dojos"])

    # Start a challenge container
    client.start_challenge(
        dojo="welcome",
        module="intro",
        challenge="level1",
        practice=False,  # True for practice mode (privileged)
    )

    # SSH into the container and solve...
    # ssh -p 2222 hacker@localhost

    # Submit flag
    result = client.submit_flag(
        dojo="welcome",
        module="intro",
        challenge="level1",
        flag="pwn.college{...}",
    )

    # Stop container when done
    client.stop_challenge()
```

### Async Client

```python
import asyncio
from sdk import PwnCollegeClient

async def main():
    async with PwnCollegeClient("http://localhost:8000") as client:
        await client.login("hacker", "password123")

        # List modules in a dojo
        modules = await client.list_modules("welcome")
        for module in modules["modules"]:
            print(f"{module['id']}: {module['name']}")

        # Start challenge
        await client.start_challenge("welcome", "intro", "level1")

        # Get challenge description
        desc = await client.get_challenge_description("welcome", "intro", "level1")
        print(desc["description"])

asyncio.run(main())
```

## API Reference

| Method | Description |
|--------|-------------|
| `register(username, email, password)` | Create new user account |
| `login(username, password)` | Login and establish session |
| `logout()` | Clear session |
| `set_ssh_key(public_key)` | Set SSH public key |
| `delete_ssh_key(public_key)` | Remove SSH public key |
| `start_challenge(dojo, module, challenge, practice=False)` | Start/reset challenge container |
| `get_current_challenge()` | Get active challenge info |
| `stop_challenge()` | Stop challenge container |
| `submit_flag(dojo, module, challenge, flag)` | Submit flag for challenge |
| `list_dojos()` | List accessible dojos |
| `list_modules(dojo)` | List modules in a dojo |
| `get_challenge_description(dojo, module, challenge)` | Get challenge description |

## Notes

- Session cookies are automatically managed by httpx
- `start_challenge` removes any existing container before starting a new one
- Practice mode (`practice=True`) enables privileged container for debugging
