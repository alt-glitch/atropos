"""Minimal pwncollege SDK using httpx for programmatic interaction with a dojo server."""

import asyncio
import hashlib
import re
import subprocess
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx


def _extract_csrf_nonce(html: str) -> str | None:
    """Extract CSRF nonce from page HTML."""
    match = re.search(r"'csrfNonce': \"([^\"]+)\"", html)
    return match.group(1) if match else None


@dataclass
class DojoChallenge:
    dojo: str
    module: str
    challenge: str


class PwnCollegeClient:
    """Async client for interacting with pwncollege dojo API."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=True,
        )
        self._csrf_nonce: str | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def close(self):
        await self.client.aclose()

    async def _ensure_csrf(self) -> str:
        """Fetch CSRF nonce if not already cached."""
        if self._csrf_nonce is None:
            resp = await self.client.get("/")
            self._csrf_nonce = _extract_csrf_nonce(resp.text)
            if self._csrf_nonce is None:
                raise RuntimeError("Could not extract CSRF nonce from page")
        return self._csrf_nonce

    def _api_url(self, path: str) -> str:
        return f"/pwncollege_api/v1{path}"

    async def _post(self, path: str, json: dict | None = None) -> dict[str, Any]:
        csrf = await self._ensure_csrf()
        headers = {"CSRF-Token": csrf}
        data = dict(json or {})
        data["nonce"] = csrf
        resp = await self.client.post(self._api_url(path), json=data, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def _delete(self, path: str, json: dict | None = None) -> dict[str, Any]:
        csrf = await self._ensure_csrf()
        headers = {"CSRF-Token": csrf}
        data = dict(json or {}) if json else {}
        data["nonce"] = csrf
        resp = await self.client.request(
            "DELETE", self._api_url(path), json=data, headers=headers
        )
        resp.raise_for_status()
        return resp.json()

    async def _get(self, path: str) -> dict[str, Any]:
        resp = await self.client.get(self._api_url(path))
        resp.raise_for_status()
        return resp.json()

    # ── Auth ──────────────────────────────────────────────────────────────────

    async def register(
        self, username: str, email: str, password: str
    ) -> dict[str, Any]:
        """Register a new user account."""
        return await self._post(
            "/auth/register",
            json={"name": username, "email": email, "password": password},
        )

    async def login(self, username: str, password: str) -> dict[str, Any]:
        """Login and establish session."""
        return await self._post(
            "/auth/login",
            json={"name": username, "password": password},
        )

    async def logout(self) -> dict[str, Any]:
        """Logout and clear session."""
        return await self._post("/auth/logout")

    # ── SSH Key ───────────────────────────────────────────────────────────────

    async def set_ssh_key(self, public_key: str) -> dict[str, Any]:
        """Set SSH public key for the authenticated user."""
        return await self._post("/ssh_key", json={"ssh_key": public_key})

    async def delete_ssh_key(self, public_key: str) -> dict[str, Any]:
        """Delete SSH public key."""
        return await self._delete("/ssh_key", json={"ssh_key": public_key})

    # ── Docker/Container ──────────────────────────────────────────────────────

    async def start_challenge(
        self,
        dojo: str,
        module: str,
        challenge: str,
        practice: bool = False,
    ) -> dict[str, Any]:
        """Start a challenge container (also resets if one already exists)."""
        return await self._post(
            "/docker",
            json={
                "dojo": dojo,
                "module": module,
                "challenge": challenge,
                "practice": practice,
            },
        )

    async def get_current_challenge(self) -> dict[str, Any]:
        """Get info about the currently running challenge container."""
        return await self._get("/docker")

    async def stop_challenge(self) -> dict[str, Any]:
        """Stop the current challenge container."""
        return await self._delete("/docker")

    # ── Flag Submission ───────────────────────────────────────────────────────

    async def submit_flag(
        self, dojo: str, module: str, challenge: str, flag: str
    ) -> dict[str, Any]:
        """Submit a flag for a challenge."""
        resp = await self.client.post(
            self._api_url(f"/dojos/{dojo}/{module}/{challenge}/solve"),
            json={"submission": flag},
        )
        resp.raise_for_status()
        return resp.json()

    # ── Dojo Info ─────────────────────────────────────────────────────────────

    async def list_dojos(self) -> dict[str, Any]:
        """List all accessible dojos."""
        return await self._get("/dojos")

    async def list_modules(self, dojo: str) -> dict[str, Any]:
        """List modules in a dojo."""
        return await self._get(f"/dojos/{dojo}/modules")

    async def get_challenge_description(
        self, dojo: str, module: str, challenge: str
    ) -> dict[str, Any]:
        """Get the description of a challenge."""
        return await self._get(f"/dojos/{dojo}/{module}/{challenge}/description")


class PwnCollegeSyncClient:
    """Sync wrapper for PwnCollegeClient."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=True,
        )
        self._csrf_nonce: str | None = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.client.close()

    def _ensure_csrf(self) -> str:
        """Fetch CSRF nonce if not already cached."""
        if self._csrf_nonce is None:
            resp = self.client.get("/")
            self._csrf_nonce = _extract_csrf_nonce(resp.text)
            if self._csrf_nonce is None:
                raise RuntimeError("Could not extract CSRF nonce from page")
        return self._csrf_nonce

    def _api_url(self, path: str) -> str:
        return f"/pwncollege_api/v1{path}"

    def _post(self, path: str, json: dict | None = None) -> dict[str, Any]:
        csrf = self._ensure_csrf()
        headers = {"CSRF-Token": csrf}
        data = dict(json or {})
        data["nonce"] = csrf
        resp = self.client.post(self._api_url(path), json=data, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str, json: dict | None = None) -> dict[str, Any]:
        csrf = self._ensure_csrf()
        headers = {"CSRF-Token": csrf}
        data = dict(json or {}) if json else {}
        data["nonce"] = csrf
        resp = self.client.request(
            "DELETE", self._api_url(path), json=data, headers=headers
        )
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str) -> dict[str, Any]:
        resp = self.client.get(self._api_url(path))
        resp.raise_for_status()
        return resp.json()

    def register(self, username: str, email: str, password: str) -> dict[str, Any]:
        return self._post(
            "/auth/register",
            json={"name": username, "email": email, "password": password},
        )

    def login(self, username: str, password: str) -> dict[str, Any]:
        return self._post("/auth/login", json={"name": username, "password": password})

    def logout(self) -> dict[str, Any]:
        return self._post("/auth/logout")

    def set_ssh_key(self, public_key: str) -> dict[str, Any]:
        return self._post("/ssh_key", json={"ssh_key": public_key})

    def delete_ssh_key(self, public_key: str) -> dict[str, Any]:
        return self._delete("/ssh_key", json={"ssh_key": public_key})

    def start_challenge(
        self,
        dojo: str,
        module: str,
        challenge: str,
        practice: bool = False,
    ) -> dict[str, Any]:
        return self._post(
            "/docker",
            json={
                "dojo": dojo,
                "module": module,
                "challenge": challenge,
                "practice": practice,
            },
        )

    def get_current_challenge(self) -> dict[str, Any]:
        return self._get("/docker")

    def stop_challenge(self) -> dict[str, Any]:
        return self._delete("/docker")

    def submit_flag(
        self, dojo: str, module: str, challenge: str, flag: str
    ) -> dict[str, Any]:
        resp = self.client.post(
            self._api_url(f"/dojos/{dojo}/{module}/{challenge}/solve"),
            json={"submission": flag},
        )
        resp.raise_for_status()
        return resp.json()

    def list_dojos(self) -> dict[str, Any]:
        return self._get("/dojos")

    def list_modules(self, dojo: str) -> dict[str, Any]:
        return self._get(f"/dojos/{dojo}/modules")

    def get_challenge_description(
        self, dojo: str, module: str, challenge: str
    ) -> dict[str, Any]:
        return self._get(f"/dojos/{dojo}/{module}/{challenge}/description")


class UserState(Enum):
    """State of a user in the pool."""

    AVAILABLE = "available"
    IN_USE = "in_use"
    UNHEALTHY = "unhealthy"
    INITIALIZING = "initializing"


@dataclass
class DojoUser:
    """A managed user with SSH key for dojo access."""

    username: str
    ssh_key_path: Path
    user_id: int | None = None
    state: UserState = UserState.INITIALIZING
    acquired_at: float | None = None
    current_challenge_id: str | None = None

    @property
    def password(self) -> str:
        """Deterministic password from username."""
        return hashlib.sha256(f"{self.username}:pwncollege_salt".encode()).hexdigest()[
            :16
        ]

    @property
    def email(self) -> str:
        return f"{self.username}@dojo.local"

    @property
    def ssh_pubkey(self) -> str:
        return self.ssh_key_path.with_suffix(".pub").read_text().strip()


@dataclass
class PoolStats:
    """Statistics about the user pool."""

    total_users: int
    available: int
    in_use: int
    unhealthy: int
    initializing: int


@dataclass
class UserPool:
    """Manages a pool of DojoUsers with SSH keys for parallel trajectory collection.

    Features:
    - Idempotent SSH key generation
    - Deterministic passwords (hash-based, no storage needed)
    - Exclusive user access via asyncio.Queue
    - Health checking and stuck-user recovery
    """

    num_users: int = 32
    ssh_key_dir: Path = field(default_factory=lambda: Path(__file__).parent / "keys")
    username_prefix: str = "rl_agent_"
    acquisition_timeout: float = 300.0  # 5 minutes
    stuck_threshold: float = 600.0  # 10 minutes
    health_check_interval: float = 60.0

    _available: asyncio.Queue[DojoUser] = field(
        default_factory=asyncio.Queue, init=False
    )
    _all_users: dict[str, DojoUser] = field(default_factory=dict, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _health_check_task: asyncio.Task | None = field(default=None, init=False)
    _initialized: bool = field(default=False, init=False)
    _shutdown: bool = field(default=False, init=False)

    def _generate_ssh_key(self, key_path: Path) -> None:
        """Generate SSH key pair idempotently."""
        if key_path.exists():
            return

        key_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(key_path),
                "-N",
                "",  # No passphrase
                "-C",
                f"{key_path.stem}@dojo",
            ],
            check=True,
            capture_output=True,
        )

    async def initialize(self, client: PwnCollegeClient) -> None:
        """Initialize pool: create SSH keys, register users, populate queue."""
        if self._initialized:
            return

        async with self._lock:
            if self._initialized:
                return

            for i in range(self.num_users):
                username = f"{self.username_prefix}{i:02d}"
                key_path = self.ssh_key_dir / username

                # Generate SSH key idempotently
                self._generate_ssh_key(key_path)

                user = DojoUser(
                    username=username,
                    ssh_key_path=key_path,
                    state=UserState.INITIALIZING,
                )

                # Register user (may already exist)
                try:
                    await client.register(username, user.email, user.password)
                except httpx.HTTPStatusError as e:
                    if e.response.status_code != 409:  # 409 = already exists
                        raise

                # Login to get user_id and set SSH key
                result = await client.login(username, user.password)
                user.user_id = result.get("data", {}).get("id")

                # Set SSH key
                await client.set_ssh_key(user.ssh_pubkey)
                await client.logout()

                user.state = UserState.AVAILABLE
                self._all_users[username] = user
                await self._available.put(user)

            # Start health check background task
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            self._initialized = True

    async def _health_check_loop(self) -> None:
        """Background task to recover stuck users."""
        while not self._shutdown:
            await asyncio.sleep(self.health_check_interval)
            await self._recover_stuck_users()

    async def _recover_stuck_users(self) -> None:
        """Force-release users that have been acquired too long."""
        async with self._lock:
            now = time.time()
            for user in self._all_users.values():
                if user.state == UserState.IN_USE and user.acquired_at is not None:
                    if now - user.acquired_at > self.stuck_threshold:
                        user.state = UserState.AVAILABLE
                        user.acquired_at = None
                        user.current_challenge_id = None
                        await self._available.put(user)

    @asynccontextmanager
    async def acquire(self, challenge_id: str):
        """Acquire exclusive access to a user for a challenge.

        Usage:
            async with pool.acquire("challenge-123") as user:
                # user is exclusively yours
                ...
        """
        if not self._initialized:
            raise RuntimeError("UserPool not initialized. Call initialize() first.")

        try:
            user = await asyncio.wait_for(
                self._available.get(), timeout=self.acquisition_timeout
            )
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Could not acquire user within {self.acquisition_timeout}s"
            )

        async with self._lock:
            user.state = UserState.IN_USE
            user.acquired_at = time.time()
            user.current_challenge_id = challenge_id

        try:
            yield user
        finally:
            async with self._lock:
                user.state = UserState.AVAILABLE
                user.acquired_at = None
                user.current_challenge_id = None
            await self._available.put(user)

    async def get_stats(self) -> PoolStats:
        """Get current pool statistics."""
        async with self._lock:
            states = [u.state for u in self._all_users.values()]
            return PoolStats(
                total_users=len(self._all_users),
                available=states.count(UserState.AVAILABLE),
                in_use=states.count(UserState.IN_USE),
                unhealthy=states.count(UserState.UNHEALTHY),
                initializing=states.count(UserState.INITIALIZING),
            )

    async def shutdown(self) -> None:
        """Gracefully shutdown the pool."""
        self._shutdown = True
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        self._initialized = False
