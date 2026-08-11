"""Stdio transport: drive an MCP server as a local subprocess.

The server is launched with ``stdin``/``stdout`` wired up for line-delimited
JSON-RPC.  This is the most common deployment for desktop MCP servers, and it
is also the one with the largest blast radius: the server runs arbitrary code
in our process tree, so the proxy must

* bound the process lifetime and kill it tree-wise on close,
* never inherit more of the environment than explicitly allowed,
* treat every line as untrusted and validate it before use,
* run the process with the least privilege the OS allows.

On POSIX we drop the process into a separate session and rely on a kill of the
whole group; on Windows we fall back to :program:`taskkill` on teardown.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional

from ...core.logging import get_logger
from ..protocol import (
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcResponse,
    McpError,
    McpErrorCode,
    TransportKind,
)
from .base import TransportError, McpTransport

__all__ = ["StdioTransport"]

_LOG = get_logger("aegis.mcp.transport.stdio")

IS_WINDOWS = sys.platform == "win32"


class StdioTransport(McpTransport):
    """Communicate with an MCP server over its stdin/stdout streams."""

    kind = TransportKind.STDIO

    def __init__(
        self,
        command: List[str],
        *,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        timeout_s: float = 30.0,
        allow_env: Optional[List[str]] = None,
    ) -> None:
        """Create the transport.

        Args:
            command: The server launch command (executable + args).
            env: Environment to pass; when ``None`` a minimal allowlist from
                the current process is used so secrets are not leaked in.
            cwd: Working directory for the child.
            timeout_s: Per-request deadline.
            allow_env: Names copied from the parent env when ``env`` is None.

        Raises:
            TransportError: ``command`` is empty.
        """
        super().__init__()
        if not command:
            raise TransportError("stdio transport requires a command")
        self._command = list(command)
        self._env = self._sanitise_env(env, allow_env)
        self._cwd = cwd
        self._timeout = float(timeout_s)
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._reader: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._pending: Dict[str, "_PendingResponse"] = {}
        self._read_buffer = ""

    @staticmethod
    def _sanitise_env(env: Optional[Dict[str, str]], allow_env: Optional[List[str]]) -> Dict[str, str]:
        """Build a child environment, copying only the allowed variables.

        Args:
            env: Explicit full environment, used verbatim when provided.
            allow_env: Subset of parent env names to copy when ``env`` is None.

        Returns:
            A mapping safe to hand to the child process.
        """
        if env is not None:
            return {str(k): str(v) for k, v in env.items()}
        allowed = allow_env or ["PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL"]
        return {name: os.environ[name] for name in allowed if name in os.environ}

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        """Spawn the server subprocess and start the reader loop."""
        if self._open:
            return
        try:
            self._proc = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                cwd=self._cwd,
                bufsize=1,
                universal_newlines=False,
                # Keep the child in its own process group so we can kill it
                # tree-wise; on Windows this is ignored (handled in close()).
                start_new_session=not IS_WINDOWS,
            )
        except (OSError, ValueError) as exc:
            raise TransportError(f"failed to launch MCP server: {exc}", cause=exc)
        self._open = True
        self._stop.clear()
        self._reader = threading.Thread(target=self._pump, name="mcp-stdio-reader", daemon=True)
        self._reader.start()
        _LOG.info("stdio transport connected", extra={"command": " ".join(self._command)})

    def close(self) -> None:
        """Terminate the child process tree and join the reader."""
        if not self._open:
            return
        self._open = False
        self._stop.set()
        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            self._kill_tree(proc)
        if self._reader is not None:
            self._reader.join(timeout=self._timeout)
            self._reader = None
        _LOG.info("stdio transport closed")

    def _kill_tree(self, proc: subprocess.Popen) -> None:
        """Kill the process and its descendants across platforms."""
        pid = proc.pid
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            else:
                import os
                import signal

                os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:  # pragma: no cover - process already gone
                pass
        try:
            proc.wait(timeout=10)
        except Exception:  # pragma: no cover - ignore hang
            pass

    # -- reader loop --------------------------------------------------------

    def _pump(self) -> None:
        """Continuously read and dispatch frames from stdout."""
        assert self._proc is not None and self._proc.stdout is not None
        stream = self._proc.stdout
        while not self._stop.is_set():
            line = stream.readline()
            if not line:
                if self._proc.poll() is not None:
                    break
                continue
            self._ingest(line.decode("utf-8", "replace"))

    def _ingest(self, text: str) -> None:
        """Parse one frame (or buffered partial) and route it.

        Args:
            text: A line read from the server.  Lines are buffered until a
                complete JSON object is seen.
        """
        self._read_buffer += text
        # Only attempt to parse when we have at least one complete JSON value.
        buffer = self._read_buffer
        try:
            idx = buffer.rindex("}\n")
        except ValueError:
            idx = -1
        if idx < 0:
            # No terminator yet; keep buffering.
            if len(buffer) > 1_000_000:
                self._read_buffer = ""
            return
        chunk = buffer[: idx + 1]
        self._read_buffer = buffer[idx + 2 :]
        for raw_line in chunk.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            self._dispatch_line(raw_line)

    def _dispatch_line(self, raw_line: str) -> None:
        """Validate and route a single JSON frame line."""
        try:
            frame = json.loads(raw_line)
        except json.JSONDecodeError:
            _LOG.warning("non-JSON frame from MCP server dropped", extra={"snippet": raw_line[:80]})
            return
        if not isinstance(frame, dict):
            return
        msg_id = frame.get("id")
        if "method" in frame and "id" not in frame:
            note = JsonRpcNotification.from_dict(frame)
            self._emit_notification(note)
            return
        if "result" in frame or "error" in frame:
            response = self._validate_response(frame)
            with self._lock:
                pending = self._pending.pop(response.id, None)
            if pending is not None:
                pending.set(response)
            return
        _LOG.debug("unrouted MCP frame", extra={"frame": raw_line[:120]})

    # -- request/response ---------------------------------------------------

    def send(self, request: JsonRpcRequest) -> "JsonRpcResponse":
        """Serialise and send a request, blocking for the correlated response.

        Args:
            request: The JSON-RPC request.

        Returns:
            The correlated response.

        Raises:
            TransportError: The transport is closed, the child died, or no
                response arrived before ``timeout_s``.
        """
        if not self._open or self._proc is None:
            raise TransportError("stdio transport is not connected")
        if self._proc.poll() is not None:
            raise TransportError("MCP server process exited", transient=False)
        import time

        event = threading.Event()
        promise: "_PendingResponse" = _PendingResponse(event)
        with self._lock:
            self._pending[request.id] = promise
        payload = (json.dumps(request.to_dict()) + "\n").encode("utf-8")
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(payload)
            self._proc.stdin.flush()
        except (OSError, ValueError) as exc:
            with self._lock:
                self._pending.pop(request.id, None)
            raise TransportError("failed to write to MCP server", cause=exc)
        if not event.wait(timeout=self._timeout):
            with self._lock:
                self._pending.pop(request.id, None)
            raise TransportError(f"MCP server did not respond within {self._timeout}s", transient=True)
        return promise.response


class _PendingResponse:
    """A minimal future for a single JSON-RPC response."""

    __slots__ = ("event", "response", "_lock")

    def __init__(self, event: threading.Event) -> None:
        self.event = event
        self.response: Optional[JsonRpcResponse] = None
        self._lock = threading.Lock()

    def set(self, response: "JsonRpcResponse") -> None:
        """Store the response and signal completion."""
        with self._lock:
            self.response = response
        self.event.set()
