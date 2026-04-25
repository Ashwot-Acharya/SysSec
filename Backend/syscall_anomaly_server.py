"""
Real-Time System Call Anomaly Detection — WebSocket Server
==========================================================
Architecture:
    External collector (perf trace, strace, etc.)
        → POST /api/syscalls   or   WebSocket /ws/ingest
        → Queue → Anomaly Detection → Broadcast to frontend via /ws

Run:
    uvicorn syscall_anomaly_server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))
try:
    from Components.cyclic_monitoring import load_model
    MODEL_AVAILABLE = True
except ImportError:
    MODEL_AVAILABLE = False
    print("Warning: Could not import load_model from Components.cyclic_monitoring")

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("syscall-server")

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
MAX_CONNECTIONS: int = 10          # max frontend WebSocket clients
WINDOW_SIZE: int = 20             # sliding window for anomaly detection
ANOMALY_THRESHOLD: float = 0.7    # minimum score to fire an alert
STATS_INTERVAL: float = 1.0       # broadcast stats every N seconds


# ─────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────
@dataclass
class ParsedSyscall:
    """Represents a single parsed system call."""
    timestamp: str        # e.g. "6425.801" or "14:03:19"
    thread: str           # e.g. "Thread-1" or process name
    pid: int              # process ID
    syscall_name: str     # e.g. "openat", "read", "close"
    args: str             # e.g. "fd: 4" or "AT_FDCWD, /etc/passwd"
    return_value: Optional[int]  # syscall return value, None if unknown


@dataclass
class AnomalyResult:
    """Result from the anomaly detection engine."""
    is_anomaly: bool           # True if anomaly detected
    score: float               # 0.0 - 1.0 confidence score
    reason: Optional[str]      # human-readable explanation
    expected_tokens: list[str] # what was expected instead
    # Parse tree fields for frontend visualization
    token_parseable: list[bool] = None       # per-token: True = valid, False = anomalous
    breakdown: Optional[dict]  = None        # {position, syscall, reason, rule_violated}
    verdict: Optional[str]     = None        # one-line human-readable summary
    unknown_syscalls: list[str] = None       # syscalls never seen before
    parse_spans: list[dict]    = None        # [{start, end, label, valid}] for tree rendering


# ─────────────────────────────────────────────
#  Server State  (in-memory, single-process)
# ─────────────────────────────────────────────
class ServerState:
    """
    Central state container for the server.
    Holds connected clients, message queue, sliding window, and stats counters.
    """

    def __init__(self) -> None:
        # Set of frontend WebSocket connections (consumers)
        self.connected_clients: set[WebSocket] = set()

        # Async queue decouples ingestion from processing/broadcasting
        self.message_queue: asyncio.Queue[ParsedSyscall] = asyncio.Queue()

        # Sliding window of last N syscall names for anomaly detection
        self.syscall_window: deque[str] = deque(maxlen=WINDOW_SIZE)

        # Counters
        self.total_syscalls: int = 0
        self.total_anomalies: int = 0

        # Rate tracking — 1-second buckets for moving average
        self._rate_buckets: deque[tuple[float, int]] = deque(maxlen=10)
        self._current_bucket_time: float = time.monotonic()
        self._current_bucket_count: int = 0

        # Background task handles for clean shutdown
        self.background_tasks: list[asyncio.Task] = []

    def record_syscall_tick(self) -> None:
        """Record one syscall for per-second rate calculation.

        Groups counts into 1-second buckets. When a second passes,
        the current bucket is pushed to the deque and a new one starts.
        """
        now = time.monotonic()
        if now - self._current_bucket_time >= 1.0:
            self._rate_buckets.append(
                (self._current_bucket_time, self._current_bucket_count)
            )
            self._current_bucket_time = now
            self._current_bucket_count = 0
        self._current_bucket_count += 1

    def recent_syscalls_per_second(self) -> float:
        """Calculate simple moving average of syscalls/sec over last 10 seconds."""
        if not self._rate_buckets:
            return float(self._current_bucket_count)
        total = sum(c for _, c in self._rate_buckets) + self._current_bucket_count
        return round(total / (len(self._rate_buckets) + 1), 2)


# Global state instance
state = ServerState()


# ─────────────────────────────────────────────
#  Anomaly Detection  (pluggable stub)
# ─────────────────────────────────────────────
# Known "normal" syscall patterns — used for parse tree generation
NORMAL_PATTERNS = {
    ("openat", "read"): "file_read_start",
    ("read", "close"): "file_read_end",
    ("read", "read"): "sequential_read",
    ("openat", "write"): "file_write_start",
    ("write", "close"): "file_write_end",
    ("recvfrom", "openat"): "request_handling",
    ("sendto", "close"): "response_complete",
    ("close", "recvfrom"): "connection_cycle",
    ("read", "sendto"): "read_then_respond",
}


class AnomalyDetector:
    """
    Anomaly detector wrapper.

    Tries to load the actual PCFG model from Components/model.pkl.
    If not found, falls back to the dummy rule-based detector.
    """

    def __init__(self):
        self.actual_model = None
        self.threshold = 0.7
        self.is_dummy = True

        if MODEL_AVAILABLE:
            model_path = Path(__file__).parent.parent / "Components" / "model.pkl"
            try:
                payload = load_model(str(model_path))
                self.actual_model = payload["detector"]
                self.threshold = payload["threshold"]
                self.is_dummy = False
                log.info(f"Successfully loaded actual PCFG model from {model_path} with threshold {self.threshold:.4f}")
            except Exception as e:
                log.warning(f"Failed to load actual model: {e}. Falling back to dummy detector.")
        
        # We override the global ANOMALY_THRESHOLD if the real model provides one
        global ANOMALY_THRESHOLD
        if not self.is_dummy:
            ANOMALY_THRESHOLD = self.threshold

    def _build_parse_tree(self, window: list[str], failed_pos: int,
                          reason: str, rule_name: str) -> tuple:
        """
        Build parse tree data for a window of syscalls.

        Returns (token_parseable, breakdown, verdict, parse_spans).
        """
        n = len(window)

        # Token-level parseability: mark tokens near the anomaly as unparseable
        token_parseable = [True] * n
        if failed_pos is not None and 0 <= failed_pos < n:
            token_parseable[failed_pos] = False
            # Also mark the token before as part of the violation pair
            if failed_pos > 0:
                token_parseable[failed_pos - 1] = False

        # Breakdown info
        breakdown = {
            "position": failed_pos,
            "syscall": window[failed_pos] if 0 <= failed_pos < n else "?",
            "reason": reason,
            "rule_violated": rule_name,
            "context_before": window[max(0, failed_pos - 3):failed_pos],
            "context_after": window[failed_pos + 1:min(n, failed_pos + 3)],
        }

        # Build parse spans — identify which consecutive pairs match known patterns
        parse_spans = []
        for i in range(n - 1):
            pair = (window[i], window[i + 1])
            if pair in NORMAL_PATTERNS:
                parse_spans.append({
                    "start": i,
                    "end": i + 1,
                    "label": NORMAL_PATTERNS[pair],
                    "valid": token_parseable[i] and token_parseable[i + 1],
                })

        # Verdict
        parseable_count = sum(token_parseable)
        verdict = (
            f"RULE VIOLATION at position {failed_pos}: "
            f"'{window[failed_pos] if failed_pos < n else '?'}' "
            f"violates {rule_name}. "
            f"{parseable_count}/{n} tokens match normal grammar patterns."
        )

        return token_parseable, breakdown, verdict, parse_spans

    def detect(self, window: list[str]) -> AnomalyResult:
        """Analyze the sliding window of syscall names for anomalies.

        Rules:
            1. Double close — two consecutive 'close' calls
            2. Too many opens — more than 2 'openat' without matching 'close'

        Returns AnomalyResult with full parse tree data for visualization.
        """
        if not window:
            return AnomalyResult(False, 0.1, None, [])

        if not self.is_dummy and self.actual_model is not None:
            # Use the ACTUAL PCFG inside model!
            # The model predict() takes a sequence and returns (is_anomaly, score, explanation_dict)
            is_anom, score, explanation = self.actual_model.predict(window)
            
            # extract parse tree details provided by explain_with_parse_tree
            token_parseable = explanation.get("token_parseable")
            breakdown = explanation.get("breakdown")
            verdict = explanation.get("verdict", str(explanation))
            unknown_syscalls = explanation.get("unknown_syscalls", [])
            parse_spans = explanation.get("parse_spans", [])

            return AnomalyResult(
                is_anomaly=is_anom,
                score=score,
                reason=breakdown.get("reason") if breakdown else "Anomalous sequence detected by PCFG model",
                expected_tokens=[], # Model doesn't predict specific next tokens natively yet
                token_parseable=token_parseable,
                breakdown=breakdown,
                verdict=verdict,
                unknown_syscalls=unknown_syscalls,
                parse_spans=parse_spans,
            )

        # ── Fallback Dummy Rules ──────────────────────────────────────────────
        n = len(window)
        current = window[-1]

        # Rule 1 — double close
        if current == "close" and n >= 2 and window[-2] == "close":
            failed_pos = n - 1
            reason = "Double close without open in between"
            rule_name = "fd_lifecycle (open → read/write → close)"

            token_parseable, breakdown, verdict, parse_spans = \
                self._build_parse_tree(window, failed_pos, reason, rule_name)

            return AnomalyResult(
                is_anomaly=True,
                score=0.85,
                reason=reason,
                expected_tokens=["openat", "read", "write"],
                token_parseable=token_parseable,
                breakdown=breakdown,
                verdict=verdict,
                unknown_syscalls=[],
                parse_spans=parse_spans,
            )

        # Rule 2 — too many openat without close
        if current == "openat":
            opens = window.count("openat")
            closes = window.count("close")
            if opens - closes > 2:
                failed_pos = n - 1
                reason = f"Too many open files without close (opens={opens}, closes={closes})"
                rule_name = "fd_balance (each open must have a close)"

                token_parseable, breakdown, verdict, parse_spans = \
                    self._build_parse_tree(window, failed_pos, reason, rule_name)

                return AnomalyResult(
                    is_anomaly=True,
                    score=0.92,
                    reason=reason,
                    expected_tokens=["close"],
                    token_parseable=token_parseable,
                    breakdown=breakdown,
                    verdict=verdict,
                    unknown_syscalls=[],
                    parse_spans=parse_spans,
                )

        return AnomalyResult(False, 0.1, None, [])


# Singleton detector instance — swap this for ML model later
detector = AnomalyDetector()


def detect_anomaly(window: list[str]) -> AnomalyResult:
    """Public API — delegates to the pluggable detector instance."""
    return detector.detect(window)


# ─────────────────────────────────────────────
#  Statistics
# ─────────────────────────────────────────────
def update_stats(new_anomaly: bool = False) -> None:
    """Increment counters after processing a syscall."""
    state.total_syscalls += 1
    state.record_syscall_tick()
    if new_anomaly:
        state.total_anomalies += 1


def build_stats_message() -> dict:
    """Build the JSON stats payload for broadcasting."""
    rate = state.recent_syscalls_per_second()
    anomaly_rate = (
        round(state.total_anomalies / state.total_syscalls, 5)
        if state.total_syscalls
        else 0.0
    )
    return {
        "type": "stats",
        "total_syscalls": state.total_syscalls,
        "total_anomalies": state.total_anomalies,
        "anomaly_rate": anomaly_rate,
        "recent_syscalls_per_second": rate,
    }


# ─────────────────────────────────────────────
#  Broadcasting
# ─────────────────────────────────────────────
async def broadcast_to_clients(message: dict) -> None:
    """Send a JSON message to every connected frontend client.

    If a send fails, the client is considered dead and removed from the set.
    """
    if not state.connected_clients:
        return
    payload = json.dumps(message)
    dead: set[WebSocket] = set()
    for ws in list(state.connected_clients):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    for ws in dead:
        state.connected_clients.discard(ws)
        log.info("Removed stale connection during broadcast.")


# ─────────────────────────────────────────────
#  Processor  (queue consumer)
# ─────────────────────────────────────────────
async def processor_task() -> None:
    """
    Background task: continuously reads from the message queue,
    runs anomaly detection on the sliding window, then broadcasts
    the syscall (and any anomaly alert) to all connected frontend clients.
    """
    log.info("Processor task started.")
    while True:
        syscall: ParsedSyscall = await state.message_queue.get()

        try:
            # 1. Update sliding window
            state.syscall_window.append(syscall.syscall_name)
            window_snapshot = list(state.syscall_window)

            # 2. Run anomaly detection
            result = detect_anomaly(window_snapshot)

            # 3. Broadcast syscall event to frontend
            syscall_msg = {
                "type": "syscall",
                "timestamp": syscall.timestamp,
                "thread": syscall.thread,
                "pid": syscall.pid,
                "syscall": syscall.syscall_name,
                "args": syscall.args,
                "return_value": syscall.return_value,
            }
            await broadcast_to_clients(syscall_msg)

            # 4. Update stats
            update_stats(new_anomaly=result.is_anomaly)

            # 5. Broadcast anomaly alert if detected
            if result.is_anomaly and result.score >= ANOMALY_THRESHOLD:
                failed_pos = len(window_snapshot) - 1
                anomaly_msg = {
                    "type": "anomaly",
                    "timestamp": syscall.timestamp,
                    "anomaly_score": result.score,
                    "threshold": ANOMALY_THRESHOLD,
                    "window_sequence": window_snapshot,
                    "failure_reason": result.reason,
                    "failed_at_position": failed_pos,
                    "expected_tokens": result.expected_tokens,
                    # Parse tree data for frontend visualization
                    "parse_tree": {
                        "token_parseable": result.token_parseable or [True] * len(window_snapshot),
                        "breakdown": result.breakdown,
                        "verdict": result.verdict,
                        "unknown_syscalls": result.unknown_syscalls or [],
                        "parse_spans": result.parse_spans or [],
                    },
                }
                await broadcast_to_clients(anomaly_msg)
                log.warning(
                    "ANOMALY | score=%.2f | %s | window=%s",
                    result.score,
                    result.reason,
                    window_snapshot[-5:],
                )
        except Exception as exc:
            log.error("Error processing syscall: %s", exc)
        finally:
            state.message_queue.task_done()


# ─────────────────────────────────────────────
#  Periodic Stats Broadcaster
# ─────────────────────────────────────────────
async def broadcast_stats_task() -> None:
    """Background task: sends stats snapshot to all frontend clients every second."""
    log.info("Stats broadcast task started.")
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        if state.connected_clients:
            try:
                await broadcast_to_clients(build_stats_message())
            except Exception as exc:
                log.error("Error broadcasting stats: %s", exc)


# ─────────────────────────────────────────────
#  Ping / Keep-Alive
# ─────────────────────────────────────────────
async def ping_clients_task() -> None:
    """Background task: sends ping every 20s to keep frontend WebSocket connections alive."""
    while True:
        await asyncio.sleep(20)
        dead: set[WebSocket] = set()
        for ws in list(state.connected_clients):
            try:
                await ws.send_text(json.dumps({"type": "ping"}))
            except Exception:
                dead.add(ws)
        for ws in dead:
            state.connected_clients.discard(ws)


# ─────────────────────────────────────────────
#  Lifespan  (startup + shutdown)
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage background task lifecycle — start on boot, cancel on shutdown."""
    # ── Startup ──
    tasks = [
        asyncio.create_task(processor_task(), name="processor"),
        asyncio.create_task(broadcast_stats_task(), name="stats_broadcast"),
        asyncio.create_task(ping_clients_task(), name="ping"),
    ]
    state.background_tasks = tasks
    log.info("Server ready. Waiting for syscall data on POST /api/syscalls or WS /ws/ingest")

    yield

    # ── Shutdown ──
    log.info("Shutting down…")
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    # Close all frontend connections
    for ws in list(state.connected_clients):
        try:
            await ws.close(code=1001, reason="Server shutting down")
        except Exception:
            pass
    state.connected_clients.clear()
    log.info("Shutdown complete.")


# ─────────────────────────────────────────────
#  FastAPI Application
# ─────────────────────────────────────────────
app = FastAPI(
    title="Syscall Anomaly Detection Server",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allow any origin during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
#  REST Endpoints
# ──────────────────────────────────────────────

@app.get("/health")
async def health_check() -> JSONResponse:
    """Returns {"status": "ok"} — verify the server is running."""
    return JSONResponse({"status": "ok"})


@app.get("/stats")
async def get_stats() -> JSONResponse:
    """Returns current stats snapshot as JSON."""
    return JSONResponse(build_stats_message())


@app.post("/api/syscalls")
async def ingest_syscall(payload: dict) -> JSONResponse:
    """
    REST endpoint to ingest a single syscall from an external collector.

    Expected JSON body:
    {
        "timestamp": "6425.801",
        "thread": "Thread-1",
        "pid": 14298,
        "syscall": "recvfrom",
        "args": "fd: 4",
        "return_value": 438
    }
    """
    try:
        sc = ParsedSyscall(
            timestamp=str(payload.get("timestamp", "")),
            thread=str(payload.get("thread", "unknown")),
            pid=int(payload.get("pid", 0)),
            syscall_name=str(payload.get("syscall", "")),
            args=str(payload.get("args", "")),
            return_value=payload.get("return_value"),
        )
        if not sc.syscall_name:
            return JSONResponse({"error": "Missing 'syscall' field"}, status_code=400)

        await state.message_queue.put(sc)
        return JSONResponse({"status": "queued"})
    except Exception as exc:
        log.error("Error ingesting syscall via REST: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/syscalls/batch")
async def ingest_syscall_batch(payload: dict) -> JSONResponse:
    """
    REST endpoint to ingest multiple syscalls at once.

    Expected JSON body:
    {
        "syscalls": [
            {"timestamp": "...", "thread": "...", "pid": 123, "syscall": "read", "args": "...", "return_value": 0},
            ...
        ]
    }
    """
    try:
        items = payload.get("syscalls", [])
        if not isinstance(items, list):
            return JSONResponse({"error": "'syscalls' must be a list"}, status_code=400)

        count = 0
        for item in items:
            sc = ParsedSyscall(
                timestamp=str(item.get("timestamp", "")),
                thread=str(item.get("thread", "unknown")),
                pid=int(item.get("pid", 0)),
                syscall_name=str(item.get("syscall", "")),
                args=str(item.get("args", "")),
                return_value=item.get("return_value"),
            )
            if sc.syscall_name:
                await state.message_queue.put(sc)
                count += 1

        return JSONResponse({"status": "queued", "count": count})
    except Exception as exc:
        log.error("Error ingesting batch: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=400)


# ──────────────────────────────────────────────
#  WebSocket: Ingest  (external collector → server)
# ──────────────────────────────────────────────

@app.websocket("/ws/ingest")
async def websocket_ingest(ws: WebSocket) -> None:
    """
    WebSocket for INGESTING syscall data from an external collector.

    The collector (e.g. a script running perf trace / strace) connects here
    and sends JSON syscall messages. The server queues them for processing
    and broadcasting to frontend clients.

    Expected messages:
    {
        "timestamp": "6425.801",
        "thread": "Thread-1",
        "pid": 14298,
        "syscall": "recvfrom",
        "args": "fd: 4",
        "return_value": 438
    }
    """
    await ws.accept()
    client = ws.client
    log.info("Ingest client connected: %s:%s", client.host, client.port)

    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                sc = ParsedSyscall(
                    timestamp=str(msg.get("timestamp", "")),
                    thread=str(msg.get("thread", "unknown")),
                    pid=int(msg.get("pid", 0)),
                    syscall_name=str(msg.get("syscall", "")),
                    args=str(msg.get("args", "")),
                    return_value=msg.get("return_value"),
                )
                if sc.syscall_name:
                    await state.message_queue.put(sc)
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                log.warning("Bad ingest message: %s — %r", exc, data[:200])

    except WebSocketDisconnect:
        log.info("Ingest client disconnected: %s:%s", client.host, client.port)
    except Exception as exc:
        log.error("Ingest client error: %s", exc)


# ──────────────────────────────────────────────
#  WebSocket: Frontend  (server → browser)
# ──────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_frontend(ws: WebSocket) -> None:
    """
    WebSocket for FRONTEND clients (browsers).

    Clients connect here and receive:
    - Syscall events  (type: "syscall")
    - Anomaly alerts  (type: "anomaly")
    - Stats updates   (type: "stats")   every 1 second
    - Ping messages   (type: "ping")    every 20 seconds

    Clients can send:
    - {"type": "pong"}  — keep-alive response
    """
    # Guard: max connections
    if len(state.connected_clients) >= MAX_CONNECTIONS:
        await ws.close(code=1008, reason="Server at capacity")
        log.warning(
            "Rejected frontend connection — at capacity (%d/%d).",
            len(state.connected_clients), MAX_CONNECTIONS,
        )
        return

    await ws.accept()
    state.connected_clients.add(ws)
    client = ws.client
    log.info(
        "Frontend client connected: %s:%s (total=%d)",
        client.host, client.port, len(state.connected_clients),
    )

    # Send welcome + current stats immediately
    await ws.send_text(json.dumps({
        "type": "welcome",
        "message": "Connected to Syscall Anomaly Detection Server",
        "window_size": WINDOW_SIZE,
        "anomaly_threshold": ANOMALY_THRESHOLD,
    }))
    await ws.send_text(json.dumps(build_stats_message()))

    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "pong":
                    pass  # expected keep-alive reply
                else:
                    log.debug("Frontend client message: %s", msg)
            except json.JSONDecodeError:
                log.warning("Non-JSON from frontend client: %r", data)

    except WebSocketDisconnect:
        log.info(
            "Frontend client disconnected: %s:%s (total=%d)",
            client.host, client.port, len(state.connected_clients) - 1,
        )
    except Exception as exc:
        log.error("Frontend client error %s:%s — %s", client.host, client.port, exc)
    finally:
        state.connected_clients.discard(ws)


# ─────────────────────────────────────────────
#  Standalone Entry-Point
# ─────────────────────────────────────────────
async def main() -> None:
    """Run the server directly with: python syscall_anomaly_server.py"""
    import uvicorn
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())