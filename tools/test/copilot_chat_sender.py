"""
Copilot Chat sender with strict window binding and ledger closure.
ASCII-only source for unattended compatibility.
"""

import argparse
import ctypes
import hashlib
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pyperclip
from pywinauto import Application, findwindows
CHAT_ROOT_TITLE_REGEX = r"(?i).*(copilot|chat|\u804a\u5929).*"

CHAT_ROOT_HINT_TOKENS = (
    "chat",
    "copilot",
    "composer",
    "assistant",
    "prompt",
    "\u804a\u5929",
    "\u63d0\u95ee",
)
CHAT_INPUT_HINT_TOKENS = (
    "chat",
    "copilot",
    "message",
    "input",
    "prompt",
    "compose",
    "composer",
    "ask",
    "query",
    "question",
    "\u804a\u5929",
    "\u6d88\u606f",
    "\u8f93\u5165",
    "\u63d0\u95ee",
    "\u8be2\u95ee",
)



REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER_PATH = (
    REPO_ROOT
    / "out"
    / "artifacts"
    / "ab_agent_queue"
    / "chat_dispatch"
    / "pywinauto_sender_ledger.jsonl"
)
DEFAULT_LOG_DIR = REPO_ROOT / "out" / "artifacts" / "ab_agent_queue" / "chat_dispatch"

WINDOW_FOREGROUND_MAX_ATTEMPTS = 3
FOREGROUND_BLOCKED_EXTRA_ATTEMPTS = 2
CHAT_INPUT_MIN_SCORE = 45
VERIFY_MIN_FRAGMENT_LEN = 3
VERIFY_POLL_INTERVAL_SEC = 0.25
VERIFY_WEAK_ALPHA_FRAGMENT_MAX_LEN = 12
VERIFY_WEAK_STOPWORDS = {
    "running",
    "status",
    "report",
    "event",
    "ticket",
    "session",
}
MAX_AMBIGUOUS_CANDIDATES = 8
RESTORE_PER_WINDOW_MAX_ATTEMPTS = 3
RESTORE_INTER_WINDOW_DELAY_SEC = 0.18
RESTORE_STABLE_FOREGROUND_DELAY_SEC = 0.16
RESTORE_MAX_GAP_AFTER_CANDIDATE = 8

ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT = 88
ADAPTIVE_HIGH_LOAD_AVAILABLE_MB = 768
ADAPTIVE_LOW_LOAD_MEMORY_PERCENT = 72
ADAPTIVE_LOW_LOAD_AVAILABLE_MB = 1536
ADAPTIVE_HIGH_LOAD_VERIFY_TIMEOUT_SCALE = 0.45
ADAPTIVE_HIGH_LOAD_VERIFY_TIMEOUT_MAX_SEC = 4.0
ADAPTIVE_HIGH_LOAD_POLL_INTERVAL_SEC = 0.16
ADAPTIVE_HIGH_LOAD_RETRY_DELAY_SCALE = 0.55
ADAPTIVE_HIGH_LOAD_MAX_PRE_SEND_DELAY_MS = 180

SW_SHOWMAXIMIZED = 3
SW_SHOW = 5
SW_RESTORE = 9
AHK_COMPAT_SCHEMA = "AHK_CHAT_SEND_RESULT_V1"

RESTORE_SKIP_CLASSES = {
    "shell_traywnd",
    "tooltips_class32",
    "foregroundstaging",
    "ime",
    "msctfime ui",
    "thumbnaildevicehelperwnd",
    "pseudoconsolewindow",
    "workerw",
    "progman",
    "applicationframeinputsinkwindow",
    "xaml_windowedpopupclass",
}
RESTORE_SKIP_TITLES = {
    "default ime",
    "msctfime ui",
}

WindowCandidate = Tuple[int, Application, Any, str, int]


def utc_now_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_single_line(text: Any) -> str:
    if text is None:
        return ""
    raw = str(text)
    return re.sub(r"\s+", " ", raw).strip()


def contains_hint_token(text: str, tokens: Tuple[str, ...]) -> bool:
    normalized = safe_single_line(text).lower()
    if not normalized:
        return False
    return any(token in normalized for token in tokens)


def normalize_window_handles(value: Any) -> List[int]:
    handles: List[int] = []
    seen: set[int] = set()

    def add_handle(raw: Any) -> None:
        try:
            handle = int(raw)
        except Exception:
            return
        if handle <= 0 or handle in seen:
            return
        seen.add(handle)
        handles.append(handle)

    def visit(candidate: Any) -> None:
        if candidate is None:
            return

        if isinstance(candidate, dict):
            if "handle" in candidate:
                visit(candidate.get("handle"))
            if "hwnd" in candidate:
                visit(candidate.get("hwnd"))
            return

        if isinstance(candidate, (list, tuple, set)):
            for item in candidate:
                visit(item)
            return

        if isinstance(candidate, str):
            raw = safe_single_line(candidate)
            if not raw:
                return
            for token in re.split(r"[,;\s|]+", raw):
                add_handle(token.strip())
            return

        add_handle(candidate)

    visit(value)
    return handles


def stable_token(ticket_id: str, event: str, message: str, override: str = "") -> str:
    if override.strip():
        return override.strip()
    payload = "|".join([
        safe_single_line(ticket_id),
        safe_single_line(event),
        message,
    ])
    digest = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
    return f"PYW-{digest[:20]}"


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def setup_logging() -> logging.Logger:
    ensure_parent(DEFAULT_LOG_DIR / "placeholder.log")
    log_path = DEFAULT_LOG_DIR / f"copilot_sender_{datetime.now():%Y%m%d_%H%M%S}.log"

    logger = logging.getLogger("copilot_chat_sender")
    logger.setLevel(logging.INFO)
    logger.handlers = []

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.info("logger_initialized log=%s", str(log_path).replace("\\", "/"))
    return logger


@dataclass
class WindowBindingPolicy:
    title_regex: str = r".*Visual Studio Code.*"
    workspace_hint: str = ""
    expected_pid: int = 0
    expected_handle: int = 0
    active_window_only: bool = False
    allow_below_anchor_restore_fallback: bool = False


@dataclass
class SendRequest:
    message: str
    ticket_id: str = ""
    event: str = ""
    relay_path: str = ""
    ledger_path: str = ""
    dedupe_token: str = ""
    max_retries: int = 3
    timeout_per_step: float = 10.0
    require_transcript_confirmation: bool = True
    health_check_enabled: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_cooldown_sec: int = 900
    restore_previous_foreground_window: bool = True
    restore_previous_window_count: int = 12
    restore_previous_window_handles_csv: str = ""
    pre_send_delay_ms: int = 0
    esc_preflight_enabled: bool = False
    adaptive_load_enabled: bool = True
    adaptive_high_load_memory_percent: int = ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT
    adaptive_high_load_available_mb: int = ADAPTIVE_HIGH_LOAD_AVAILABLE_MB
    adaptive_low_load_memory_percent: int = ADAPTIVE_LOW_LOAD_MEMORY_PERCENT
    adaptive_low_load_available_mb: int = ADAPTIVE_LOW_LOAD_AVAILABLE_MB


@dataclass
class SendOutcome:
    success: bool
    status: str
    token: str
    reason: str
    grade: str
    fallback_action: str
    details: Dict[str, Any]


def _derive_ahk_exit_code(outcome: SendOutcome) -> int:
    if outcome.success and outcome.status in {"confirmed", "idempotent"}:
        return 0
    if outcome.status == "uncertain":
        return 2
    return 1


def _build_restore_capture_summary(trace_items: Any) -> str:
    if not isinstance(trace_items, list) or not trace_items:
        return ""

    parts: List[str] = []
    for item in trace_items[:5]:
        if not isinstance(item, dict):
            continue
        hwnd = int(item.get("hwnd", 0))
        pid = int(item.get("pid", 0))
        title = safe_single_line(item.get("title", ""))[:60]
        if hwnd <= 0:
            continue
        parts.append(f"hwnd={hwnd} pid={pid} title={title}")

    return "; ".join(parts)


def _build_restore_activation_summary(trace_items: Any) -> str:
    if not isinstance(trace_items, list) or not trace_items:
        return ""

    parts: List[str] = []
    for item in trace_items[:10]:
        if not isinstance(item, dict):
            continue
        hwnd = int(item.get("hwnd", 0))
        attempt = int(item.get("attempt", 0))
        ok = bool(item.get("ok", False))
        fg_after = int(item.get("foreground_after", 0))
        detail = safe_single_line(item.get("detail", ""))[:80]
        if hwnd <= 0:
            continue
        parts.append(
            f"hwnd={hwnd} attempt={attempt} ok={1 if ok else 0} fg={fg_after} detail={detail}"
        )

    return "; ".join(parts)


def serialize_outcome_with_ahk_compat(outcome: SendOutcome) -> Dict[str, Any]:
    payload = asdict(outcome)
    details = payload.get("details", {})
    if not isinstance(details, dict):
        details = {}

    sent = bool(outcome.success and outcome.status in {"confirmed", "idempotent"})
    ahk_exit_code = _derive_ahk_exit_code(outcome)
    dispatch_attempts = []
    if not sent:
        dispatch_attempts = [{"failure": safe_single_line(outcome.reason)}]

    restore_handles = normalize_window_handles(details.get("restore_previous_window_handles", []))
    restore_handles_csv = ",".join(str(handle) for handle in restore_handles)

    restore_trace = details.get("restore_previous_window_capture_trace", [])
    if not isinstance(restore_trace, list):
        restore_trace = []
    restore_activation_trace = details.get("restore_previous_window_activation_trace", [])
    if not isinstance(restore_activation_trace, list):
        restore_activation_trace = []

    restore_count_requested = int(details.get("restore_previous_window_count_requested", 0))
    restore_count_captured = int(details.get("restore_previous_window_count_captured", 0))
    restore_attempted = int(details.get("restore_previous_window_activation_count_attempted", 0))
    restore_succeeded = int(details.get("restore_previous_window_activation_count_succeeded", 0))
    restore_final_fg = int(details.get("restore_previous_window_activation_final_foreground_handle", 0))
    restore_executed = bool(details.get("restore_previous_window_activation_restore_executed", False))
    restore_skipped_reason = safe_single_line(
        details.get("restore_previous_window_activation_skipped_reason", "")
    )
    restore_capture_summary = _build_restore_capture_summary(restore_trace)
    restore_activation_summary = _build_restore_activation_summary(restore_activation_trace)

    code_focus_policy = {
        "restore_previous_window_count_requested": restore_count_requested,
        "restore_previous_window_count_captured": restore_count_captured,
        "restore_previous_window_handles": restore_handles,
        "restore_previous_window_handles_csv": restore_handles_csv,
        "restore_previous_window_capture_summary": restore_capture_summary,
        "restore_previous_window_activation_trace": restore_activation_summary,
        "restore_previous_window_activation_count_attempted": restore_attempted,
        "restore_previous_window_activation_count_succeeded": restore_succeeded,
        "restore_previous_window_activation_final_foreground_handle": restore_final_fg,
        "restore_previous_window_activation_restore_executed": restore_executed,
        "restore_previous_window_activation_skipped_reason": restore_skipped_reason,
        "effective_esc_preflight": bool(details.get("esc_preflight_enabled", False)),
    }

    payload.update(
        {
            "schema": AHK_COMPAT_SCHEMA,
            "sent": sent,
            "ahk_exit_code": ahk_exit_code,
            "dispatch_attempts": dispatch_attempts,
            "auto_reconnect_resend": {"triggered": False, "trigger_reason": ""},
            "esc_preflight_enabled": bool(details.get("esc_preflight_enabled", False)),
            "restore_previous_window_count_requested": restore_count_requested,
            "restore_previous_window_count_captured": restore_count_captured,
            "restore_previous_window_handles": restore_handles,
            "restore_previous_window_handles_csv": restore_handles_csv,
            "restore_previous_window_capture_summary": restore_capture_summary,
            "restore_previous_window_activation_trace": restore_activation_summary,
            "restore_previous_window_activation_count_attempted": restore_attempted,
            "restore_previous_window_activation_count_succeeded": restore_succeeded,
            "restore_previous_window_activation_final_foreground_handle": restore_final_fg,
            "restore_previous_window_activation_restore_executed": restore_executed,
            "restore_previous_window_activation_skipped_reason": restore_skipped_reason,
            "code_focus_policy": code_focus_policy,
            "note": "",
        }
    )
    return payload


def parse_utc_text(text: str) -> Optional[datetime]:
    value = safe_single_line(text)
    if not value:
        return None

    try:
        if value.endswith("Z"):
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value)
    except Exception:
        return None


def build_message_fragments(message: str, max_fragments: int = 5) -> List[str]:
    normalized = message.replace("\r", "\n")
    fragments: List[str] = []
    seen: set[str] = set()

    # Preserve explicit ticket anchors such as "[TICKET=... ]".
    for match in re.findall(r"(?i)\[ticket\s*=\s*([^\]\s]{6,128})\]", normalized):
        token = safe_single_line(match)
        if len(token) < VERIFY_MIN_FRAGMENT_LEN:
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        fragments.append(token)
        if len(fragments) >= max_fragments:
            return fragments

    # Preserve full ticket id so verification has a high-specificity anchor.
    for match in re.findall(r"[Tt]\d{8}-\d{9}-[0-9a-fA-F]{8}", normalized):
        token = safe_single_line(match)
        if len(token) < VERIFY_MIN_FRAGMENT_LEN:
            continue
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        fragments.append(token)
        if len(fragments) >= max_fragments:
            return fragments

    for line in normalized.split("\n"):
        token = safe_single_line(line)
        if len(token) < 3:
            continue
        token = token[:96]
        key = token.lower()
        if key in seen:
            continue
        seen.add(key)
        fragments.append(token)
        if len(fragments) >= max_fragments:
            return fragments

    body = safe_single_line(normalized)
    if len(body) >= 2 and len(fragments) < max_fragments:
        short_head = body[:96]
        key = short_head.lower()
        if key not in seen:
            seen.add(key)
            fragments.append(short_head)

    # Add semantic chunks (letters/digits/CJK) to survive punctuation or
    # markdown rendering differences in transcript text.
    for token in re.findall(r"[0-9A-Za-z\u4e00-\u9fff]{6,}", body):
        compact = token[:64]
        key = compact.lower()
        if key in seen:
            continue
        seen.add(key)
        fragments.append(compact)
        if len(fragments) >= max_fragments:
            return fragments

    return fragments


def classify_retry_reason(reason: str) -> str:
    token = safe_single_line(reason).lower()
    if not token:
        return "transient"

    if "operation_timeout" in token:
        return "focus"

    fatal_markers = [
        "ambiguous_candidates",
        "no_candidate_after_strict_filter",
        "window_not_bound",
        "chat_input_not_found",
        "invalid_main_window_handle",
        "unsupported_platform",
        "message_too_long",
        "environment_preflight_failed",
        "ticket_fingerprint_missing_in_message",
        "ticket_fingerprint_mismatch_pre_submit",
    ]
    focus_markers = [
        "foreground_not_acquired",
        "window_activation_failed",
        "window_minimized",
    ]
    clipboard_markers = [
        "clipboard",
        "paste_verification_failed",
    ]
    network_markers = [
        "network",
        "dns",
        "socket",
        "connection",
        "timed out",
    ]
    resource_markers = [
        "memory",
        "resource",
        "out of memory",
        "insufficient",
    ]

    for marker in fatal_markers:
        if marker in token:
            return "fatal"
    for marker in focus_markers:
        if marker in token:
            return "focus"
    for marker in clipboard_markers:
        if marker in token:
            return "clipboard"
    for marker in network_markers:
        if marker in token:
            return "network"
    for marker in resource_markers:
        if marker in token:
            return "resource"
    return "transient"


def next_retry_delay_sec(reason: str, attempt: int) -> float:
    category = classify_retry_reason(reason)
    if category == "fatal":
        return 0.0
    if category == "resource":
        return 0.0
    if category == "focus":
        return min(2.5, 0.35 * max(1, attempt))
    if category == "clipboard":
        return min(3.0, 0.45 * max(1, attempt))
    if category == "network":
        return min(6.0, 0.40 * (2 ** max(0, attempt - 1)))
    return min(4.0, 0.50 * max(1, attempt))


def effective_retry_limit(base_limit: int, reason: str, hard_cap: int = 7) -> int:
    category = classify_retry_reason(reason)
    if category == "fatal":
        return 1
    if category == "resource":
        return 1
    if category in {"focus", "clipboard"}:
        return min(hard_cap, base_limit + 2)
    if category == "network":
        return min(hard_cap, base_limit + 3)
    return min(hard_cap, base_limit + 1)


def _read_memory_status_ex() -> Optional[Any]:
    if os.name != "nt":
        return None

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    try:
        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return status
    except Exception:
        return None


def get_available_memory_mb() -> int:
    status = _read_memory_status_ex()
    if status is None:
        return 0
    try:
        return int(status.ullAvailPhys / (1024 * 1024))
    except Exception:
        return 0


def get_memory_load_percent() -> int:
    status = _read_memory_status_ex()
    if status is None:
        return 0
    try:
        return int(status.dwMemoryLoad)
    except Exception:
        return 0


def derive_runtime_adaptive_profile(
    request: SendRequest,
    preflight_details: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    details = preflight_details if isinstance(preflight_details, dict) else {}
    available_mb = int(details.get("available_memory_mb", 0) or 0)
    memory_load_percent = int(details.get("memory_load_percent", 0) or 0)

    requested_pre_send_delay_ms = max(0, min(60000, int(request.pre_send_delay_ms)))
    requested_timeout_sec = max(0.8, float(request.timeout_per_step))

    profile: Dict[str, Any] = {
        "enabled": bool(request.adaptive_load_enabled),
        "mode": "strict",
        "high_load": False,
        "low_load": False,
        "thresholds": {
            "high_load_memory_percent": int(request.adaptive_high_load_memory_percent),
            "high_load_available_mb": int(request.adaptive_high_load_available_mb),
            "low_load_memory_percent": int(request.adaptive_low_load_memory_percent),
            "low_load_available_mb": int(request.adaptive_low_load_available_mb),
        },
        "available_memory_mb": available_mb,
        "memory_load_percent": memory_load_percent,
        "pre_send_delay_ms_requested": requested_pre_send_delay_ms,
        "pre_send_delay_ms_effective": requested_pre_send_delay_ms,
        "retry_delay_scale": 1.0,
        "verify_timeout_sec": requested_timeout_sec,
        "verify_poll_interval_sec": VERIFY_POLL_INTERVAL_SEC,
        "require_transcript_confirmation": bool(request.require_transcript_confirmation),
        "verification_level": "strict",
    }

    if not bool(request.adaptive_load_enabled):
        profile["mode"] = "adaptive-disabled"
        return profile

    high_memory_percent_threshold = max(50, min(99, int(request.adaptive_high_load_memory_percent)))
    high_available_mb_threshold = max(128, min(16384, int(request.adaptive_high_load_available_mb)))
    low_memory_percent_threshold = max(30, min(95, int(request.adaptive_low_load_memory_percent)))
    low_available_mb_threshold = max(256, min(32768, int(request.adaptive_low_load_available_mb)))

    if low_memory_percent_threshold >= high_memory_percent_threshold:
        low_memory_percent_threshold = max(30, high_memory_percent_threshold - 5)
    if low_available_mb_threshold <= high_available_mb_threshold:
        low_available_mb_threshold = min(32768, high_available_mb_threshold + 256)

    profile["thresholds"] = {
        "high_load_memory_percent": high_memory_percent_threshold,
        "high_load_available_mb": high_available_mb_threshold,
        "low_load_memory_percent": low_memory_percent_threshold,
        "low_load_available_mb": low_available_mb_threshold,
    }

    high_load = False
    if memory_load_percent > 0 and memory_load_percent >= high_memory_percent_threshold:
        high_load = True
    if available_mb > 0 and available_mb <= high_available_mb_threshold:
        high_load = True

    low_load = False
    if not high_load and memory_load_percent > 0 and memory_load_percent <= low_memory_percent_threshold:
        if available_mb == 0 or available_mb >= low_available_mb_threshold:
            low_load = True

    if high_load:
        profile["mode"] = "high-load-adaptive"
        profile["high_load"] = True
        profile["retry_delay_scale"] = ADAPTIVE_HIGH_LOAD_RETRY_DELAY_SCALE
        profile["verify_timeout_sec"] = min(
            ADAPTIVE_HIGH_LOAD_VERIFY_TIMEOUT_MAX_SEC,
            max(1.2, requested_timeout_sec * ADAPTIVE_HIGH_LOAD_VERIFY_TIMEOUT_SCALE),
        )
        profile["verify_poll_interval_sec"] = ADAPTIVE_HIGH_LOAD_POLL_INTERVAL_SEC
        profile["pre_send_delay_ms_effective"] = min(
            requested_pre_send_delay_ms,
            ADAPTIVE_HIGH_LOAD_MAX_PRE_SEND_DELAY_MS,
        )
        profile["require_transcript_confirmation"] = False
        profile["verification_level"] = "relaxed"
        return profile

    if low_load:
        profile["mode"] = "low-load-strict"
        profile["low_load"] = True
    else:
        profile["mode"] = "normal-strict"

    return profile


def get_vscode_window_summaries(title_regex: str, workspace_hint: str = "") -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    try:
        handles = list(findwindows.find_windows(title_re=title_regex))
    except Exception:
        return summaries

    seen_pids: set[int] = set()
    for hwnd in handles[:30]:
        try:
            app = Application(backend="uia").connect(handle=hwnd)
            window = app.window(handle=hwnd)
            title = safe_single_line(window.window_text())
            pid = int(window.process_id())
        except Exception:
            continue

        if workspace_hint and workspace_hint.lower() not in title.lower():
            continue

        if pid in seen_pids:
            continue
        seen_pids.add(pid)

        summaries.append(
            {
                "hwnd": int(hwnd),
                "pid": pid,
                "title": title[:120],
                "copilot_title_hint": ("copilot" in title.lower() or "chat" in title.lower()),
            }
        )

    return summaries


def is_process_alive(pid: int) -> bool:
    if pid <= 0:
        return False

    if os.name != "nt":
        return False

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    try:
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    except Exception:
        return False


class DispatchLedger:
    def __init__(self, ledger_path: Path, logger: logging.Logger):
        self.path = ledger_path
        self.logger = logger

    def _read_lines(self, max_scan_lines: int) -> List[str]:
        if not self.path.exists():
            return []

        try:
            lines = self.path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as exc:
            self.logger.warning("ledger_read_failed detail=%s", safe_single_line(exc))
            return []

        return lines[-max_scan_lines:]

    def append(self, payload: Dict[str, Any]) -> None:
        ensure_parent(self.path)
        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")

    def get_last_record(self, token: str, max_scan_lines: int = 5000) -> Optional[Dict[str, Any]]:
        lines = self._read_lines(max_scan_lines)
        if not lines:
            return None

        for raw_line in reversed(lines):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                item = json.loads(raw_line)
            except Exception:
                continue
            if safe_single_line(item.get("token")) == token:
                return item
        return None

    def get_recent_entries(self, max_scan_lines: int = 5000) -> List[Dict[str, Any]]:
        lines = self._read_lines(max_scan_lines)
        if not lines:
            return []

        entries: List[Dict[str, Any]] = []
        for raw_line in lines:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                item = json.loads(raw_line)
            except Exception:
                continue
            entries.append(item)
        return entries

    def get_circuit_state(self, threshold: int, cooldown_sec: int, max_scan_lines: int = 5000) -> Dict[str, Any]:
        entries = self.get_recent_entries(max_scan_lines=max_scan_lines)
        if not entries:
            return {
                "open": False,
                "consecutive_failures": 0,
                "last_failure_at": "",
                "remaining_cooldown_sec": 0,
            }

        consecutive_failures = 0
        last_failure_at = ""
        now_utc = datetime.now(timezone.utc)

        for item in reversed(entries):
            if safe_single_line(item.get("phase")) != "result":
                continue

            status = safe_single_line(item.get("status"))
            if status in {"confirmed", "idempotent"}:
                break

            if status in {"failed", "uncertain"}:
                consecutive_failures += 1
                if not last_failure_at:
                    last_failure_at = safe_single_line(item.get("at"))
            else:
                break

        if consecutive_failures < max(1, int(threshold)):
            return {
                "open": False,
                "consecutive_failures": consecutive_failures,
                "last_failure_at": last_failure_at,
                "remaining_cooldown_sec": 0,
            }

        last_failure_dt = parse_utc_text(last_failure_at)
        if last_failure_dt is None:
            return {
                "open": True,
                "consecutive_failures": consecutive_failures,
                "last_failure_at": last_failure_at,
                "remaining_cooldown_sec": max(1, int(cooldown_sec)),
            }

        elapsed_sec = max(0, int((now_utc - last_failure_dt).total_seconds()))
        remaining = max(0, int(cooldown_sec) - elapsed_sec)
        return {
            "open": remaining > 0,
            "consecutive_failures": consecutive_failures,
            "last_failure_at": last_failure_at,
            "remaining_cooldown_sec": remaining,
        }


class CopilotChatSender:
    def __init__(self, policy: WindowBindingPolicy, timeout_per_step: float, logger: logging.Logger):
        self.policy = policy
        self.timeout = timeout_per_step
        self.logger = logger
        self.app: Optional[Application] = None
        self.main_window = None
        self.chat_root = None
        self.chat_input = None
        self.window_activation_attempts = 0
        self.last_foreground_probe: Dict[str, Any] = {}
        self.restore_window_handles: List[int] = []

    @staticmethod
    def _safe_handle(wrapper: Any) -> int:
        try:
            return int(wrapper.handle)
        except Exception:
            return 0

    @staticmethod
    def _safe_pid(wrapper: Any) -> int:
        try:
            return int(wrapper.process_id())
        except Exception:
            try:
                return int(wrapper.element_info.process_id)
            except Exception:
                return 0

    @staticmethod
    def _safe_window_text(wrapper: Any) -> str:
        try:
            return safe_single_line(wrapper.window_text())
        except Exception:
            return ""

    @staticmethod
    def _safe_automation_id(wrapper: Any) -> str:
        try:
            return safe_single_line(wrapper.element_info.automation_id)
        except Exception:
            return ""

    @staticmethod
    def _safe_control_type(wrapper: Any) -> str:
        try:
            return safe_single_line(wrapper.element_info.control_type).lower()
        except Exception:
            try:
                return safe_single_line(wrapper.friendly_class_name()).lower()
            except Exception:
                return ""

    def _wrapper_is_usable(self, wrapper: Any) -> bool:
        try:
            return bool(wrapper.exists(timeout=1)) and bool(wrapper.is_visible())
        except Exception:
            return False

    def _is_window_minimized(self) -> bool:
        if self.main_window is None:
            return False
        hwnd = self._safe_handle(self.main_window)
        if hwnd <= 0:
            return False
        try:
            user32 = ctypes.windll.user32
            return bool(user32.IsIconic(hwnd))
        except Exception:
            return False

    def _prepare_window_for_foreground(self, user32: Any, hwnd: int) -> str:
        if bool(user32.IsIconic(hwnd)):
            user32.ShowWindow(hwnd, SW_RESTORE)
            return "restored_from_minimized"

        if bool(user32.IsZoomed(hwnd)):
            user32.ShowWindow(hwnd, SW_SHOWMAXIMIZED)
            return "kept_maximized"

        user32.ShowWindow(hwnd, SW_SHOW)
        return "shown_normal"

    @staticmethod
    def _safe_hwnd_text(user32: Any, hwnd: int, max_chars: int = 512) -> str:
        if hwnd <= 0:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(max_chars)
            user32.GetWindowTextW(hwnd, buf, max_chars)
            return safe_single_line(buf.value)
        except Exception:
            return ""

    @staticmethod
    def _safe_hwnd_class_name(user32: Any, hwnd: int, max_chars: int = 256) -> str:
        if hwnd <= 0:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(max_chars)
            user32.GetClassNameW(hwnd, buf, max_chars)
            return safe_single_line(buf.value)
        except Exception:
            return ""

    @staticmethod
    def _safe_hwnd_pid(user32: Any, hwnd: int) -> int:
        if hwnd <= 0:
            return 0
        try:
            pid_ref = ctypes.c_ulong(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_ref))
            return int(pid_ref.value)
        except Exception:
            return 0

    def _collect_hwnd_probe(self, user32: Any, hwnd: int) -> Dict[str, Any]:
        return {
            "hwnd": int(hwnd),
            "pid": self._safe_hwnd_pid(user32, hwnd),
            "title": self._safe_hwnd_text(user32, hwnd)[:120],
            "class": self._safe_hwnd_class_name(user32, hwnd)[:80],
        }

    def _resolve_restore_anchor_handle(self, user32: Any) -> int:
        candidates: List[int] = []

        if self.main_window is not None:
            candidates.append(self._safe_handle(self.main_window))
        elif self.policy.expected_handle > 0:
            candidates.append(int(self.policy.expected_handle))
        else:
            # main_window not bound yet — locate VS Code via title regex
            # so that capture always anchors on VS Code, not the current
            # foreground window (which could be an overlayed window).
            try:
                found = list(findwindows.find_windows(title_re=self.policy.title_regex))
                for h in found[:8]:
                    candidates.append(int(h))
            except Exception:
                pass

        if int(self.policy.expected_handle) > 0:
            candidates.append(int(self.policy.expected_handle))

        try:
            candidates.append(int(user32.GetForegroundWindow()))
        except Exception:
            pass

        seen: set[int] = set()
        for hwnd in candidates:
            if hwnd <= 0 or hwnd in seen:
                continue
            seen.add(hwnd)
            try:
                if bool(user32.IsWindow(hwnd)):
                    return int(hwnd)
            except Exception:
                continue

        return 0

    def _is_restore_candidate(
        self,
        user32: Any,
        hwnd: int,
        probe: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        if hwnd <= 0:
            return False, "invalid_handle"

        info = probe or self._collect_hwnd_probe(user32, hwnd)
        class_name = safe_single_line(info.get("class", "")).lower()
        title = safe_single_line(info.get("title", ""))
        title_lower = title.lower()

        try:
            is_visible = bool(user32.IsWindowVisible(hwnd))
        except Exception:
            return False, "visibility_probe_failed"

        try:
            is_iconic = bool(user32.IsIconic(hwnd))
        except Exception:
            is_iconic = False

        if (not is_visible) and (not is_iconic):
            return False, "not_visible"

        if class_name == "#32770" and "visual studio code" in title_lower:
            return False, "skip_vscode_dialog"

        if class_name in RESTORE_SKIP_CLASSES:
            return False, f"skip_class={class_name}"

        if "qwindowtoolsavebits" in class_name:
            # Some third-party apps expose their main UI through this Qt class.
            # Allow visible/iconic titled windows so restore can bring users back.
            if not title_lower:
                # Untitled Qt windows — allow if visible and iconic.
                if not is_visible and not is_iconic:
                    return False, "skip_class=qwindowtoolsavebits_not_visible"
                if is_iconic:
                    return True, "candidate_qwindowtoolsavebits_untitled_iconic"
                return True, "candidate_qwindowtoolsavebits_untitled"
            if title_lower not in RESTORE_SKIP_TITLES and (is_visible or is_iconic):
                if (not is_visible) and is_iconic:
                    return True, "candidate_qwindowtoolsavebits_iconic"
                return True, "candidate_qwindowtoolsavebits"
            return False, "skip_class=qwindowtoolsavebits"

        if "toolsavebits" in class_name or "tooltipsavebits" in class_name:
            return False, "skip_class=toolsavebits"

        if not title_lower:
            # Some dialogue/chat windows (e.g. Kimi, Electron apps) may have an
            # empty or undetectable title but are still valid restore candidates.
            # Reject only fully hidden windows, system skip classes, and known
            # dialog/proxy shells.
            if (not is_visible) and (not is_iconic):
                return False, "not_visible"
            if class_name in RESTORE_SKIP_CLASSES:
                return False, f"skip_class_untitled={class_name}"
            if "tooltipsavebits" in class_name or "toolsavebits" in class_name:
                return False, f"skip_class_untitled={class_name}"
            if class_name.startswith("#32770"):
                return False, f"skip_dialog_untitled={class_name}"
            if class_name in ("ime", "msctfime ui", "cicerouiwndframe", "windowsdashboard"):
                return False, f"skip_system_class_untitled={class_name}"
            if is_iconic:
                return True, "candidate_untitled_iconic"
            return True, "candidate_untitled"

        if title_lower in RESTORE_SKIP_TITLES:
            return False, f"skip_title={title_lower}"

        if (not is_visible) and is_iconic:
            return True, "candidate_iconic_not_visible"

        return True, "candidate"

    def capture_previous_foreground_windows(self, max_count: int) -> Dict[str, Any]:
        user32 = ctypes.windll.user32
        requested = max(1, min(30, int(max_count)))

        anchor_hwnd = self._resolve_restore_anchor_handle(user32)
        if anchor_hwnd <= 0:
            return {"handles": [], "trace": [], "requested": requested, "scanned": 0}

        # Enumerate all top-level windows in z-order (topmost first, then
        # normal windows).  Find the anchor (VS Code) position and collect
        # only windows that appear above it — these are the true overlayed
        # windows.  This ensures topmost windows (VirtualBox, etc.) are
        # captured while windows below VS Code are excluded.
        collected: List[int] = []

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        def enum_proc(hwnd: int, _lparam: int) -> bool:
            if hwnd > 0:
                collected.append(hwnd)
            return True

        try:
            enum_win = user32.EnumWindows
            enum_win.argtypes = [
                ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int),
                ctypes.c_int,
            ]
            enum_win.restype = ctypes.c_bool
            enum_win(enum_proc, 0)
        except Exception:
            pass

        anchor_idx: Optional[int] = None
        for i, hwnd in enumerate(collected):
            if hwnd == anchor_hwnd:
                anchor_idx = i
                break

        # Windows before the anchor are above it in z-order. Windows after
        # anchor are below and are only considered when explicit fallback is on.
        if anchor_idx is not None:
            raw_above = collected[:anchor_idx]
            raw_below = collected[anchor_idx + 1 :]
        else:
            raw_above = collected[:]
            raw_below = []

        # Build trace and filter candidates, preserving z-order.
        handles: List[int] = []
        traces: List[Dict[str, Any]] = []
        seen: set[int] = {anchor_hwnd}

        anchor_probe = self._collect_hwnd_probe(user32, anchor_hwnd)
        anchor_probe["restore_candidate"] = False
        anchor_probe["skip_reason"] = "anchor_window"
        traces.append(anchor_probe)

        scanned = 0
        def scan_candidates(raw_list: List[int], scope: str, max_scan_count: int) -> None:
            nonlocal scanned
            for hwnd in raw_list:
                if scanned >= max_scan_count:
                    break
                if len(handles) >= requested:
                    break
                if hwnd <= 0 or hwnd in seen:
                    continue
                seen.add(hwnd)
                scanned += 1

                probe = self._collect_hwnd_probe(user32, hwnd)
                probe["scan_scope"] = scope
                candidate, candidate_reason = self._is_restore_candidate(user32, hwnd, probe)
                probe["restore_candidate"] = bool(candidate)
                if not candidate:
                    probe["skip_reason"] = candidate_reason
                else:
                    probe["candidate_reason"] = candidate_reason
                    handles.append(hwnd)
                traces.append(probe)

        max_scan_above = max(40, requested * 8)
        scan_candidates(raw_above, "above_anchor", max_scan_above)

        below_anchor_fallback_used = False
        # Guard against restore pollution: only fallback to below-anchor scan
        # when above-anchor capture is empty.
        if (
            len(handles) < 1
            and bool(self.policy.allow_below_anchor_restore_fallback)
            and raw_below
        ):
            below_anchor_fallback_used = True
            max_scan_below = max(12, (requested - len(handles)) * 8)
            scan_candidates(raw_below, "below_anchor_fallback", max_scan_below)

        self.restore_window_handles = list(handles)

        return {
            "handles": handles,
            "trace": traces,
            "requested": requested,
            "scanned": scanned,
            "below_anchor_fallback_used": below_anchor_fallback_used,
        }

    def _activate_window_handle(self, user32: Any, hwnd: int) -> Tuple[bool, str]:
        if hwnd <= 0:
            return False, "invalid_handle"

        state_action = self._prepare_window_for_foreground(user32, hwnd)
        try:
            user32.SetForegroundWindow(hwnd)
            try:
                user32.SwitchToThisWindow(hwnd, True)
            except Exception:
                pass
            time.sleep(0.08)
        except Exception as exc:
            return False, f"activate_failed:{safe_single_line(exc)}"

        current_fg = int(user32.GetForegroundWindow())
        if current_fg == hwnd:
            time.sleep(RESTORE_STABLE_FOREGROUND_DELAY_SEC)
            stable_fg = int(user32.GetForegroundWindow())
            if stable_fg == hwnd:
                return True, f"activated state={state_action}"
            return False, f"unstable_foreground fg={stable_fg} state={state_action}"
        return False, f"still_not_foreground fg={current_fg} state={state_action}"

    def restore_previous_foreground_window(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "attempted": 0,
            "succeeded": False,
            "succeeded_count": 0,
            "restored_handle": 0,
            "restored_handles": [],
            "activation_trace": [],
            "final_foreground_handle": 0,
            "reason": "",
        }

        if not self.restore_window_handles:
            result["reason"] = "no_captured_windows"
            return result

        user32 = ctypes.windll.user32
        # Handles are in top-to-bottom z-order.  Restore in reverse (bottom to
        # top) so each subsequent activation brings a higher window forward,
        # ending with the true topmost window as the final foreground.
        restore_order = list(reversed(self.restore_window_handles))
        last_detail = ""
        activation_trace: List[Dict[str, Any]] = []
        for hwnd in restore_order:
            target_probe = self._collect_hwnd_probe(user32, int(hwnd))
            result["attempted"] = int(result["attempted"]) + 1
            window_ok = False
            for retry_index in range(1, RESTORE_PER_WINDOW_MAX_ATTEMPTS + 1):
                ok, detail = self._activate_window_handle(user32, int(hwnd))
                current_fg = int(user32.GetForegroundWindow())
                activation_trace.append(
                    {
                        "hwnd": int(hwnd),
                        "pid": int(target_probe.get("pid", 0)),
                        "title": safe_single_line(target_probe.get("title", ""))[:120],
                        "class": safe_single_line(target_probe.get("class", ""))[:80],
                        "attempt": int(retry_index),
                        "ok": bool(ok),
                        "detail": safe_single_line(detail),
                        "foreground_after": current_fg,
                    }
                )
                last_detail = detail
                if ok:
                    window_ok = True
                    break
                time.sleep(min(0.24, 0.08 * retry_index))

            if window_ok:
                result["succeeded_count"] = int(result["succeeded_count"]) + 1
                result["succeeded"] = bool(int(result["succeeded_count"]) > 0)
                result["restored_handle"] = int(hwnd)
                restored_handles = list(result.get("restored_handles", []))
                restored_handles.append(int(hwnd))
                result["restored_handles"] = restored_handles
                time.sleep(RESTORE_INTER_WINDOW_DELAY_SEC)

        result["activation_trace"] = activation_trace

        attempted = int(result.get("attempted", 0))
        succeeded_count = int(result.get("succeeded_count", 0))
        if succeeded_count <= 0:
            result["reason"] = "restore_attempts_exhausted"
        elif succeeded_count >= attempted and attempted > 0:
            result["reason"] = f"restore_sequence_completed count={succeeded_count}"
        else:
            result["reason"] = (
                f"restore_sequence_partial success={succeeded_count}/{attempted};last={safe_single_line(last_detail)}"
            )

        result["final_foreground_handle"] = int(user32.GetForegroundWindow())
        return result

    def _collect_foreground_probe(self, user32: Any, expected_hwnd: int) -> Dict[str, Any]:
        fg_hwnd = int(user32.GetForegroundWindow())
        fg_probe = self._collect_hwnd_probe(user32, fg_hwnd)
        probe = {
            "expected_hwnd": int(expected_hwnd),
            "foreground_hwnd": int(fg_probe.get("hwnd", 0)),
            "foreground_pid": int(fg_probe.get("pid", 0)),
            "foreground_title": safe_single_line(fg_probe.get("title", ""))[:120],
            "foreground_class": safe_single_line(fg_probe.get("class", ""))[:80],
        }
        return probe

    @staticmethod
    def _format_foreground_probe(probe: Dict[str, Any]) -> str:
        return "hwnd={0} pid={1} class={2} title={3}".format(
            int(probe.get("foreground_hwnd", 0)),
            int(probe.get("foreground_pid", 0)),
            safe_single_line(probe.get("foreground_class", "")),
            safe_single_line(probe.get("foreground_title", "")),
        )

    def ensure_main_window_foreground(self) -> Tuple[bool, str]:
        if self.main_window is None:
            return False, "window_not_bound"

        hwnd = self._safe_handle(self.main_window)
        if hwnd <= 0:
            return False, "invalid_main_window_handle"

        try:
            self.window_activation_attempts += 1
            user32 = ctypes.windll.user32

            if bool(self.policy.active_window_only):
                fg = int(user32.GetForegroundWindow())
                if fg != hwnd:
                    probe = self._collect_foreground_probe(user32, hwnd)
                    self.last_foreground_probe = probe
                    blocker = self._format_foreground_probe(probe)
                    self.logger.warning("active_window_only_blocked %s", blocker)
                    return False, f"active_window_only_blocked hwnd={hwnd} fg={fg} blocker={blocker}"

                self.last_foreground_probe = {}
                try:
                    self.main_window.set_focus()
                except Exception:
                    pass
                return True, "foreground_already_active_active_window_only"

            state_action = self._prepare_window_for_foreground(user32, hwnd)
            time.sleep(0.05)
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.10)

            try:
                self.main_window.set_focus()
            except Exception:
                pass

            fg = int(user32.GetForegroundWindow())
            if fg != hwnd:
                probe = self._collect_foreground_probe(user32, hwnd)
                self.last_foreground_probe = probe
                blocker = self._format_foreground_probe(probe)
                self.logger.warning("foreground_blocked %s", blocker)
                return False, f"foreground_not_acquired hwnd={hwnd} fg={fg} blocker={blocker}"

            self.last_foreground_probe = {}

            return True, f"foreground_acquired hwnd={hwnd} state={state_action}"
        except Exception as exc:
            return False, f"window_activation_failed:{safe_single_line(exc)}"

    def ensure_window_foreground_with_retry(self, max_attempts: int = 3) -> Tuple[bool, str]:
        if self.main_window is None:
            return False, "window_not_bound"

        safe_attempts = max(1, int(max_attempts))
        total_attempts = safe_attempts + FOREGROUND_BLOCKED_EXTRA_ATTEMPTS
        last_detail = "foreground_retry_exhausted"
        attempts_used = 0
        hwnd = self._safe_handle(self.main_window)
        user32 = ctypes.windll.user32

        for attempt in range(1, total_attempts + 1):
            attempts_used = attempt
            ok, detail = self.ensure_main_window_foreground()
            if ok:
                return True, f"foreground_acquired_on_attempt={attempt}"

            last_detail = detail
            is_focus_blocked = (
                "foreground_not_acquired" in detail
                or "active_window_only_blocked" in detail
            )
            if attempt >= safe_attempts and not is_focus_blocked:
                break

            if bool(self.policy.active_window_only):
                time.sleep(min(0.35, 0.10 * attempt))
                continue

            try:
                if hwnd > 0:
                    self._prepare_window_for_foreground(user32, hwnd)
                    try:
                        user32.SwitchToThisWindow(hwnd, True)
                    except Exception:
                        pass
                    user32.SetForegroundWindow(hwnd)
            except Exception:
                pass

            time.sleep(min(0.35, 0.10 * attempt))

        return False, f"foreground_failed_after_{attempts_used}_attempts:{last_detail}"

    def run_ui_health_check(self) -> Tuple[bool, str, Dict[str, Any]]:
        details: Dict[str, Any] = {
            "window_bound": self.main_window is not None,
            "chat_input_bound": self.chat_input is not None,
            "window_minimized": self._is_window_minimized(),
            "window_activation_attempts": self.window_activation_attempts,
        }

        if self.main_window is None:
            return False, "window_not_bound", details
        if self.chat_input is None:
            return False, "chat_input_not_bound", details

        activated, activation_detail = self.ensure_window_foreground_with_retry(
            max_attempts=WINDOW_FOREGROUND_MAX_ATTEMPTS
        )
        details["activation_detail"] = activation_detail
        details["window_activation_attempts"] = self.window_activation_attempts
        if self.last_foreground_probe:
            details["foreground_probe"] = dict(self.last_foreground_probe)
        if not activated:
            return False, activation_detail, details

        try:
            details["chat_input_enabled"] = bool(self.chat_input.is_enabled())
            details["chat_input_visible"] = bool(self.chat_input.is_visible())
        except Exception:
            details["chat_input_enabled"] = False
            details["chat_input_visible"] = False

        if not details["chat_input_enabled"] or not details["chat_input_visible"]:
            return False, "chat_input_unavailable", details

        return True, "ui_health_ok", details

    def _discover_window_handles(self) -> Tuple[List[int], str]:
        if self.policy.expected_handle > 0:
            return [self.policy.expected_handle], ""

        try:
            handles = list(findwindows.find_windows(title_re=self.policy.title_regex))
        except Exception as exc:
            return [], f"find_windows_failed:{safe_single_line(exc)}"

        if not handles:
            return [], "no_vscode_window_found"
        return handles, ""

    def _candidate_matches_policy(self, title: str, pid: int) -> bool:
        if self.policy.expected_pid > 0 and pid != self.policy.expected_pid:
            return False

        if self.policy.workspace_hint:
            hint = self.policy.workspace_hint.lower()
            if hint not in title.lower():
                return False
        return True

    def _build_window_candidate(self, hwnd: int) -> Optional[WindowCandidate]:
        try:
            app = Application(backend="uia").connect(handle=hwnd)
            window = app.window(handle=hwnd)
        except Exception:
            return None

        if not self._wrapper_is_usable(window):
            return None

        title = self._safe_window_text(window)
        pid = self._safe_pid(window)
        if not self._candidate_matches_policy(title, pid):
            return None

        return (hwnd, app, window, title, pid)

    def _collect_window_candidates(self, handles: List[int]) -> List[WindowCandidate]:
        candidates: List[WindowCandidate] = []
        for hwnd in handles:
            candidate = self._build_window_candidate(hwnd)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    @staticmethod
    def _describe_candidates(candidates: List[WindowCandidate]) -> str:
        parts: List[str] = []
        for hwnd, _app, _window, title, pid in candidates[:MAX_AMBIGUOUS_CANDIDATES]:
            parts.append(f"hwnd={hwnd} pid={pid} title={title[:80]}")
        return ";".join(parts)

    def _bind_window_candidate(self, candidate: WindowCandidate) -> None:
        hwnd, app, window, title, pid = candidate
        self.app = app
        self.main_window = window
        self.logger.info("window_bound hwnd=%s pid=%s title=%s", hwnd, pid, title)

    def connect_to_vscode(self) -> Tuple[bool, str]:
        handles, handle_reason = self._discover_window_handles()
        if not handles:
            return False, handle_reason

        candidates = self._collect_window_candidates(handles)

        if not candidates:
            return False, "no_candidate_after_strict_filter"

        if len(candidates) > 1:
            # Prefer the active VS Code window when multiple strict candidates exist.
            # This avoids false ambiguity when the same process has multiple UIA roots.
            try:
                foreground_hwnd = int(ctypes.windll.user32.GetForegroundWindow())
            except Exception:
                foreground_hwnd = 0

            if foreground_hwnd > 0:
                for candidate in candidates:
                    if int(candidate[0]) == foreground_hwnd:
                        self._bind_window_candidate(candidate)
                        activated, activation_detail = self.ensure_window_foreground_with_retry(
                            max_attempts=WINDOW_FOREGROUND_MAX_ATTEMPTS
                        )
                        if not activated:
                            return False, activation_detail
                        return True, "bound_foreground_candidate"

            descriptor = self._describe_candidates(candidates)
            return False, f"ambiguous_candidates:{descriptor}"

        self._bind_window_candidate(candidates[0])

        activated, activation_detail = self.ensure_window_foreground_with_retry(
            max_attempts=WINDOW_FOREGROUND_MAX_ATTEMPTS
        )
        if not activated:
            return False, activation_detail

        return True, "bound"

    def _collect_chat_roots(self) -> List[Any]:
        if self.main_window is None:
            return []

        roots: List[Any] = []
        seen: set[int] = set()

        selectors = [
            ("Pane", CHAT_ROOT_TITLE_REGEX),
            ("Group", CHAT_ROOT_TITLE_REGEX),
            ("Document", CHAT_ROOT_TITLE_REGEX),
            ("Custom", CHAT_ROOT_TITLE_REGEX),
        ]

        for control_type, title_re in selectors:
            try:
                found = self.main_window.descendants(control_type=control_type, title_re=title_re)
            except Exception:
                continue

            for item in found:
                handle = self._safe_handle(item)
                if handle > 0 and handle in seen:
                    continue
                if not self._wrapper_is_usable(item):
                    continue
                if handle > 0:
                    seen.add(handle)
                roots.append(item)

        if roots:
            return roots

        semantic_selectors = ["Pane", "Group", "Document", "Custom"]
        for control_type in semantic_selectors:
            try:
                found = self.main_window.descendants(control_type=control_type)
            except Exception:
                continue

            for item in found[:600]:
                handle = self._safe_handle(item)
                if handle > 0 and handle in seen:
                    continue
                if not self._wrapper_is_usable(item):
                    continue

                title = self._safe_window_text(item)
                auto_id = self._safe_automation_id(item)
                if not (
                    contains_hint_token(title, CHAT_ROOT_HINT_TOKENS)
                    or contains_hint_token(auto_id, CHAT_ROOT_HINT_TOKENS)
                ):
                    continue

                if handle > 0:
                    seen.add(handle)
                roots.append(item)

        return roots

    def _invoke_chat_root_recovery_shortcut(self) -> bool:
        if self.main_window is None:
            return False

        try:
            self.main_window.set_focus()
            time.sleep(0.08)
            # VS Code default: open/focus Chat view.
            self.main_window.type_keys("^!i", set_foreground=True)
            time.sleep(0.45)
            self.logger.info("chat_root_recovery_shortcut_invoked shortcut=Ctrl+Alt+I")
            return True
        except Exception as exc:
            self.logger.warning("chat_root_recovery_shortcut_failed detail=%s", safe_single_line(exc))
            return False

    def _invoke_vscode_command_cli(self, command_id: str) -> bool:
        """Execute a VS Code command via `code --command`, avoiding fragile
        keyboard-typing into the command palette.  Returns True if the CLI
        reports success, False otherwise."""
        try:
            import subprocess
            import shutil
            # Look up `code` CLI in PATH first, then common install locations.
            code_path = shutil.which("code") or shutil.which("code.cmd")
            if not code_path:
                for candidate in (
                    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code"),
                    os.path.expandvars(r"%PROGRAMFILES%\Microsoft VS Code\bin\code"),
                    os.path.expandvars(r"%PROGRAMFILES(X86)%\Microsoft VS Code\bin\code"),
                ):
                    if os.path.isfile(candidate):
                        code_path = candidate
                        break
            if not code_path:
                self.logger.info("vscode_cli_command_skipped reason=code_not_found")
                return False

            result = subprocess.run(
                [code_path, "--reuse-window", "--command", command_id],
                capture_output=True,
                text=True,
                timeout=15,
            )
            ok = result.returncode == 0
            self.logger.info(
                "vscode_cli_command command=%s ok=%s returncode=%s",
                command_id,
                ok,
                result.returncode,
            )
            if not ok and result.stderr.strip():
                self.logger.info("vscode_cli_stderr=%s", safe_single_line(result.stderr)[:120])
            return ok
        except Exception as exc:
            self.logger.warning(
                "vscode_cli_command_failed command=%s detail=%s",
                command_id,
                safe_single_line(exc),
            )
            return False

    def _invoke_chat_command_palette_action(self, command_id: str) -> bool:
        if self.main_window is None:
            return False

        try:
            self.main_window.set_focus()
            time.sleep(0.08)
            self.main_window.type_keys("^+p", set_foreground=True)
            time.sleep(0.22)
            self.main_window.type_keys("^a{BACKSPACE}", set_foreground=True)
            time.sleep(0.06)
            self.main_window.type_keys(">" + command_id, with_spaces=True, set_foreground=True)
            time.sleep(0.08)
            self.main_window.type_keys("{ENTER}", set_foreground=True)
            time.sleep(0.45)
            self.logger.info("chat_root_recovery_palette_invoked command=%s", safe_single_line(command_id))
            return True
        except Exception as exc:
            self.logger.warning(
                "chat_root_recovery_palette_failed command=%s detail=%s",
                safe_single_line(command_id),
                safe_single_line(exc),
            )
            return False

    @staticmethod
    def _safe_wrapper_rectangle(wrapper: Any) -> Optional[Any]:
        try:
            return wrapper.rectangle()
        except Exception:
            return None

    def _get_edit_rect(self, edit: Any) -> Tuple[Optional[Any], str]:
        try:
            if not edit.is_visible() or not edit.is_enabled():
                return None, "not_visible_or_disabled"
        except Exception:
            return None, "not_visible_or_disabled"

        rect = self._safe_wrapper_rectangle(edit)
        if rect is None:
            return None, "no_geometry"
        return rect, ""

    def _score_root_context(self, root: Any) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        root_title = self._safe_window_text(root)
        root_auto_id = self._safe_automation_id(root)
        if root is not self.main_window:
            score += 25
            reasons.append("inside_subroot")

        title_lower = root_title.lower()
        auto_id_lower = root_auto_id.lower()
        if root is not self.main_window and (
            contains_hint_token(title_lower, CHAT_ROOT_HINT_TOKENS)
            or contains_hint_token(auto_id_lower, CHAT_ROOT_HINT_TOKENS)
        ):
            score += 25
            reasons.append("chat_named_root")

        root_context = " ".join([title_lower, auto_id_lower])
        if any(token in root_context for token in ["terminal", "powershell", "debug console", "output"]):
            score -= 45
            reasons.append("terminal_like_root")

        return score, reasons

    def _derive_chat_root_from_input(self, edit: Any) -> Optional[Any]:
        if self.main_window is None:
            return None

        try:
            current = edit
            main_handle = self._safe_handle(self.main_window)
            main_rect = self._safe_wrapper_rectangle(self.main_window)
            main_width = max(1, (main_rect.right - main_rect.left)) if main_rect else 1
            fallback_root = None
            best_root = None
            best_score = -1
            noisy_label_tokens = {
                "\u6253\u5f00\u804a\u5929",
                "\u663e\u793a\u5efa\u8bae",
                "\u663e\u793a",
                "\u751f\u6210\u4ee3\u7801",
                "\u9009\u62e9\u8bed\u8a00",
                "\u4e0d\u518d\u663e\u793a",
            }

            for _ in range(12):
                parent = current.parent()
                if parent is None:
                    break

                parent_handle = self._safe_handle(parent)
                if parent_handle > 0 and parent_handle == main_handle:
                    break

                rect = self._safe_wrapper_rectangle(parent)
                if fallback_root is None:
                    fallback_root = parent

                if rect is not None:
                    if rect.width() > int(0.97 * main_width):
                        current = parent
                        continue

                    score = 0
                    if rect.width() <= int(0.92 * main_width):
                        score += 10
                    if rect.height() >= 120:
                        score += 6

                    title = self._safe_window_text(parent)
                    auto_id = self._safe_automation_id(parent)
                    if (
                        contains_hint_token(title, CHAT_ROOT_HINT_TOKENS)
                        or contains_hint_token(auto_id, CHAT_ROOT_HINT_TOKENS)
                    ):
                        score += 30

                    visible_nodes = 0
                    long_nodes = 0
                    listitem_nodes = 0
                    noisy_hits = 0
                    for control_type in ("Text", "Document", "ListItem", "Hyperlink"):
                        try:
                            nodes = parent.descendants(control_type=control_type)
                        except Exception:
                            continue

                        for node in nodes[:120]:
                            try:
                                if not node.is_visible():
                                    continue
                                text = safe_single_line(node.window_text())
                                if not text:
                                    continue
                                visible_nodes += 1
                                if len(text) >= 18:
                                    long_nodes += 1
                                if control_type == "ListItem":
                                    listitem_nodes += 1
                                if text.lower() in noisy_label_tokens:
                                    noisy_hits += 1
                            except Exception:
                                continue

                    if visible_nodes >= 4:
                        score += 8
                    score += min(24, long_nodes * 4)
                    score += min(12, listitem_nodes * 2)
                    score -= min(20, noisy_hits * 4)

                    send_bonus, _ = self._score_send_button_affinity(edit, parent)
                    score += send_bonus

                    if score > best_score:
                        best_score = score
                        best_root = parent

                current = parent
        except Exception:
            return None

        if best_root is not None and best_score >= 22:
            return best_root
        return best_root if best_root is not None else fallback_root

    def _is_semantic_input_candidate(self, wrapper: Any) -> bool:
        title = self._safe_window_text(wrapper)
        auto_id = self._safe_automation_id(wrapper)
        control_type = self._safe_control_type(wrapper)

        if (
            contains_hint_token(title, CHAT_INPUT_HINT_TOKENS)
            or contains_hint_token(auto_id, CHAT_INPUT_HINT_TOKENS)
            or contains_hint_token(control_type, CHAT_INPUT_HINT_TOKENS)
        ):
            return True

        try:
            if bool(wrapper.has_keyboard_focus()):
                return True
        except Exception:
            pass

        return False

    def _collect_input_candidates(self, root: Any) -> List[Any]:
        candidates: List[Any] = []
        seen_handles: set[int] = set()
        seen_ids: set[int] = set()

        # Only accept controls within the VS Code process; this excludes Edit
        # /Document/Pane controls from overlaid application windows.
        target_pid = self._safe_pid(self.main_window) if self.main_window is not None else 0

        specs = [
            ("Edit", False),
            ("Document", True),
            ("Pane", True),
            ("Custom", True),
        ]
        for control_type, require_semantic_hint in specs:
            try:
                items = root.descendants(control_type=control_type)
            except Exception:
                continue

            for item in items[:320]:
                handle = self._safe_handle(item)
                if handle > 0:
                    if handle in seen_handles:
                        continue
                    seen_handles.add(handle)
                else:
                    item_id = id(item)
                    if item_id in seen_ids:
                        continue
                    seen_ids.add(item_id)

                # Reject controls that belong to a different process (overlay
                # windows that are not part of VS Code).
                if target_pid > 0:
                    try:
                        item_pid = int(item.process_id())
                    except Exception:
                        item_pid = 0
                    if item_pid > 0 and item_pid != target_pid:
                        continue

                if require_semantic_hint and not self._is_semantic_input_candidate(item):
                    continue
                candidates.append(item)

        return candidates

    def _score_vertical_position(self, rect: Any) -> Tuple[int, List[str]]:
        reasons: List[str] = []
        if self.main_window is None:
            return 0, reasons

        win_rect = self._safe_wrapper_rectangle(self.main_window)
        if win_rect is None:
            return 0, reasons

        win_height = max(1, win_rect.bottom - win_rect.top)
        lower_half_top = win_rect.top + int(0.55 * win_height)
        if rect.top >= lower_half_top:
            reasons.append("lower_half")
            return 20, reasons
        return 0, reasons

    def _score_side_panel_position(self, rect: Any) -> Tuple[int, List[str]]:
        reasons: List[str] = []
        if self.main_window is None:
            return 0, reasons

        win_rect = self._safe_wrapper_rectangle(self.main_window)
        if win_rect is None:
            return 0, reasons

        win_width = max(1, win_rect.right - win_rect.left)
        panel_like = rect.width() <= int(0.68 * win_width)
        right_side = rect.left >= (win_rect.left + int(0.35 * win_width))

        score = 0
        if panel_like:
            score += 10
            reasons.append("side_narrow")
        if right_side:
            score += 10
            reasons.append("right_side")
        return score, reasons

    @staticmethod
    def _score_edit_shape(rect: Any) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []
        if rect.width() >= 280:
            score += 15
            reasons.append("wide")
        if rect.height() >= 22:
            score += 10
            reasons.append("tall")
        return score, reasons

    def _score_edit_title(self, edit: Any) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        title = self._safe_window_text(edit).lower()
        auto_id = self._safe_automation_id(edit).lower()
        control_type = self._safe_control_type(edit)

        if contains_hint_token(title, CHAT_INPUT_HINT_TOKENS):
            score += 12
            reasons.append("title_hint")

        if contains_hint_token(auto_id, CHAT_INPUT_HINT_TOKENS):
            score += 18
            reasons.append("auto_id_hint")

        if control_type == "edit":
            score += 6
            reasons.append("edit_control")
        elif control_type in {"document", "pane", "custom"}:
            score += 2
            reasons.append(f"{control_type}_control")

        try:
            if bool(edit.has_keyboard_focus()):
                score += 18
                reasons.append("focus_hint")
        except Exception:
            pass

        return score, reasons

    def _score_send_button_affinity(self, edit: Any, root: Any) -> Tuple[int, List[str]]:
        input_rect = self._safe_wrapper_rectangle(edit)
        if input_rect is None:
            return 0, []

        roots: List[Any] = [root]
        if self.main_window is not None and self.main_window is not root:
            roots.append(self.main_window)

        best_score = -1
        for candidate_root in roots:
            try:
                buttons = candidate_root.descendants(control_type="Button")
            except Exception:
                continue

            for button in buttons[:260]:
                try:
                    if not button.is_visible() or not button.is_enabled():
                        continue
                except Exception:
                    continue

                score = 0
                title = self._safe_window_text(button).lower()
                auto_id = self._safe_automation_id(button).lower()
                if any(token in title for token in ["send", "submit", "ask", "\u53d1\u9001", "\u63d0\u4ea4", "\u8be2\u95ee", "\u63d0\u95ee"]):
                    score += 40
                if any(token in auto_id for token in ["send", "submit", "chat"]):
                    score += 20

                button_rect = self._safe_wrapper_rectangle(button)
                if button_rect is not None:
                    overlap = not (
                        button_rect.bottom < (input_rect.top - 12)
                        or button_rect.top > (input_rect.bottom + 12)
                    )
                    on_right = button_rect.left >= (
                        input_rect.left + int(0.55 * max(1, input_rect.width()))
                    )
                    compact = button_rect.width() <= max(180, int(0.35 * max(1, input_rect.width())))
                    if overlap:
                        score += 15
                    if on_right:
                        score += 15
                    if compact:
                        score += 10

                if score > best_score:
                    best_score = score

        if best_score >= 35:
            return 15, ["send_button_nearby"]
        return 0, []

    def _score_edit_candidate(self, edit: Any, root: Any) -> Tuple[int, str]:
        rect, reject_reason = self._get_edit_rect(edit)
        if rect is None:
            return -1, reject_reason

        score = 0
        reasons: List[str] = []

        partial_score, partial_reasons = self._score_root_context(root)
        score += partial_score
        reasons.extend(partial_reasons)

        partial_score, partial_reasons = self._score_vertical_position(rect)
        score += partial_score
        reasons.extend(partial_reasons)

        partial_score, partial_reasons = self._score_side_panel_position(rect)
        score += partial_score
        reasons.extend(partial_reasons)

        partial_score, partial_reasons = self._score_edit_shape(rect)
        score += partial_score
        reasons.extend(partial_reasons)

        partial_score, partial_reasons = self._score_edit_title(edit)
        score += partial_score
        reasons.extend(partial_reasons)

        # Geometry-only candidates are common in VS Code. Add button affinity as
        # a stronger discriminator only for already-promising candidates.
        if score >= 55:
            partial_score, partial_reasons = self._score_send_button_affinity(edit, root)
            score += partial_score
            reasons.extend(partial_reasons)

        return score, "+".join(reasons)

    def locate_chat_input(self) -> Tuple[bool, str]:
        if self.main_window is None:
            return False, "window_not_bound"

        best_score = -1
        best_reason = ""
        best_root = None
        best_input = None

        roots = self._collect_chat_roots()
        used_main_window_fallback = False
        if not roots:
            # Skip Ctrl+Alt+I by default to avoid leaking a literal "i" into
            # the active editor when keyboard layout or IME swallows modifiers.
            self.logger.info("chat_root_recovery_shortcut_skipped reason=avoid_editor_pollution")
            # Prefer `code --command` CLI before keyboard-based palette to
            # avoid interference from user keystrokes and IME/keyboard layout.
            # CLI commands exit 0 when the IPC send succeeds, but the VS Code
            # UI may take a moment to respond — retry with increasing delays.
            cli_open_ok = self._invoke_vscode_command_cli("workbench.action.chat.open")
            for delay in (0.5, 0.8, 1.2):
                time.sleep(delay)
                roots = self._collect_chat_roots()
                if roots:
                    break
            if not roots:
                self._invoke_vscode_command_cli("workbench.action.chat.focusInput")
                for delay in (0.5, 0.8, 1.2):
                    time.sleep(delay)
                    roots = self._collect_chat_roots()
                    if roots:
                        break
            # If CLI delivered the command (exit 0) but UIA hasn't caught up,
            # skip the keyboard palette entirely — it would only create visual
            # noise.  The input scoring works reliably with main_window fallback.
            if not roots:
                roots = [self.main_window]
                used_main_window_fallback = True

        for root in roots:
            for edit in self._collect_input_candidates(root):
                score, reason = self._score_edit_candidate(edit, root)
                if score > best_score:
                    best_score = score
                    best_reason = reason
                    best_root = root
                    best_input = edit

        if best_input is None or best_score < CHAT_INPUT_MIN_SCORE:
            return False, f"chat_input_not_found score={best_score}"

        try:
            best_input.set_focus()
            time.sleep(0.05)
            if "focus_set" not in best_reason:
                best_reason = (best_reason + "+focus_set") if best_reason else "focus_set"
            try:
                if bool(best_input.has_keyboard_focus()) and "focus_hint" not in best_reason:
                    best_reason = (best_reason + "+focus_hint") if best_reason else "focus_hint"
            except Exception:
                pass
        except Exception:
            pass

        strong_markers = ["inside_subroot", "chat_named_root", "title_hint", "auto_id_hint"]
        has_strong_binding = any(marker in best_reason for marker in strong_markers)
        if not has_strong_binding and (
            ("focus_hint" in best_reason or "focus_set" in best_reason)
            and "lower_half" in best_reason
            and "right_side" in best_reason
            and "send_button_nearby" in best_reason
        ):
            has_strong_binding = True

        if not has_strong_binding:
            return False, f"chat_input_not_found weak_binding score={best_score};reason={best_reason}"

        if used_main_window_fallback and (
            "title_hint" not in best_reason
            and "auto_id_hint" not in best_reason
            and not (
                ("focus_hint" in best_reason or "focus_set" in best_reason)
                and "lower_half" in best_reason
                and "right_side" in best_reason
                and "send_button_nearby" in best_reason
            )
        ):
            return (
                False,
                f"chat_input_not_found fallback_binding_rejected score={best_score};reason={best_reason}",
            )

        chat_root = best_root
        if used_main_window_fallback and best_root is self.main_window:
            derived_root = self._derive_chat_root_from_input(best_input)
            if derived_root is not None:
                chat_root = derived_root

        self.chat_root = chat_root
        self.chat_input = best_input
        self.logger.info("chat_input_bound score=%s reason=%s", best_score, best_reason)
        return True, f"score={best_score};reason={best_reason}"

    def _read_input_text(self) -> str:
        if self.chat_input is None:
            return ""

        readers = [
            lambda: self.chat_input.get_value(),
            lambda: self.chat_input.window_text(),
            lambda: "\n".join(self.chat_input.texts()),
        ]
        for reader in readers:
            try:
                value = reader()
                return str(value or "")
            except Exception:
                continue
        return ""

    def _input_has_text(self) -> bool:
        return bool(self._read_input_text().strip())

    @staticmethod
    def _normalize_text_for_compare(text: str) -> str:
        return safe_single_line(text).replace("\r", " ").replace("\n", " ").strip().lower()

    def _input_matches_expected_text(self, expected_text: str) -> bool:
        expected_norm = self._normalize_text_for_compare(expected_text)
        if not expected_norm:
            return False

        observed_norm = self._normalize_text_for_compare(self._read_input_text())
        return bool(observed_norm) and (expected_norm in observed_norm)

    @staticmethod
    def _compact_text_for_guard(text: str) -> str:
        return re.sub(r"[^0-9a-z]", "", text.lower())

    def _read_input_text_via_clipboard_probe(self) -> str:
        if self.chat_input is None:
            return ""

        original_clipboard = ""
        try:
            try:
                original_clipboard = pyperclip.paste()
            except Exception:
                original_clipboard = ""

            self.chat_input.set_focus()
            time.sleep(0.04)
            self.chat_input.type_keys("^A^C", set_foreground=True)
            time.sleep(0.08)

            copied = ""
            try:
                copied = str(pyperclip.paste() or "")
            except Exception:
                copied = ""

            return copied
        except Exception:
            return ""
        finally:
            try:
                pyperclip.copy(original_clipboard)
            except Exception:
                pass

    def _input_has_text_via_clipboard_probe(self, expected_text: str = "") -> bool:
        copied = self._read_input_text_via_clipboard_probe()
        if not copied.strip():
            return False

        if expected_text:
            expected_norm = self._normalize_text_for_compare(expected_text)
            copied_norm = self._normalize_text_for_compare(copied)
            if expected_norm:
                return expected_norm in copied_norm

        return True

    @staticmethod
    def _contains_ticket_fingerprint(observed_norm: str, ticket_norm: str) -> bool:
        if not ticket_norm:
            return True

        observed_compact = CopilotChatSender._compact_text_for_guard(observed_norm)
        ticket_compact = CopilotChatSender._compact_text_for_guard(ticket_norm)
        return (ticket_norm in observed_norm) or (
            bool(ticket_compact) and ticket_compact in observed_compact
        )

    def _verify_ticket_fingerprint_guard(self, ticket_id: str, message: str) -> Tuple[bool, str]:
        ticket_norm = self._normalize_text_for_compare(ticket_id)
        message_norm = self._normalize_text_for_compare(message)
        if not message_norm:
            return False, "pre_submit_message_empty"

        if ticket_norm and not self._contains_ticket_fingerprint(message_norm, ticket_norm):
            return False, (
                "ticket_fingerprint_missing_in_message ticket={0}".format(
                    safe_single_line(ticket_id)
                )
            )

        # Prefer probe-based verification because it follows the same keyboard
        # path used by submit and better reflects the actual focused input.
        observed_probe = self._read_input_text_via_clipboard_probe()
        observed_probe_norm = self._normalize_text_for_compare(observed_probe)
        if observed_probe_norm:
            if message_norm not in observed_probe_norm:
                preview = safe_single_line(observed_probe)[:180]
                return False, (
                    "message_fingerprint_mismatch_pre_submit probe_preview={0}".format(
                        preview
                    )
                )

            if not self._contains_ticket_fingerprint(observed_probe_norm, ticket_norm):
                preview = safe_single_line(observed_probe)[:180]
                return False, (
                    "ticket_fingerprint_mismatch_pre_submit ticket={0} probe_preview={1}".format(
                        safe_single_line(ticket_id),
                        preview,
                    )
                )

            return True, "message_and_ticket_fingerprint_verified_via_probe"

        # Fallback to direct control read only when probe cannot read text.
        observed_direct = self._read_input_text()
        observed_direct_norm = self._normalize_text_for_compare(observed_direct)
        if not observed_direct_norm:
            return False, "pre_submit_input_probe_empty"

        if message_norm not in observed_direct_norm:
            preview = safe_single_line(observed_direct)[:180]
            return False, (
                "message_fingerprint_mismatch_pre_submit_direct direct_preview={0}".format(
                    preview
                )
            )

        if not self._contains_ticket_fingerprint(observed_direct_norm, ticket_norm):
            preview = safe_single_line(observed_direct)[:180]
            return False, (
                "ticket_fingerprint_mismatch_pre_submit_direct ticket={0} direct_preview={1}".format(
                    safe_single_line(ticket_id),
                    preview,
                )
            )

        return True, "message_and_ticket_fingerprint_verified_direct"

    def _wait_for_input_observed(self, expected_text: str = "", timeout_sec: float = 0.8) -> bool:
        deadline = time.time() + max(0.15, float(timeout_sec))
        require_match = bool(safe_single_line(expected_text))

        while time.time() < deadline:
            if require_match:
                if self._input_matches_expected_text(expected_text) or self._input_has_text_via_clipboard_probe(expected_text):
                    return True
            else:
                if self._input_has_text() or self._input_has_text_via_clipboard_probe(expected_text):
                    return True
            time.sleep(0.06)

        if require_match:
            return self._input_matches_expected_text(expected_text) or self._input_has_text_via_clipboard_probe(expected_text)
        return self._input_has_text() or self._input_has_text_via_clipboard_probe(expected_text)

    def _wait_for_input_clear(self, timeout_sec: float = 0.8) -> bool:
        deadline = time.time() + max(0.1, float(timeout_sec))
        while time.time() < deadline:
            if not self._input_has_text():
                return True
            time.sleep(0.06)
        return not self._input_has_text()

    def _try_click_send_button(self) -> bool:
        if self.chat_input is None:
            return False

        input_rect = self._safe_wrapper_rectangle(self.chat_input)
        roots: List[Any] = []
        if self.chat_root is not None:
            roots.append(self.chat_root)
        if self.main_window is not None and self.main_window is not self.chat_root:
            roots.append(self.main_window)

        best_button = None
        best_score = -1
        for root in roots:
            try:
                buttons = root.descendants(control_type="Button")
            except Exception:
                continue

            for button in buttons[:280]:
                try:
                    if not button.is_visible() or not button.is_enabled():
                        continue
                except Exception:
                    continue

                score = 0
                title = self._safe_window_text(button).lower()
                auto_id = self._safe_automation_id(button).lower()
                if any(token in title for token in ["send", "submit", "ask", "发送", "提交", "询问", "提问"]):
                    score += 40
                if any(token in auto_id for token in ["send", "submit", "chat"]):
                    score += 20

                button_rect = self._safe_wrapper_rectangle(button)
                if button_rect is not None and input_rect is not None:
                    overlap = not (
                        button_rect.bottom < (input_rect.top - 12)
                        or button_rect.top > (input_rect.bottom + 12)
                    )
                    on_right = button_rect.left >= (
                        input_rect.left + int(0.55 * max(1, input_rect.width()))
                    )
                    compact = button_rect.width() <= max(180, int(0.35 * max(1, input_rect.width())))
                    if overlap:
                        score += 15
                    if on_right:
                        score += 15
                    if compact:
                        score += 10

                if score > best_score:
                    best_score = score
                    best_button = button

        if best_button is None or best_score < 35:
            return False

        try:
            try:
                best_button.invoke()
            except Exception:
                best_button.click_input()
            time.sleep(0.2)
            return True
        except Exception:
            return False

    def _submit_enter_and_validate(self) -> Tuple[bool, str]:
        if self.chat_input is None:
            return False, "chat_input_not_bound"

        try:
            self.chat_input.set_focus()
            time.sleep(0.05)

            # Different VS Code chat settings/layouts may require different
            # submit chords, so try them in strict order.
            submit_chords = [
                ("{ENTER}", "enter_submit_observed"),
                ("^{ENTER}", "ctrl_enter_submit_observed"),
                ("%{ENTER}", "alt_enter_submit_observed"),
            ]
            for chord, reason in submit_chords:
                self.chat_input.type_keys(chord, set_foreground=True)
                if self._wait_for_input_clear(timeout_sec=0.85):
                    return True, reason

            if self._try_click_send_button() and self._wait_for_input_clear(timeout_sec=0.9):
                return True, "send_button_submit_observed"

            return False, "enter_submit_not_observed_input_retained"
        except Exception as exc:
            return False, f"enter_submit_failed:{safe_single_line(exc)}"

    def _set_input_text_fallback(self, message: str) -> bool:
        if self.chat_input is None:
            return False
        try:
            self.chat_input.set_edit_text(message)
            time.sleep(0.12)
            return self._wait_for_input_observed(expected_text=message, timeout_sec=0.75)
        except Exception:
            return False

    def prepare_and_focus_input(self) -> Tuple[bool, str]:
        if self.chat_input is None:
            return False, "chat_input_not_bound"

        try:
            activated, activation_detail = self.ensure_window_foreground_with_retry(
                max_attempts=WINDOW_FOREGROUND_MAX_ATTEMPTS
            )
            if not activated:
                return False, activation_detail

            self.chat_input.set_focus()
            time.sleep(0.1)
            self.chat_input.type_keys("^A{BACKSPACE}", set_foreground=True)
            time.sleep(0.1)

            residue = self._read_input_text().strip()
            if residue:
                try:
                    self.chat_input.set_edit_text("")
                    time.sleep(0.1)
                except Exception:
                    pass

            residue = self._read_input_text().strip()
            if residue:
                return False, f"input_not_cleared len={len(residue)}"

            return True, "focused_and_cleared"
        except Exception as exc:
            return False, f"prepare_failed:{safe_single_line(exc)}"

    def _collect_visible_transcript_texts(
        self,
        root: Any,
        max_nodes_per_type: int = 600,
        selectors: Optional[List[str]] = None,
    ) -> List[str]:
        texts: List[str] = []
        seen: set[str] = set()
        control_types = selectors or ["Text", "Document", "ListItem", "Hyperlink"]
        for control_type in control_types:
            try:
                nodes = root.descendants(control_type=control_type)
            except Exception:
                continue

            for idx, node in enumerate(nodes):
                if idx >= max_nodes_per_type:
                    break
                try:
                    if not node.is_visible():
                        continue
                    text = safe_single_line(node.window_text())
                    if not text:
                        continue
                    lowered = text.lower()
                    if lowered in seen:
                        continue
                    seen.add(lowered)
                    if len(text) >= 2:
                        texts.append(text)
                except Exception:
                    continue

        return texts

    def _capture_transcript_signature(self) -> Dict[str, Any]:
        root = self.chat_root if self.chat_root is not None else self.main_window
        if root is None:
            return {
                "text_count": 0,
                "tail_hash": "",
                "tail_preview": [],
                "tail_text": "",
                "search_text": "",
                "source": "none",
            }

        source = "chat_root" if root is self.chat_root else "main_window"
        texts = self._collect_visible_transcript_texts(root)

        def _looks_low_value(items: List[str]) -> bool:
            if not items:
                return True

            noise_markers = [
                "\u73b0\u5728\u65e0\u6cd5\u8bbf\u95ee\u7f16\u8f91\u5668",
                "shift+alt+f1",
                "cannot access editor",
                "screen reader",
            ]
            informative = 0
            for item in items:
                text = safe_single_line(item).lower()
                if not text:
                    continue
                if any(marker in text for marker in noise_markers):
                    continue
                if len(text) >= 16:
                    informative += 1
                if contains_hint_token(text, CHAT_ROOT_HINT_TOKENS):
                    informative += 2
            return informative == 0 and len(items) <= 4

        if root is self.chat_root and _looks_low_value(texts):
            texts = []

        # Some VS Code chat builds expose transcript content through broader
        # container controls instead of Text/ListItem nodes.
        if not texts and self.chat_root is not None and root is self.chat_root:
            expanded_selectors = [
                "Text",
                "Document",
                "ListItem",
                "Hyperlink",
                "Edit",
                "Custom",
                "Pane",
                "Group",
                "Button",
            ]
            texts = self._collect_visible_transcript_texts(
                root,
                max_nodes_per_type=300,
                selectors=expanded_selectors,
            )
            if texts and not _looks_low_value(texts):
                source = "chat_root_expanded"
            elif texts:
                texts = []

        # If chat_root still yields nothing, retry without the visibility
        # filter — overlay windows may obscure the chat panel and cause
        # is_visible() to return false for the transcript content nodes.
        if not texts and self.chat_root is not None and root is self.chat_root:
            texts_fallback = []
            seen_fallback: set[str] = set()
            hidden_selectors = expanded_selectors if 'expanded_selectors' in dir() else [
                "Text", "Document", "ListItem", "Hyperlink", "Custom", "Pane"
            ]
            for control_type in hidden_selectors:
                try:
                    nodes = root.descendants(control_type=control_type)
                except Exception:
                    continue
                for idx, node in enumerate(nodes):
                    if idx >= 200:
                        break
                    try:
                        text = safe_single_line(node.window_text())
                        if not text:
                            continue
                        lowered = text.lower()
                        if lowered in seen_fallback:
                            continue
                        seen_fallback.add(lowered)
                        if len(text) >= 2:
                            texts_fallback.append(text)
                    except Exception:
                        continue
            if texts_fallback and not _looks_low_value(texts_fallback):
                texts = texts_fallback
                source = "chat_root_any_visibility"

        if not texts and self.main_window is not None and root is not self.main_window:
            fallback_texts = self._collect_visible_transcript_texts(self.main_window)
            if fallback_texts:
                texts = fallback_texts
                source = "main_window_fallback"

        tail = texts[-160:]
        joined = "\n".join(tail)
        tail_hash = hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()[:20]
        # Build a wider search window so recently-sent user messages are not
        # pushed out of scope by rapid agent streaming responses or by dense
        # UIA content from terminals/panels on the main_window fallback.
        search_window = texts[-320:]
        search_text = "\n".join(search_window)[:24000]
        return {
            "text_count": len(texts),
            "tail_hash": tail_hash,
            "tail_preview": tail[-3:],
            "tail_text": joined[:8000],
            "search_text": search_text,
            "source": source,
        }

    def _message_appeared_in_transcript(self, message: str, signature: Dict[str, Any]) -> bool:
        if not self._signature_source_is_chat_root(signature):
            return False

        # Search the wider window first; fall back to tail_text for backward compat.
        haystack = safe_single_line(
            signature.get("search_text", "") or signature.get("tail_text", "")
        ).lower()
        needle = safe_single_line(message).lower()

        if not haystack or not needle:
            return False

        # Keep this check strict: fuzzy token matching can produce false positives
        # when transcript changes for unrelated reasons (for example, tool logs).
        return needle in haystack

    @staticmethod
    def _is_weak_fragment(token: str) -> bool:
        normalized = safe_single_line(token).lower()
        if not normalized:
            return True

        if normalized in VERIFY_WEAK_STOPWORDS:
            return True

        if re.fullmatch(r"t\d{8}", normalized):
            return True

        if normalized.isalpha() and len(normalized) <= VERIFY_WEAK_ALPHA_FRAGMENT_MAX_LEN:
            return True

        return False

    @staticmethod
    def _normalize_fragments(message_fragments: Optional[List[str]]) -> List[str]:
        fragments: List[str] = []
        for item in message_fragments or []:
            token = safe_single_line(item).lower()
            if len(token) >= VERIFY_MIN_FRAGMENT_LEN and not CopilotChatSender._is_weak_fragment(token):
                fragments.append(token)
        return fragments

    @staticmethod
    def _has_fragment_hit(signature: Dict[str, Any], fragments: List[str]) -> bool:
        if not fragments:
            return False

        if not CopilotChatSender._signature_source_is_chat_root(signature):
            return False

        haystack = safe_single_line(
            signature.get("search_text", "") or signature.get("tail_text", "")
        ).lower()
        if not haystack:
            return False

        for fragment in fragments:
            if fragment in haystack:
                return True
        return False

    @staticmethod
    def _signature_has_delta(pre_signature: Dict[str, Any], post_signature: Dict[str, Any]) -> bool:
        if post_signature.get("tail_hash") != pre_signature.get("tail_hash"):
            return True

        pre_count = int(pre_signature.get("text_count", 0))
        post_count = int(post_signature.get("text_count", 0))
        return post_count > pre_count

    @staticmethod
    def _build_verify_details(
        input_cleared: bool,
        transcript_changed: bool,
        fragment_matched: bool,
        message_matched: bool,
        ticket_fingerprint: str,
        ticket_fingerprint_matched: bool,
        fragments: List[str],
        pre_signature: Dict[str, Any],
        post_signature: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "input_cleared": input_cleared,
            "transcript_changed": transcript_changed,
            "fragment_matched": fragment_matched,
            "message_matched": message_matched,
            "ticket_fingerprint": ticket_fingerprint,
            "ticket_fingerprint_matched": ticket_fingerprint_matched,
            "fragments": fragments,
            "pre_signature": pre_signature,
            "post_signature": post_signature,
        }

    def _verify_result(
        self,
        status: str,
        reason: str,
        input_cleared: bool,
        transcript_changed: bool,
        fragment_matched: bool,
        message_matched: bool,
        ticket_fingerprint: str,
        ticket_fingerprint_matched: bool,
        fragments: List[str],
        pre_signature: Dict[str, Any],
        post_signature: Dict[str, Any],
    ) -> Tuple[str, str, Dict[str, Any]]:
        details = self._build_verify_details(
            input_cleared=input_cleared,
            transcript_changed=transcript_changed,
            fragment_matched=fragment_matched,
            message_matched=message_matched,
            ticket_fingerprint=ticket_fingerprint,
            ticket_fingerprint_matched=ticket_fingerprint_matched,
            fragments=fragments,
            pre_signature=pre_signature,
            post_signature=post_signature,
        )
        return status, reason, details

    @staticmethod
    def _extract_ticket_fingerprint(ticket_id: str, message_text: str) -> str:
        direct = safe_single_line(ticket_id).strip()
        if direct:
            return direct

        normalized_message = message_text.replace("\r", "\n")
        match = re.search(r"(?i)\[ticket\s*=\s*([^\]\s]{6,128})\]", normalized_message)
        if match:
            return safe_single_line(match.group(1)).strip()

        match = re.search(r"(?i)\bticket\s*=\s*([a-z0-9._:-]{6,128})", normalized_message)
        if match:
            return safe_single_line(match.group(1)).strip()

        return ""

    @staticmethod
    def _signature_source_is_chat_root(signature: Dict[str, Any]) -> bool:
        source = safe_single_line(signature.get("source", "")).lower()
        return source.startswith("chat_root")

    @staticmethod
    def _signature_source_allows_ticket_fingerprint(signature: Dict[str, Any]) -> bool:
        source = safe_single_line(signature.get("source", "")).lower()
        if source.startswith("chat_root"):
            return True
        # When chat_root extraction is blocked by overlay/visibility quirks,
        # transcript capture may fall back to main_window while still reflecting
        # the active chat thread. Keep this exception ticket-fingerprint-only.
        return source == "main_window_fallback"

    def _signature_contains_ticket_fingerprint(
        self,
        signature: Dict[str, Any],
        ticket_fingerprint_norm: str,
    ) -> bool:
        if not ticket_fingerprint_norm:
            return False

        if not self._signature_source_allows_ticket_fingerprint(signature):
            return False

        haystack_norm = self._normalize_text_for_compare(
            safe_single_line(signature.get("search_text", "") or signature.get("tail_text", ""))
        )
        if not haystack_norm:
            return False

        return self._contains_ticket_fingerprint(haystack_norm, ticket_fingerprint_norm)

    def send_message_via_clipboard(
        self,
        message: str,
        ticket_id: str = "",
        adaptive_mode: str = "strict",
    ) -> Tuple[bool, str]:
        if self.chat_input is None:
            return False, "chat_input_not_bound"

        original_clipboard = ""
        try:
            clipboard_verified = False
            try:
                original_clipboard = pyperclip.paste()
            except Exception:
                original_clipboard = ""

            # Copy message to clipboard with verification.
            pyperclip.copy(message)
            time.sleep(0.15)
            try:
                clipboard_verified = safe_single_line(pyperclip.paste()) == safe_single_line(message)
            except Exception:
                clipboard_verified = False

            if not clipboard_verified:
                self.logger.warning("clipboard_copy_verify_failed fallback=set_edit_text")

            max_paste_attempts = 3
            paste_observed_in_loop = False
            paste_succeeded = False

            for paste_attempt in range(1, max_paste_attempts + 1):
                # Re-copy to clipboard on retry in case clipboard was disturbed.
                if paste_attempt > 1:
                    pyperclip.copy(message)
                    time.sleep(0.2)
                    try:
                        clipboard_verified = safe_single_line(pyperclip.paste()) == safe_single_line(message)
                    except Exception:
                        clipboard_verified = False

                self.chat_input.set_focus()
                time.sleep(0.05)
                self.chat_input.type_keys("^A{BACKSPACE}", set_foreground=True)
                time.sleep(0.05)
                if clipboard_verified:
                    self.chat_input.type_keys("^V", set_foreground=True)
                else:
                    self.chat_input.set_edit_text(message)
                    time.sleep(0.15)

                # Settle time grows with each retry to tolerate system load spikes.
                settle_sec = 0.2 + 0.25 * paste_attempt
                time.sleep(settle_sec)

                if self._wait_for_input_observed(expected_text=message, timeout_sec=1.0):
                    paste_observed_in_loop = True
                    paste_succeeded = True
                    break

                self.logger.warning("paste_attempt_%d_not_observed retrying", paste_attempt)

            if not paste_succeeded:
                paste_succeeded = self._set_input_text_fallback(message)

            if not paste_succeeded:
                return False, "input_not_observed_after_paste"

            guard_ok, guard_reason = self._verify_ticket_fingerprint_guard(
                ticket_id=ticket_id,
                message=message,
            )
            if not guard_ok:
                self.logger.error(
                    "pre_submit_ticket_fingerprint_guard_failed mode=%s reason=%s",
                    safe_single_line(adaptive_mode),
                    safe_single_line(guard_reason),
                )
                return False, guard_reason

            ok, detail = self._submit_enter_and_validate()
            if not ok:
                return False, detail

            if paste_observed_in_loop:
                return True, "clipboard_paste_and_" + detail
            return True, "clipboard_paste_unobserved_input_and_" + detail
        except Exception as exc:
            return False, f"send_failed:{safe_single_line(exc)}"
        finally:
            if original_clipboard:
                try:
                    pyperclip.copy(original_clipboard)
                except Exception:
                    pass

    def verify_message_sent(
        self,
        pre_signature: Dict[str, Any],
        require_transcript_confirmation: bool,
        message_fragments: Optional[List[str]] = None,
        message_text: str = "",
        ticket_id: str = "",
        verification_profile: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str, Dict[str, Any]]:
        profile = verification_profile if isinstance(verification_profile, dict) else {}
        verify_timeout_sec = max(0.8, float(profile.get("timeout_sec", self.timeout)))
        verify_poll_interval_sec = max(
            0.06,
            float(profile.get("poll_interval_sec", VERIFY_POLL_INTERVAL_SEC)),
        )
        verification_level = safe_single_line(profile.get("level", "strict")).lower() or "strict"
        effective_require_transcript = bool(
            profile.get("require_transcript_confirmation", require_transcript_confirmation)
        )
        ticket_fingerprint = self._extract_ticket_fingerprint(ticket_id, message_text)
        ticket_fingerprint_norm = self._normalize_text_for_compare(ticket_fingerprint)

        fragments = self._normalize_fragments(message_fragments)
        (
            input_cleared,
            transcript_changed,
            fragment_matched,
            message_matched,
            ticket_fingerprint_matched,
            last_signature,
            early_confirmed,
        ) = self._poll_verify_state(
            pre_signature=pre_signature,
            fragments=fragments,
            message_text=message_text,
            ticket_fingerprint_norm=ticket_fingerprint_norm,
            timeout_sec=verify_timeout_sec,
            poll_interval_sec=verify_poll_interval_sec,
        )

        status, reason = self._resolve_verify_outcome(
            input_cleared=input_cleared,
            transcript_changed=transcript_changed,
            fragment_matched=fragment_matched,
            message_matched=message_matched,
            ticket_fingerprint_matched=ticket_fingerprint_matched,
            require_transcript_confirmation=effective_require_transcript,
            early_confirmed=early_confirmed,
            verification_level=verification_level,
        )

        status, reason, details = self._verify_result(
            status=status,
            reason=reason,
            input_cleared=input_cleared,
            transcript_changed=transcript_changed,
            fragment_matched=fragment_matched,
            message_matched=message_matched,
            ticket_fingerprint=ticket_fingerprint,
            ticket_fingerprint_matched=ticket_fingerprint_matched,
            fragments=fragments,
            pre_signature=pre_signature,
            post_signature=last_signature,
        )
        details["verification_profile"] = {
            "level": verification_level,
            "timeout_sec": verify_timeout_sec,
            "poll_interval_sec": verify_poll_interval_sec,
            "require_transcript_confirmation": effective_require_transcript,
            "mode": safe_single_line(profile.get("mode", "")),
        }
        return status, reason, details

    def _poll_verify_state(
        self,
        pre_signature: Dict[str, Any],
        fragments: List[str],
        message_text: str,
        ticket_fingerprint_norm: str,
        timeout_sec: float,
        poll_interval_sec: float,
    ) -> Tuple[bool, bool, bool, bool, bool, Dict[str, Any], bool]:
        deadline = time.time() + max(0.8, float(timeout_sec))
        input_cleared = False
        transcript_changed = False
        fragment_matched = False
        message_matched = False
        ticket_fingerprint_matched = False
        last_signature: Dict[str, Any] = pre_signature
        early_confirmed = False
        pre_ticket_seen = self._signature_contains_ticket_fingerprint(
            pre_signature,
            ticket_fingerprint_norm,
        )

        while time.time() < deadline:
            current_text = self._read_input_text().strip()
            input_cleared = input_cleared or (current_text == "")

            post_signature = self._capture_transcript_signature()
            last_signature = post_signature
            fragment_matched = fragment_matched or self._has_fragment_hit(post_signature, fragments)
            message_matched = message_matched or self._message_appeared_in_transcript(
                message_text,
                post_signature,
            )

            if self._signature_has_delta(pre_signature, post_signature):
                transcript_changed = True

            post_ticket_seen = self._signature_contains_ticket_fingerprint(
                post_signature,
                ticket_fingerprint_norm,
            )
            if ticket_fingerprint_norm and (not pre_ticket_seen) and post_ticket_seen and transcript_changed:
                ticket_fingerprint_matched = True

            if input_cleared and transcript_changed and (
                fragment_matched or message_matched or ticket_fingerprint_matched
            ):
                early_confirmed = True
                break

            time.sleep(max(0.06, float(poll_interval_sec)))

        return (
            input_cleared,
            transcript_changed,
            fragment_matched,
            message_matched,
            ticket_fingerprint_matched,
            last_signature,
            early_confirmed,
        )

    @staticmethod
    def _resolve_verify_outcome(
        input_cleared: bool,
        transcript_changed: bool,
        fragment_matched: bool,
        message_matched: bool,
        ticket_fingerprint_matched: bool,
        require_transcript_confirmation: bool,
        early_confirmed: bool,
        verification_level: str = "strict",
    ) -> Tuple[str, str]:
        mode = safe_single_line(verification_level).lower() or "strict"
        if early_confirmed and (fragment_matched or message_matched or ticket_fingerprint_matched):
            if ticket_fingerprint_matched and not (fragment_matched or message_matched):
                return "confirmed", "ticket_fingerprint_delta_matched"
            return "confirmed", "input_cleared_and_transcript_changed"
        if message_matched:
            return "confirmed", "message_matched_in_transcript"
        if fragment_matched and transcript_changed:
            return "confirmed", "fragment_matched_and_transcript_changed"
        if ticket_fingerprint_matched and input_cleared and transcript_changed:
            return "confirmed", "ticket_fingerprint_delta_matched"

        if mode == "relaxed":
            if input_cleared and transcript_changed:
                return "confirmed", "relaxed_input_cleared_and_transcript_changed"
            if input_cleared and (fragment_matched or message_matched):
                return "confirmed", "relaxed_input_cleared_with_fragment_hit"

        if transcript_changed:
            return "uncertain", "transcript_changed_without_message_match"

        if not input_cleared:
            return "failed", "no_clear_no_transcript_delta"

        if require_transcript_confirmation:
            return "uncertain", "input_cleared_without_transcript_delta"
        return "uncertain", "input_cleared_transcript_check_disabled"

    def close(self) -> None:
        self.chat_input = None
        self.chat_root = None
        self.main_window = None
        self.app = None


def write_relay_ack(relay_path: str, payload: Dict[str, Any], logger: logging.Logger) -> str:
    relay = relay_path.strip()
    if not relay:
        return ""

    ack_path = Path(relay + ".pywinauto_ack.json")
    try:
        ensure_parent(ack_path)
        ack_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        return str(ack_path).replace("\\", "/")
    except Exception as exc:
        logger.warning("relay_ack_write_failed path=%s detail=%s", relay, safe_single_line(exc))
        return ""


def build_fallback_action(status: str, grade: str) -> str:
    if status in {"confirmed", "idempotent"}:
        return "none"
    if grade == "fatal":
        return "fallback_to_ahk_immediately"
    if status == "uncertain":
        return "fallback_to_ahk_with_duplicate_guard"
    return "retry_then_fallback_to_ahk"


def run_environment_preflight(
    request: SendRequest,
    policy: WindowBindingPolicy,
    logger: logging.Logger,
) -> Tuple[bool, str, Dict[str, Any]]:
    details: Dict[str, Any] = {
        "os_name": os.name,
        "message_len": len(request.message),
        "health_check_enabled": bool(request.health_check_enabled),
    }

    if os.name != "nt":
        return False, "unsupported_platform", details

    if len(request.message.strip()) == 0:
        return False, "empty_message", details

    if len(request.message) > 12000:
        return False, "message_too_long", details

    if not request.health_check_enabled:
        return True, "health_check_skipped", details

    details["min_available_memory_mb"] = 96
    details["available_memory_mb"] = get_available_memory_mb()
    details["memory_load_percent"] = get_memory_load_percent()
    details["adaptive_high_load_available_mb"] = ADAPTIVE_HIGH_LOAD_AVAILABLE_MB
    details["adaptive_high_load_memory_percent"] = ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT
    if details["available_memory_mb"] > 0 and details["available_memory_mb"] < details["min_available_memory_mb"]:
        return False, "resource_low_memory", details

    original_clipboard = ""
    clipboard_probe = f"pyw_probe_{int(time.time() * 1000)}"
    try:
        original_clipboard = pyperclip.paste()
        pyperclip.copy(clipboard_probe)
        roundtrip = pyperclip.paste()
        details["clipboard_roundtrip_ok"] = roundtrip == clipboard_probe
        if roundtrip != clipboard_probe:
            return False, "clipboard_roundtrip_failed", details
    except Exception as exc:
        details["clipboard_roundtrip_ok"] = False
        details["clipboard_error"] = safe_single_line(exc)
        return False, f"clipboard_health_failed:{safe_single_line(exc)}", details
    finally:
        try:
            pyperclip.copy(original_clipboard)
        except Exception:
            pass

    try:
        socket.getaddrinfo("api.github.com", 443)
        details["network_dns_ok"] = True
    except Exception as exc:
        details["network_dns_ok"] = False
        details["network_dns_error"] = safe_single_line(exc)

    if policy.expected_handle > 0:
        try:
            app = Application(backend="uia").connect(handle=policy.expected_handle)
            window = app.window(handle=policy.expected_handle)
            title = safe_single_line(window.window_text())
            pid = int(window.process_id())
        except Exception as exc:
            details["window_probe_mode"] = "handle"
            details["window_probe_error"] = safe_single_line(exc)
            return False, f"window_probe_failed:{safe_single_line(exc)}", details

        details["window_probe_mode"] = "handle"
        details["vscode_window_count"] = 1
        details["vscode_candidate_pids"] = [pid]
        details["vscode_alive_process_count"] = 1 if is_process_alive(pid) else 0
        details["copilot_title_hint"] = ("copilot" in title.lower() or "chat" in title.lower())

        if details["vscode_alive_process_count"] < 1:
            return False, "vscode_process_not_alive", details

        return True, "preflight_ok", details

    summaries = get_vscode_window_summaries(policy.title_regex, policy.workspace_hint)
    details["vscode_window_count"] = len(summaries)
    details["vscode_candidate_pids"] = [int(item.get("pid", 0)) for item in summaries if int(item.get("pid", 0)) > 0]
    details["copilot_title_hint"] = any(bool(item.get("copilot_title_hint")) for item in summaries)
    details["window_summaries"] = summaries[:5]

    if len(summaries) < 1:
        return False, "no_vscode_window_found_preflight", details

    alive_count = 0
    for pid in details["vscode_candidate_pids"]:
        if is_process_alive(int(pid)):
            alive_count += 1
    details["vscode_alive_process_count"] = alive_count
    if alive_count < 1:
        return False, "vscode_process_not_alive", details

    return True, "preflight_ok", details


def run_stage_operation_with_timeout(
    operation: Callable[[], Tuple[bool, str]],
    timeout_sec: float,
) -> Tuple[bool, str, bool]:
    safe_timeout = max(0.10, float(timeout_sec))
    state = {"done": False}
    result: Dict[str, Any] = {"ok": False, "detail": "operation_not_started"}

    def worker() -> None:
        try:
            op_result = operation()
            if isinstance(op_result, tuple) and len(op_result) >= 2:
                result["ok"] = bool(op_result[0])
                result["detail"] = safe_single_line(op_result[1])
            else:
                result["ok"] = False
                result["detail"] = "operation_invalid_result"
        except Exception as exc:
            result["ok"] = False
            result["detail"] = f"operation_exception:{safe_single_line(exc)}"
        finally:
            state["done"] = True

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=safe_timeout)

    if not bool(state["done"]):
        return False, f"operation_timeout timeout_sec={safe_timeout:.2f}", True

    return bool(result.get("ok", False)), safe_single_line(result.get("detail", "")), False


def run_send_request(request: SendRequest, policy: WindowBindingPolicy, logger: logging.Logger) -> SendOutcome:
    run_started = time.perf_counter()
    token = stable_token(request.ticket_id, request.event, request.message, request.dedupe_token)
    message_fragments = build_message_fragments(request.message)
    sender: Optional[CopilotChatSender] = None

    ledger_path = Path(request.ledger_path) if request.ledger_path.strip() else DEFAULT_LEDGER_PATH
    ledger = DispatchLedger(ledger_path, logger)
    base_limit = max(1, int(request.max_retries))

    perf_summary: Dict[str, Any] = {
        "started_at": utc_now_text(),
        "base_max_retries": base_limit,
        "stage_attempts": {},
        "stage_elapsed_ms": {},
        "window_activation_attempts": 0,
    }
    restore_requested = max(1, min(30, int(request.restore_previous_window_count)))
    seeded_restore_handles = normalize_window_handles(request.restore_previous_window_handles_csv)
    if seeded_restore_handles:
        seeded_restore_handles = seeded_restore_handles[:restore_requested]
    restore_state: Dict[str, Any] = {
        "restore_previous_foreground_window_switch": bool(request.restore_previous_foreground_window),
        "restore_previous_window_count_requested": restore_requested,
        "restore_previous_window_count_captured": 0,
        "restore_previous_window_handles": list(seeded_restore_handles),
        "restore_previous_window_capture_trace": [],
        "restore_previous_window_activation_trace": [],
        "restore_previous_window_activation_count_attempted": 0,
        "restore_previous_window_activation_count_succeeded": 0,
        "restore_previous_window_activation_final_foreground_handle": 0,
        "restore_previous_window_activation_restore_executed": False,
        "restore_previous_window_activation_skipped_reason": "",
        "restore_previous_window_handles_seeded": list(seeded_restore_handles),
        "esc_preflight_enabled": bool(request.esc_preflight_enabled),
    }
    runtime_adaptive_profile: Dict[str, Any] = {
        "enabled": bool(request.adaptive_load_enabled),
        "mode": "strict",
        "verification_level": "strict",
        "verify_timeout_sec": max(0.8, float(request.timeout_per_step)),
        "verify_poll_interval_sec": VERIFY_POLL_INTERVAL_SEC,
        "require_transcript_confirmation": bool(request.require_transcript_confirmation),
        "pre_send_delay_ms_effective": max(0, min(60000, int(request.pre_send_delay_ms))),
        "retry_delay_scale": 1.0,
    }
    runtime_verify_profile: Dict[str, Any] = {
        "level": "strict",
        "timeout_sec": max(0.8, float(request.timeout_per_step)),
        "poll_interval_sec": VERIFY_POLL_INTERVAL_SEC,
        "require_transcript_confirmation": bool(request.require_transcript_confirmation),
        "mode": "strict",
    }
    runtime_retry_delay_scale = 1.0
    runtime_pre_send_delay_ms = max(0, min(60000, int(request.pre_send_delay_ms)))
    restore_applied = False

    def append_ledger(phase: str, status: str, grade: str, reason: str, details: Dict[str, Any]) -> None:
        ledger.append(
            {
                "schema": "PYW_CHAT_LEDGER_V1",
                "at": utc_now_text(),
                "token": token,
                "ticket_id": safe_single_line(request.ticket_id),
                "event": safe_single_line(request.event),
                "phase": phase,
                "status": status,
                "grade": grade,
                "reason": safe_single_line(reason),
                "details": details,
            }
        )

    def finalize_outcome(outcome: SendOutcome) -> SendOutcome:
        nonlocal restore_applied

        if sender is not None and not restore_applied:
            restore_applied = True
            if bool(request.restore_previous_foreground_window):
                restore_result = sender.restore_previous_foreground_window()
                restore_state["restore_previous_window_activation_count_attempted"] = int(
                    restore_result.get("attempted", 0)
                )
                restore_state["restore_previous_window_activation_count_succeeded"] = int(
                    restore_result.get("succeeded_count", 0)
                )
                restore_state["restore_previous_window_activation_final_foreground_handle"] = int(
                    restore_result.get("final_foreground_handle", 0)
                )
                restore_state["restore_previous_window_activation_trace"] = [
                    dict(item)
                    for item in restore_result.get("activation_trace", [])
                    if isinstance(item, dict)
                ]
                restore_state["restore_previous_window_activation_restore_executed"] = True
                restore_state["restore_previous_window_activation_skipped_reason"] = safe_single_line(
                    restore_result.get("reason", "")
                )
                append_ledger(
                    "foreground_restore",
                    "ok" if bool(restore_result.get("succeeded")) else "failed",
                    "none" if bool(restore_result.get("succeeded")) else "focus",
                    safe_single_line(restore_result.get("reason", "")),
                    {
                        "attempted": int(restore_result.get("attempted", 0)),
                        "succeeded": bool(restore_result.get("succeeded")),
                        "succeeded_count": int(restore_result.get("succeeded_count", 0)),
                        "restored_handle": int(restore_result.get("restored_handle", 0)),
                        "restored_handles": [int(item) for item in restore_result.get("restored_handles", [])],
                        "activation_trace": [
                            dict(item)
                            for item in restore_result.get("activation_trace", [])
                            if isinstance(item, dict)
                        ],
                        "final_foreground_handle": int(restore_result.get("final_foreground_handle", 0)),
                    },
                )
            else:
                restore_state["restore_previous_window_activation_skipped_reason"] = "disabled_by_request"

        total_elapsed_ms = int((time.perf_counter() - run_started) * 1000)
        perf_summary["total_elapsed_ms"] = total_elapsed_ms
        perf_summary["ended_at"] = utc_now_text()
        if sender is not None:
            perf_summary["window_activation_attempts"] = int(sender.window_activation_attempts)

        outcome.details = dict(outcome.details)
        outcome.details["token"] = token
        outcome.details["ledger_path"] = str(ledger_path).replace("\\", "/")
        outcome.details["perf"] = perf_summary
        for key, value in restore_state.items():
            outcome.details[key] = value

        append_ledger("performance", "ok", "none", "stage_metrics", {"metrics": perf_summary})
        append_ledger("result", outcome.status, outcome.grade, outcome.reason, outcome.details)

        ack_payload = serialize_outcome_with_ahk_compat(outcome)
        ack_payload["acked_at"] = utc_now_text()
        ack_path = write_relay_ack(request.relay_path, ack_payload, logger)
        if ack_path:
            outcome.details["relay_ack_path"] = ack_path
        return outcome

    def finalize_stage_failure(
        phase: str,
        reason: str,
        grade: str,
        detail_key: str,
        detail_value: Dict[str, Any],
    ) -> SendOutcome:
        return finalize_outcome(
            SendOutcome(
                success=False,
                status="failed",
                token=token,
                reason=reason,
                grade=grade,
                fallback_action=build_fallback_action("failed", grade),
                details={"phase": phase, detail_key: detail_value},
            )
        )

    last_record = ledger.get_last_record(token)
    if last_record and safe_single_line(last_record.get("status")) in {"confirmed", "idempotent"}:
        return finalize_outcome(
            SendOutcome(
                success=True,
                status="idempotent",
                token=token,
                reason="already_confirmed_in_ledger",
                grade="none",
                fallback_action="none",
                details={"last_record": last_record},
            )
        )

    circuit_state = ledger.get_circuit_state(
        threshold=max(1, int(request.circuit_breaker_threshold)),
        cooldown_sec=max(0, int(request.circuit_breaker_cooldown_sec)),
    )
    append_ledger(
        "circuit_probe",
        "open" if bool(circuit_state.get("open")) else "closed",
        "fatal" if bool(circuit_state.get("open")) else "none",
        "circuit_state_checked",
        circuit_state,
    )
    if bool(circuit_state.get("open")):
        return finalize_outcome(
            SendOutcome(
                success=False,
                status="failed",
                token=token,
                reason=(
                    "circuit_open consecutive_failures={0} remaining_cooldown_sec={1}".format(
                        int(circuit_state.get("consecutive_failures", 0)),
                        int(circuit_state.get("remaining_cooldown_sec", 0)),
                    )
                ),
                grade="fatal",
                fallback_action="fallback_to_ahk_immediately",
                details={"phase": "circuit_probe", "circuit": circuit_state},
            )
        )

    append_ledger(
        phase="claimed",
        status="claimed",
        grade="none",
        reason="request_claimed",
        details={
            "relay_path": request.relay_path,
            "require_transcript_confirmation": request.require_transcript_confirmation,
            "message_fragment_count": len(message_fragments),
            "adaptive_load_enabled": bool(request.adaptive_load_enabled),
        },
    )

    preflight_start = time.perf_counter()
    preflight_ok, preflight_reason, preflight_details = run_environment_preflight(
        request=request,
        policy=policy,
        logger=logger,
    )
    preflight_elapsed = int((time.perf_counter() - preflight_start) * 1000)
    perf_summary["stage_elapsed_ms"]["preflight"] = preflight_elapsed
    append_ledger(
        "preflight",
        "ok" if preflight_ok else "failed",
        "none" if preflight_ok else "fatal",
        preflight_reason,
        {"elapsed_ms": preflight_elapsed, **preflight_details},
    )
    if not preflight_ok:
        return finalize_outcome(
            SendOutcome(
                success=False,
                status="failed",
                token=token,
                reason=f"environment_preflight_failed:{preflight_reason}",
                grade="fatal",
                fallback_action="fallback_to_ahk_immediately",
                details={"phase": "preflight", "preflight": preflight_details},
            )
        )

    runtime_adaptive_profile = derive_runtime_adaptive_profile(
        request=request,
        preflight_details=preflight_details,
    )
    runtime_retry_delay_scale = max(
        0.20,
        min(1.50, float(runtime_adaptive_profile.get("retry_delay_scale", 1.0))),
    )
    runtime_pre_send_delay_ms = max(
        0,
        min(60000, int(runtime_adaptive_profile.get("pre_send_delay_ms_effective", request.pre_send_delay_ms))),
    )
    runtime_verify_profile = {
        "level": safe_single_line(runtime_adaptive_profile.get("verification_level", "strict")) or "strict",
        "timeout_sec": max(
            0.8,
            float(runtime_adaptive_profile.get("verify_timeout_sec", request.timeout_per_step)),
        ),
        "poll_interval_sec": max(
            0.06,
            float(runtime_adaptive_profile.get("verify_poll_interval_sec", VERIFY_POLL_INTERVAL_SEC)),
        ),
        "require_transcript_confirmation": bool(
            runtime_adaptive_profile.get(
                "require_transcript_confirmation",
                request.require_transcript_confirmation,
            )
        ),
        "mode": safe_single_line(runtime_adaptive_profile.get("mode", "strict")) or "strict",
    }
    perf_summary["adaptive"] = runtime_adaptive_profile
    append_ledger(
        "adaptive_profile",
        "ok",
        "none",
        "runtime_adaptive_profile_selected",
        runtime_adaptive_profile,
    )

    vscode_handle_hint = 0
    try:
        if int(policy.expected_handle) > 0:
            vscode_handle_hint = int(policy.expected_handle)
        elif isinstance(preflight_details, dict):
            summaries = preflight_details.get("window_summaries", [])
            if isinstance(summaries, list):
                for item in summaries:
                    if not isinstance(item, dict):
                        continue
                    hwnd = int(item.get("hwnd", 0))
                    if hwnd > 0:
                        vscode_handle_hint = hwnd
                        break
    except Exception:
        vscode_handle_hint = 0

    sender = CopilotChatSender(policy=policy, timeout_per_step=request.timeout_per_step, logger=logger)

    if bool(request.restore_previous_foreground_window) and seeded_restore_handles:
        sender.restore_window_handles = list(seeded_restore_handles)
        append_ledger(
            "foreground_seed",
            "ok",
            "none",
            "seeded_restore_handles",
            {
                "seeded_count": len(seeded_restore_handles),
                "seeded_handles": list(seeded_restore_handles),
            },
        )

    def _unique_positive_handles(handles: List[int]) -> List[int]:
        ordered: List[int] = []
        seen: set[int] = set()
        for raw in handles:
            try:
                handle = int(raw)
            except Exception:
                continue
            if handle <= 0 or handle in seen:
                continue
            seen.add(handle)
            ordered.append(handle)
        return ordered

    def _current_vscode_handle() -> int:
        try:
            if sender.main_window is not None:
                hwnd = int(sender.main_window.handle)
                if hwnd > 0:
                    return hwnd
        except Exception:
            pass
        if int(policy.expected_handle) > 0:
            return int(policy.expected_handle)
        if int(vscode_handle_hint) > 0:
            return int(vscode_handle_hint)
        return 0

    def _normalize_restore_handles(raw_handles: List[int], phase_name: str) -> List[int]:
        existing_handles = _unique_positive_handles(restore_state.get("restore_previous_window_handles", []))
        candidate_handles = _unique_positive_handles(raw_handles)

        # Keep newly captured handles first, then retain prior handles as backup
        # when capture misses some windows (for cross-sender and delayed overlays).
        if phase_name == "foreground_recapture":
            merged = list(candidate_handles)
            merged.extend(item for item in existing_handles if item not in candidate_handles)
        else:
            merged = list(candidate_handles)
            merged.extend(item for item in existing_handles if item not in candidate_handles)

        vscode_hwnd = _current_vscode_handle()
        if vscode_hwnd > 0:
            has_non_vscode = any(item != vscode_hwnd for item in merged)
            if has_non_vscode:
                non_vscode = [item for item in merged if item != vscode_hwnd]
                merged = non_vscode

        return merged[:restore_requested]

    def refresh_restore_capture(phase_name: str, reason: str) -> None:
        if not bool(request.restore_previous_foreground_window):
            return

        restore_capture = sender.capture_previous_foreground_windows(restore_requested)
        raw_handles = [int(item) for item in restore_capture.get("handles", [])]
        effective_handles = _normalize_restore_handles(raw_handles, phase_name)
        sender.restore_window_handles = list(effective_handles)

        restore_state["restore_previous_window_count_requested"] = int(restore_capture.get("requested", 0))
        restore_state["restore_previous_window_count_captured"] = len(effective_handles)
        restore_state["restore_previous_window_handles"] = list(effective_handles)
        restore_state["restore_previous_window_capture_trace"] = list(restore_capture.get("trace", []))

        append_ledger(
            phase_name,
            "ok",
            "none",
            reason,
            {
                "requested": int(restore_capture.get("requested", 0)),
                "captured_raw": len(raw_handles),
                "captured_effective": len(effective_handles),
                "scanned": int(restore_capture.get("scanned", 0)),
                "handles_raw": raw_handles,
                "handles_effective": list(effective_handles),
                "vscode_handle": int(_current_vscode_handle()),
            },
        )

    def run_stage(
        stage_name: str,
        operation: Any,
        failure_grade: str,
        on_retry: Optional[Any] = None,
        attempt_timeout_sec: float = 0.0,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        stage_started = time.perf_counter()
        attempt = 0
        dynamic_limit = base_limit
        last_detail = ""

        while attempt < dynamic_limit:
            attempt += 1
            attempt_start = time.perf_counter()
            timed_out = False
            if attempt_timeout_sec > 0:
                ok, detail, timed_out = run_stage_operation_with_timeout(operation, attempt_timeout_sec)
            else:
                ok, detail = operation()
            last_detail = detail
            category = classify_retry_reason(detail)
            attempt_elapsed = int((time.perf_counter() - attempt_start) * 1000)

            append_ledger(
                f"{stage_name}_attempt",
                "ok" if ok else "failed",
                "none" if ok else category,
                detail,
                {
                    "attempt": attempt,
                    "attempt_elapsed_ms": attempt_elapsed,
                    "attempt_timeout_ms": int(max(0.0, attempt_timeout_sec) * 1000),
                    "attempt_timed_out": timed_out,
                    "dynamic_limit": dynamic_limit,
                    "retry_category": category,
                },
            )

            if ok:
                stage_elapsed = int((time.perf_counter() - stage_started) * 1000)
                perf_summary["stage_attempts"][stage_name] = attempt
                perf_summary["stage_elapsed_ms"][stage_name] = stage_elapsed
                return True, detail, {
                    "attempts": attempt,
                    "elapsed_ms": stage_elapsed,
                    "retry_category": category,
                }

            if category in {"fatal", "resource"}:
                break

            dynamic_limit = max(dynamic_limit, effective_retry_limit(base_limit, detail))

            if on_retry is not None:
                try:
                    on_retry()
                except Exception:
                    pass

            delay = next_retry_delay_sec(detail, attempt)
            delay = delay * runtime_retry_delay_scale
            if delay > 0:
                time.sleep(delay)

        stage_elapsed = int((time.perf_counter() - stage_started) * 1000)
        perf_summary["stage_attempts"][stage_name] = attempt
        perf_summary["stage_elapsed_ms"][stage_name] = stage_elapsed
        append_ledger(
            stage_name,
            "failed",
            failure_grade,
            last_detail,
            {
                "attempts": attempt,
                "elapsed_ms": stage_elapsed,
                "dynamic_limit": dynamic_limit,
                "retry_category": classify_retry_reason(last_detail),
            },
        )
        return False, last_detail, {
            "attempts": attempt,
            "elapsed_ms": stage_elapsed,
            "retry_category": classify_retry_reason(last_detail),
        }

    try:
        connect_locate_timeout_sec = max(2.0, min(30.0, float(request.timeout_per_step)))

        # Capture stacked windows before VS Code is connected/activated.
        refresh_restore_capture("foreground_capture", "captured_previous_foreground_windows")

        ok, detail, stage_meta = run_stage(
            stage_name="connect",
            operation=sender.connect_to_vscode,
            failure_grade="fatal",
            attempt_timeout_sec=connect_locate_timeout_sec,
        )
        if not ok:
            return finalize_stage_failure("connect", detail, "fatal", "stage", stage_meta)

        ok, detail, stage_meta = run_stage(
            stage_name="locate_input",
            operation=sender.locate_chat_input,
            failure_grade="fatal",
            attempt_timeout_sec=connect_locate_timeout_sec,
        )
        if not ok:
            return finalize_stage_failure("locate_input", detail, "fatal", "stage", stage_meta)

        ui_start = time.perf_counter()
        ui_ok, ui_reason, ui_details = sender.run_ui_health_check()
        ui_elapsed = int((time.perf_counter() - ui_start) * 1000)
        perf_summary["stage_elapsed_ms"]["ui_health"] = ui_elapsed
        append_ledger(
            "ui_health",
            "ok" if ui_ok else "failed",
            "none" if ui_ok else classify_retry_reason(ui_reason),
            ui_reason,
            {"elapsed_ms": ui_elapsed, **ui_details},
        )
        if not ui_ok:
            grade = "fatal" if classify_retry_reason(ui_reason) == "fatal" else "recoverable"
            return finalize_stage_failure("ui_health", ui_reason, grade, "ui", ui_details)

        ok, detail, stage_meta = run_stage(
            stage_name="prepare",
            operation=sender.prepare_and_focus_input,
            failure_grade="recoverable",
        )
        if not ok:
            return finalize_stage_failure(
                "prepare",
                detail,
                "recoverable",
                "stage",
                stage_meta,
            )

        snapshot_start = time.perf_counter()
        pre_signature = sender._capture_transcript_signature()
        snapshot_elapsed = int((time.perf_counter() - snapshot_start) * 1000)
        perf_summary["stage_elapsed_ms"]["snapshot"] = snapshot_elapsed
        append_ledger(
            "snapshot",
            "ok",
            "none",
            "pre_signature_captured",
            {"elapsed_ms": snapshot_elapsed, **pre_signature},
        )

        pre_send_delay_ms = runtime_pre_send_delay_ms
        if pre_send_delay_ms > 0:
            delay_start = time.perf_counter()
            time.sleep(float(pre_send_delay_ms) / 1000.0)
            delay_elapsed = int((time.perf_counter() - delay_start) * 1000)
            perf_summary["stage_elapsed_ms"]["pre_send_delay"] = delay_elapsed
            append_ledger(
                "pre_send_delay",
                "ok",
                "none",
                "pre_send_delay_applied",
                {
                    "requested_ms": max(0, min(60000, int(request.pre_send_delay_ms))),
                    "effective_ms": pre_send_delay_ms,
                    "elapsed_ms": delay_elapsed,
                    "adaptive_mode": safe_single_line(runtime_verify_profile.get("mode", "")),
                },
            )
            refresh_restore_capture("foreground_recapture", "recaptured_after_pre_send_delay")

        ok, detail, stage_meta = run_stage(
            stage_name="send",
            operation=lambda: sender.send_message_via_clipboard(
                request.message,
                ticket_id=request.ticket_id,
                adaptive_mode=safe_single_line(runtime_verify_profile.get("mode", "strict")),
            ),
            failure_grade="recoverable",
            on_retry=sender.prepare_and_focus_input,
        )
        if not ok:
            return finalize_stage_failure("send", detail, "recoverable", "stage", stage_meta)

        verify_start = time.perf_counter()
        verify_status, verify_reason, verify_details = sender.verify_message_sent(
            pre_signature=pre_signature,
            require_transcript_confirmation=request.require_transcript_confirmation,
            message_fragments=message_fragments,
            message_text=request.message,
            ticket_id=request.ticket_id,
            verification_profile=runtime_verify_profile,
        )
        verify_elapsed = int((time.perf_counter() - verify_start) * 1000)
        perf_summary["stage_elapsed_ms"]["verify"] = verify_elapsed

        grade = "none"
        success = True
        if verify_status == "uncertain":
            grade = "uncertain"
            success = False
        elif verify_status == "failed":
            grade = "recoverable"
            success = False

        append_ledger(
            "verify",
            verify_status,
            grade,
            verify_reason,
            {"elapsed_ms": verify_elapsed, **verify_details},
        )

        return finalize_outcome(
            SendOutcome(
                success=success,
                status=verify_status,
                token=token,
                reason=verify_reason,
                grade=grade,
                fallback_action=build_fallback_action(verify_status, grade),
                details={
                    "phase": "verify",
                    "verify": verify_details,
                    "message_fragments": message_fragments,
                },
            )
        )
    finally:
        sender.close()


def send_to_copilot_chat_prod(message: str, max_retries: int = 3) -> Tuple[bool, str]:
    logger = setup_logging()
    request = SendRequest(message=message, max_retries=max_retries)
    policy = WindowBindingPolicy()
    outcome = run_send_request(request=request, policy=policy, logger=logger)
    payload = serialize_outcome_with_ahk_compat(outcome)
    return outcome.success, json.dumps(payload, ensure_ascii=True)


def send_message_with_instrumentation(
    message: str,
    ticket_id: str = "",
    event: str = "",
    max_retries: int = 3,
) -> Dict[str, Any]:
    logger = setup_logging()
    request = SendRequest(
        message=message,
        ticket_id=ticket_id,
        event=event,
        max_retries=max(1, int(max_retries)),
    )
    policy = WindowBindingPolicy()
    outcome = run_send_request(request=request, policy=policy, logger=logger)
    metrics = {}
    if isinstance(outcome.details, dict):
        metrics = outcome.details.get("perf", {})

    return {
        "success": bool(outcome.success),
        "status": outcome.status,
        "reason": outcome.reason,
        "metrics": metrics,
        "outcome": serialize_outcome_with_ahk_compat(outcome),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Strict Copilot Chat sender for unattended runs")
    parser.add_argument("--message", "--Message", default="", help="Message text to send")
    parser.add_argument(
        "--message-file",
        "--MessageFile",
        default="",
        help="Path to UTF-8 text file containing message",
    )
    parser.add_argument("--ticket-id", default="", help="Ticket id for idempotency ledger")
    parser.add_argument("--event", default="", help="Event name for ledger and ack")
    parser.add_argument("--relay-path", default="", help="Relay markdown path; ack sidecar will be written")
    parser.add_argument("--ledger-path", default="", help="Optional ledger JSONL path override")
    parser.add_argument("--dedupe-token", default="", help="Optional explicit dedupe token")
    parser.add_argument("--workspace-hint", default="", help="Substring required in VS Code window title")
    parser.add_argument(
        "--window-title-regex",
        default=r".*Visual Studio Code.*",
        help="Regex for VS Code window title",
    )
    parser.add_argument("--vscode-pid", type=int, default=0, help="Expected VS Code process id")
    parser.add_argument("--window-handle", type=int, default=0, help="Expected window handle")
    parser.add_argument(
        "--max-retries",
        "--MaxRetries",
        type=int,
        default=3,
        help="Max retries for connect/locate loops",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout per verification step in seconds")
    parser.add_argument("--timeout-ms", "--TimeoutMs", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--disable-health-check", action="store_true", help="Skip environment preflight checks")
    parser.add_argument(
        "--circuit-breaker-threshold",
        type=int,
        default=5,
        help="Open circuit after N consecutive failed/uncertain results",
    )
    parser.add_argument("--circuit-breaker-cooldown-sec", type=int, default=900, help="Circuit open cooldown seconds")
    parser.add_argument(
        "--allow-input-clear-only",
        action="store_true",
        help="Allow input-clear-only verification (less strict)",
    )
    parser.add_argument(
        "--restore-previous-foreground-window",
        "--RestorePreviousForegroundWindow",
        dest="restore_previous_foreground_window_override",
        action="store_const",
        const=True,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-restore-previous-foreground-window",
        "--NoRestorePreviousForegroundWindow",
        dest="restore_previous_foreground_window_override",
        action="store_const",
        const=False,
        default=None,
        help="Do not restore previous foreground window after send",
    )
    parser.add_argument(
        "--pre-send-delay-ms",
        "--PreSendDelayMs",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-activate-window",
        "--NoActivateWindow",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--require-active-code-window",
        "--RequireActiveCodeWindow",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--allow-inconclusive-submit-outcome",
        "--AllowInconclusiveSubmitOutcome",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--enable-esc-preflight",
        "--EnableEscPreflight",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--enable-auto-reconnect-resend",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-auto-reconnect-resend",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-palette-focus-command",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--enable-palette-focus-command",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--use-click-focus-fallback",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-click-focus-fallback",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-maximize-code-window",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-reset-zoom-before-send",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--chat-bottom-avoid-px",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--chat-input-right-offset-px",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--chat-input-x-mode",
        default="",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--reconnect-resend-delay-ms",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--reconnect-detect-window-sec",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-chat-toggle-shortcut",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--enable-chat-toggle-shortcut",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--chat-toggle-shortcut",
        default="",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--restore-previous-window-count",
        "--RestorePreviousWindowCount",
        type=int,
        default=12,
        help="How many previous foreground windows to capture for restore",
    )
    parser.add_argument(
        "--restore-previous-window-handles-csv",
        "--RestorePreviousWindowHandlesCsv",
        default="",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--enable-below-anchor-restore-fallback",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--disable-adaptive-load",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--adaptive-high-load-memory-percent",
        type=int,
        default=ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--adaptive-high-load-available-mb",
        type=int,
        default=ADAPTIVE_HIGH_LOAD_AVAILABLE_MB,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--adaptive-low-load-memory-percent",
        type=int,
        default=ADAPTIVE_LOW_LOAD_MEMORY_PERCENT,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--adaptive-low-load-available-mb",
        type=int,
        default=ADAPTIVE_LOW_LOAD_AVAILABLE_MB,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--json-output", action="store_true", help="Print outcome as JSON only")
    args, unknown = parser.parse_known_args()
    setattr(args, "_unknown_args", unknown)
    return args


def load_message(args: argparse.Namespace) -> str:
    if args.message_file:
        path = Path(args.message_file)
        return path.read_text(encoding="utf-8")
    return args.message


def main() -> int:
    args = parse_args()
    logger = setup_logging()

    unknown_args = getattr(args, "_unknown_args", [])
    if unknown_args:
        unknown_text = ",".join(safe_single_line(item) for item in unknown_args[:20])
        logger.warning("ignored_unsupported_args=%s", unknown_text)

    try:
        message = load_message(args)
    except Exception as exc:
        logger.error("message_load_failed detail=%s", safe_single_line(exc))
        return 1

    # Pre-send validation: reject messages with no visible content or exceeding length limit.
    if not message or not any(c.isprintable() or c in '\n\r\t' for c in message):
        logger.error("message_contains_no_visible_content")
        if args.json_output:
            print(json.dumps({"success": False, "status": "failed", "reason": "message_contains_no_visible_content"}))
        return 3

    if len(message) > 12000:
        logger.error("message_too_long len=%d max=12000", len(message))
        if args.json_output:
            print(json.dumps({"success": False, "status": "failed", "reason": "message_too_long", "detail": "max_len=12000"}))
        return 4

    if not message.strip():
        logger.error("empty_message")
        return 1

    if bool(args.dry_run):
        dry_run_outcome = SendOutcome(
            success=False,
            status="failed",
            token="dry-run",
            reason="dry_run_no_dispatch",
            grade="none",
            fallback_action="none",
            details={"phase": "dry_run"},
        )
        dry_run_json = json.dumps(serialize_outcome_with_ahk_compat(dry_run_outcome), ensure_ascii=True)
        print(dry_run_json)
        return 0

    active_window_only = bool(args.no_activate_window or args.require_active_code_window)
    effective_timeout = max(2.0, float(args.timeout))
    if int(args.timeout_ms) > 0:
        effective_timeout = max(2.0, float(args.timeout_ms) / 1000.0)

    restore_previous_foreground_window = True
    if args.restore_previous_foreground_window_override is not None:
        restore_previous_foreground_window = bool(args.restore_previous_foreground_window_override)

    policy = WindowBindingPolicy(
        title_regex=args.window_title_regex,
        workspace_hint=args.workspace_hint,
        expected_pid=max(0, int(args.vscode_pid)),
        expected_handle=max(0, int(args.window_handle)),
        active_window_only=active_window_only,
        allow_below_anchor_restore_fallback=bool(args.enable_below_anchor_restore_fallback),
    )

    request = SendRequest(
        message=message,
        ticket_id=args.ticket_id,
        event=args.event,
        relay_path=args.relay_path,
        ledger_path=args.ledger_path,
        dedupe_token=args.dedupe_token,
        max_retries=max(1, int(args.max_retries)),
        timeout_per_step=effective_timeout,
        require_transcript_confirmation=not bool(
            args.allow_input_clear_only or args.allow_inconclusive_submit_outcome
        ),
        health_check_enabled=not bool(args.disable_health_check),
        circuit_breaker_threshold=max(1, int(args.circuit_breaker_threshold)),
        circuit_breaker_cooldown_sec=max(0, int(args.circuit_breaker_cooldown_sec)),
        restore_previous_foreground_window=restore_previous_foreground_window,
        restore_previous_window_count=max(1, min(30, int(args.restore_previous_window_count))),
        restore_previous_window_handles_csv=safe_single_line(args.restore_previous_window_handles_csv),
        pre_send_delay_ms=max(0, min(60000, int(args.pre_send_delay_ms))),
        esc_preflight_enabled=bool(args.enable_esc_preflight),
        adaptive_load_enabled=not bool(args.disable_adaptive_load),
        adaptive_high_load_memory_percent=max(50, min(99, int(args.adaptive_high_load_memory_percent))),
        adaptive_high_load_available_mb=max(128, min(16384, int(args.adaptive_high_load_available_mb))),
        adaptive_low_load_memory_percent=max(30, min(95, int(args.adaptive_low_load_memory_percent))),
        adaptive_low_load_available_mb=max(256, min(32768, int(args.adaptive_low_load_available_mb))),
    )

    outcome = run_send_request(request=request, policy=policy, logger=logger)
    outcome_json = json.dumps(serialize_outcome_with_ahk_compat(outcome), ensure_ascii=True)

    if args.json_output:
        print(outcome_json)
    else:
        logger.info("send_outcome %s", outcome_json)
        print(outcome_json)

    if outcome.status in {"confirmed", "idempotent"} and outcome.success:
        return 0
    if outcome.status == "uncertain":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
