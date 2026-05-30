#!/usr/bin/env python3
"""
IPC Chat Sender — pure IPC chat message delivery for VS Code.

No UI automation (pywinauto / AHK) is involved.  A VS Code extension
(vscode-chat-sender) polls a command file and processes messages on
its own schedule.  Both normal and high priorities clear the pending
queue before sending to avoid VS Code's confirmation dialog.

Multi-instance routing:
  Auto-detects the target VS Code instance PID from the VSCODE_PID
  environment variable (integrated terminal) or the first Code.exe
  process with a window title (external terminal).  Pass --target-pid
  explicitly to target a specific instance when multiple VS Code
  windows are open.

Usage:
    python ipc_chat_sender.py --message "hello"
    python ipc_chat_sender.py --message "status" --priority normal
    python ipc_chat_sender.py --message "urgent" --priority high
    python ipc_chat_sender.py --message "test" --target-pid 12345 --json-output

Dependencies:
    - VS Code >= 1.82 with GitHub Copilot extension
    - The vscode-chat-sender extension must be installed
      (run `tools\\test\\install_ipc_chat_extension.ps1` once)

Exit codes:
    0   message sent successfully
    2   extension reported failure (check reason in JSON output)
    3   validation error (empty message)
    1   fatal error (timeout, write failure)
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time


def resolve_target_pid(preferred_pid: int) -> int:
    """Auto-detect the target VS Code main-window PID.

    Order:
      1. preferred_pid if > 0 (verified as a running Code.exe process)
      2. $VSCODE_PID environment variable
      3. First Code.exe process with a non-empty MainWindowTitle
    """
    if preferred_pid > 0:
        # Verify the specified PID belongs to a running Code.exe process.
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'Get-Process -Id {preferred_pid} -ErrorAction SilentlyContinue | '
                 f'Where-Object {{ $_.Name -eq "Code" }} | Select-Object -ExpandProperty Id'],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return preferred_pid
        except Exception:
            pass
        # PID invalid or not Code.exe — fall through to auto-detect.
        preferred_pid = 0

    vscode_pid = os.environ.get('VSCODE_PID', '').strip()
    if vscode_pid:
        try:
            pid = int(vscode_pid)
            if pid > 0:
                return pid
        except ValueError:
            pass

    # Fallback: find the newest Code.exe with a window title.
    # PowerShell equivalent:
    #   Get-Process -Name Code | Where-Object MainWindowTitle | ...
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-Process -Name Code -ErrorAction SilentlyContinue | '
             'Where-Object { -not [string]::IsNullOrWhiteSpace($_.MainWindowTitle) } | '
             'Sort-Object StartTime -Descending | '
             'Select-Object -First 1 -ExpandProperty Id'],
            capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            raw = result.stdout.strip()
            if raw:
                pid = int(raw)
                if pid > 0:
                    return pid
    except Exception:
        pass

    return 0


def get_file_paths(pid: int) -> tuple:
    """Return (cmd_file, res_file) tuple.

    When PID > 0, use PID-scoped files for instance-specific routing.
    Otherwise, use legacy shared file paths.
    """
    tmpdir = tempfile.gettempdir()
    if pid > 0:
        return (
            os.path.join(tmpdir, f'vscode_chat_send_cmd_{pid}.json'),
            os.path.join(tmpdir, f'vscode_chat_send_res_{pid}.json'),
        )
    return (
        os.path.join(tmpdir, 'vscode_chat_send_cmd.json'),
        os.path.join(tmpdir, 'vscode_chat_send_result.json'),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description='IPC Chat Sender for VS Code')
    parser.add_argument('--message', default='', help='Message text to send')
    parser.add_argument('--request-id', default='', help='Optional request identifier')
    parser.add_argument('--priority', default='normal', choices=['normal', 'high'],
                        help='Send priority: normal (queue, clears queue first, no dialog) '
                             'or high (cancel + clear + submit, no dialog)')
    parser.add_argument('--target-pid', type=int, default=0,
                        help='Target VS Code main-window PID (0 = auto-detect)')
    parser.add_argument('--json-output', action='store_true', help='Print result as JSON')
    parser.add_argument('--auto-escalate', action='store_true',
                        help='With --priority normal: if send times out, '
                             'auto-retry with --priority high')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Maximum seconds to wait for extension response (default: 30)')
    parser.add_argument('--poll-interval', type=int, default=200,
                        help='Polling interval in milliseconds (default: 200)')
    parser.add_argument('--mode', default='visible', choices=['silent', 'visible', 'auto'],
                        help='Delivery mode: silent (LM API only, captures AI response), '
                             'visible (clipboard only, shows in chat panel), '
                             'auto (LM API first, fallback to clipboard, default)')
    args = parser.parse_args()

    message = args.message.strip()
    if not message:
        if args.json_output:
            print(json.dumps({'success': False, 'reason': 'empty_message'}))
        return 3

    # Resolve target PID and file paths.
    target_pid = resolve_target_pid(args.target_pid)
    cmd_file, res_file = get_file_paths(target_pid)

    def send_attempt(priority: str) -> dict | None:
        """Write command file and poll for result.

        Returns outcome dict on success, None on timeout.
        """
        # 1. Write command file — the extension polls for this.
        cmd_payload = {
            'message': message,
            'request_id': args.request_id,
            'priority': priority,
            'mode': args.mode,
        }
        try:
            with open(cmd_file, 'w', encoding='utf-8') as f:
                json.dump(cmd_payload, f, ensure_ascii=False)
        except Exception as exc:
            return {'success': False, 'reason': f'write_cmd_failed:{exc}'}

        # 2. Remove any stale result from a previous invocation.
        if os.path.isfile(res_file):
            try:
                os.unlink(res_file)
            except Exception:
                pass

        # 3. Poll for the result.
        poll_interval_sec = args.poll_interval / 1000.0
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            if os.path.isfile(res_file):
                try:
                    with open(res_file, 'r', encoding='utf-8') as f:
                        outcome = json.load(f)
                    os.unlink(res_file)
                    return outcome
                except Exception:
                    time.sleep(poll_interval_sec)
                    continue
            time.sleep(poll_interval_sec)

        # Timeout — clean up command file.
        if os.path.isfile(cmd_file):
            try:
                os.unlink(cmd_file)
            except Exception:
                pass
        return None

    # ---- initial attempt with configured priority ----
    outcome = send_attempt(args.priority)

    # ---- auto-escalate: normal timeout → retry with high ----
    escalated = False
    if outcome is None and args.auto_escalate and args.priority == 'normal':
        outcome = send_attempt('high')
        if outcome is not None:
            escalated = True

    # ---- final outcome ----
    if outcome is None:
        outcome = {'success': False, 'reason': 'poll_timeout'}
    elif escalated:
        outcome = dict(outcome)
        outcome['escalated'] = True
        outcome['escalated_reason'] = 'normal_timeout_retry_with_high'

    if args.json_output:
        outcome.update({'target_pid': target_pid})
        print(json.dumps(outcome, ensure_ascii=False))

    if outcome.get('success'):
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
