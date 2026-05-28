#!/usr/bin/env python3
"""
IPC Chat Sender — pure IPC chat message delivery for VS Code.

No UI automation (pywinauto / AHK) is involved.  A VS Code extension
(vscode-chat-sender) polls a command file and sends the message via
vscode.chat.sendRequest() — no `code --command` needed.

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

POLL_TIMEOUT_SEC = 30
POLL_INTERVAL_SEC = 0.2


def resolve_target_pid(preferred_pid: int) -> int:
    """Auto-detect the target VS Code main-window PID.

    Order:
      1. preferred_pid if > 0
      2. $VSCODE_PID environment variable
      3. First Code.exe process with a non-empty MainWindowTitle
    """
    if preferred_pid > 0:
        return preferred_pid

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
                        help='Send priority: normal (queue) or high (interrupt)')
    parser.add_argument('--target-pid', type=int, default=0,
                        help='Target VS Code main-window PID (0 = auto-detect)')
    parser.add_argument('--json-output', action='store_true', help='Print result as JSON')
    args = parser.parse_args()

    message = args.message.strip()
    if not message:
        if args.json_output:
            print(json.dumps({'success': False, 'reason': 'empty_message'}))
        return 3

    # Resolve target PID and file paths.
    target_pid = resolve_target_pid(args.target_pid)
    cmd_file, res_file = get_file_paths(target_pid)

    # 1. Write command file — the extension polls for this.
    cmd_payload = {
        'message': message,
        'request_id': args.request_id,
        'priority': args.priority,
    }
    try:
        with open(cmd_file, 'w', encoding='utf-8') as f:
            json.dump(cmd_payload, f, ensure_ascii=False)
    except Exception as exc:
        if args.json_output:
            print(json.dumps({'success': False, 'reason': f'write_cmd_failed:{exc}'}))
        return 1

    # 2. Remove any stale result from a previous invocation.
    if os.path.isfile(res_file):
        try:
            os.unlink(res_file)
        except Exception:
            pass

    # 3. Poll for the result — the extension reads the command file on its
    #    own polling schedule (~300 ms interval).
    deadline = time.time() + POLL_TIMEOUT_SEC
    outcome = None
    while time.time() < deadline:
        if os.path.isfile(res_file):
            try:
                with open(res_file, 'r', encoding='utf-8') as f:
                    outcome = json.load(f)
                os.unlink(res_file)
                break
            except Exception:
                time.sleep(POLL_INTERVAL_SEC)
                continue
        time.sleep(POLL_INTERVAL_SEC)

    if outcome is None:
        outcome = {'success': False, 'reason': 'poll_timeout'}
        if os.path.isfile(cmd_file):
            try:
                os.unlink(cmd_file)
            except Exception:
                pass

    if args.json_output:
        outcome.update({'target_pid': target_pid})
        print(json.dumps(outcome, ensure_ascii=False))

    if outcome.get('success'):
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
