#!/usr/bin/env python3
"""
IPC Chat Sender — pure IPC chat message delivery for VS Code.

No UI automation (pywinauto / AHK) is involved.  A VS Code extension
(vscode-chat-sender) polls a command file and sends the message via
vscode.chat.sendRequest() — no `code --command` needed.

Usage:
    python ipc_chat_sender.py --message "hello" [--request-id "id123"] [--json-output]

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
import sys
import tempfile
import time

CMD_FILE = os.path.join(tempfile.gettempdir(), 'vscode_chat_send_cmd.json')
RESULT_FILE = os.path.join(tempfile.gettempdir(), 'vscode_chat_send_result.json')
POLL_TIMEOUT_SEC = 30
POLL_INTERVAL_SEC = 0.2


def main() -> int:
    parser = argparse.ArgumentParser(description='IPC Chat Sender for VS Code')
    parser.add_argument('--message', default='', help='Message text to send')
    parser.add_argument('--request-id', default='', help='Optional request identifier')
    parser.add_argument('--submit-chord', default='enter', choices=['enter', 'ctrl-enter', 'alt-enter'],
                        help='Submit chord (for protocol alignment; IPC submit handles all chords)')
    parser.add_argument('--json-output', action='store_true', help='Print result as JSON')
    args = parser.parse_args()

    message = args.message.strip()
    if not message:
        if args.json_output:
            print(json.dumps({'success': False, 'status': 'failed', 'reason': 'empty_message'}))
        return 3

    # 1. Write command file — the extension polls for this.
    cmd_payload = {
        'message': message,
        'request_id': args.request_id,
        'submit_chord': args.submit_chord,
    }
    try:
        with open(CMD_FILE, 'w', encoding='utf-8') as f:
            json.dump(cmd_payload, f, ensure_ascii=False)
    except Exception as exc:
        if args.json_output:
            print(json.dumps({'success': False, 'status': 'failed', 'reason': f'write_cmd_failed:{exc}'}))
        return 1

    # 2. Remove any stale result from a previous invocation.
    if os.path.isfile(RESULT_FILE):
        try:
            os.unlink(RESULT_FILE)
        except Exception:
            pass

    # 3. Poll for the result — the extension reads the command file on its
    #    own polling schedule (~300 ms interval).
    deadline = time.time() + POLL_TIMEOUT_SEC
    outcome = None
    while time.time() < deadline:
        if os.path.isfile(RESULT_FILE):
            try:
                with open(RESULT_FILE, 'r', encoding='utf-8') as f:
                    outcome = json.load(f)
                os.unlink(RESULT_FILE)
                break
            except Exception:
                time.sleep(POLL_INTERVAL_SEC)
                continue
        time.sleep(POLL_INTERVAL_SEC)

    if outcome is None:
        outcome = {'success': False, 'reason': 'poll_timeout'}
        if os.path.isfile(CMD_FILE):
            try:
                os.unlink(CMD_FILE)
            except Exception:
                pass

    if args.json_output:
        print(json.dumps(outcome, ensure_ascii=False))

    if outcome.get('success'):
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
