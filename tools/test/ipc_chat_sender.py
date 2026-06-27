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
    python ipc_chat_sender.py --discover

Dependencies:
    - VS Code >= 1.82 with GitHub Copilot extension
    - The vscode-chat-sender extension must be installed
      (run `tools\\test\\install_ipc_chat_extension.ps1` once)

Exit codes:
    0   message/discovery completed successfully
    1   local transport failure (poll_timeout, write_cmd_failed)
    2   extension-side failure (check reason in JSON output)
    3   validation error (empty message when not using --discover)
"""

import argparse
from collections import defaultdict
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid


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


def print_discovery_models(models: list[dict]) -> None:
    """Print discovery results in a readable non-JSON format."""
    ordered = sorted(
        models,
        key=lambda item: (str(item.get('vendor', '')), str(item.get('name', ''))),
    )

    grouped: dict[str, list[dict]] = defaultdict(list)
    for model in ordered:
        vendor = str(model.get('vendor') or 'unknown')
        grouped[vendor].append(model)

    print()
    print('Available Models (grouped by vendor):')
    print('-' * 140)

    header = (
        f"{'Model Name':40} "
        f"{'ID':30} "
        f"{'Family':22} "
        f"{'Version':22} "
        f"{'MaxInputTokens':14}"
    )

    for vendor in sorted(grouped.keys()):
        print()
        print(f'[{vendor}]')
        print(header)
        print('-' * len(header))
        for model in grouped[vendor]:
            max_tokens = model.get('maxInputTokens')
            if isinstance(max_tokens, int):
                max_tokens_text = f'{max_tokens:,}'
            elif max_tokens is None:
                max_tokens_text = '-'
            else:
                max_tokens_text = str(max_tokens)

            print(
                f"{str(model.get('name') or '')[:40]:40} "
                f"{str(model.get('id') or '')[:30]:30} "
                f"{str(model.get('family') or '')[:22]:22} "
                f"{str(model.get('version') or '')[:22]:22} "
                f"{max_tokens_text:>14}"
            )

    print('-' * 140)
    print(f'[{len(ordered)} model(s) total]')
    print('Tip: use --json-output for scripting.')


def main() -> int:
    # Parameter-set style parsing to match PowerShell behavior:
    # - send mode: validate --message
    # - discover mode: independent branch, no message validation
    discover_probe = argparse.ArgumentParser(add_help=False)
    discover_probe.add_argument('--discover', action='store_true')
    discover_probe_args, _ = discover_probe.parse_known_args()
    discover_mode = discover_probe_args.discover

    parser = argparse.ArgumentParser(description='IPC Chat Sender for VS Code')
    if discover_mode:
        parser.add_argument('--discover', action='store_true',
                            help='List all available LM models with metadata (no message sent)')
    else:
        parser.add_argument('--message', default='', help='Message text to send')

    parser.add_argument('--request-id', default='',
                        help='Optional request identifier. '
                             'Auto-generated when omitted and used for result binding.')
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
                            'auto (LM API first, fallback to clipboard). '
                            'Default: visible')
    parser.add_argument('--model', default='',
                        help='Preferred model name/id for LM API, e.g. "DeepSeek V4 Flash", '
                             '"GPT-5.5", "auto". Empty = default selection')
    parser.add_argument('--model-options', type=json.loads, default=None,
                        help='JSON object of model-specific options passed to LM API, '
                             'e.g. \'{"thinking_mode":"deep"}\'')
    parser.add_argument('--lm-response-timeout-ms', type=int, default=0,
                        help='Per-request LM API response timeout in milliseconds '
                             '(1000-3600000). Overrides VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS '
                             'env var. 0 = use env var or default.')
    args = parser.parse_args()

    if discover_mode:
        message = ''
    else:
        message = args.message.strip()
        if not message:
            if args.json_output:
                print(json.dumps({'success': False, 'reason': 'empty_message'}))
            return 3

    request_id_input = str(args.request_id or '').strip()
    request_id_auto_generated = (request_id_input == '')
    effective_request_id = request_id_input or f'auto-{uuid.uuid4().hex}'

    # Resolve target PID and file paths.
    target_pid = resolve_target_pid(args.target_pid)
    cmd_file, res_file = get_file_paths(target_pid)

    def send_attempt(priority: str) -> dict | None:
        """Write command file and poll for result.

        Returns outcome dict on success, None on timeout.
        """
        # 1. Remove stale result before issuing a new command.
        # If deletion happens after command write, fast extension responses can be
        # accidentally removed and appear as poll_timeout.
        if os.path.isfile(res_file):
            try:
                os.unlink(res_file)
            except Exception:
                pass

        # 2. Write command file — the extension polls for this.
        cmd_payload = {
            'message': message,
            'request_id': effective_request_id,
            'priority': priority,
            'mode': args.mode,
            'model': args.model,
            'discover': discover_mode,
        }
        if args.model_options is not None:
            cmd_payload['model_options'] = args.model_options
        if args.lm_response_timeout_ms > 0:
            cmd_payload['lm_response_timeout_ms'] = args.lm_response_timeout_ms
        try:
            with open(cmd_file, 'w', encoding='utf-8') as f:
                json.dump(cmd_payload, f, ensure_ascii=False)
        except Exception as exc:
            return {
                'success': False,
                'reason': f'write_cmd_failed:{exc}',
                'request_id': effective_request_id,
            }

        # 3. Poll for the result.
        poll_interval_sec = args.poll_interval / 1000.0
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            if os.path.isfile(res_file):
                try:
                    with open(res_file, 'r', encoding='utf-8') as f:
                        outcome = json.load(f)

                    result_request_id = str(outcome.get('request_id') or '')
                    reason_text = str(outcome.get('reason') or '')
                    request_id_matches = (result_request_id == effective_request_id)
                    if not request_id_matches:
                        # Compatibility: older extensions may not echo request_id
                        # for discovery responses.
                        is_legacy_discover_no_request_id = (
                            discover_mode and
                            result_request_id == '' and
                            reason_text in ('discovery', 'discovery_failed')
                        )
                        if not is_legacy_discover_no_request_id:
                            time.sleep(poll_interval_sec)
                            continue

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
        outcome = {
            'success': False,
            'reason': 'poll_timeout',
            'request_id': effective_request_id,
        }
    elif escalated:
        outcome = dict(outcome)
        outcome['escalated'] = True
        outcome['escalated_reason'] = 'normal_timeout_retry_with_high'

    if not str(outcome.get('request_id') or ''):
        outcome['request_id'] = effective_request_id
    outcome['request_id_auto_generated'] = request_id_auto_generated

    if args.json_output:
        outcome.update({'target_pid': target_pid})
        print(json.dumps(outcome, ensure_ascii=False))
    elif discover_mode and outcome.get('success') and isinstance(outcome.get('models'), list):
        print_discovery_models(outcome.get('models', []))
    elif discover_mode and not outcome.get('success'):
        reason = str(outcome.get('reason', 'unknown_error'))
        print(f'Discovery failed: {reason}', file=sys.stderr)

    if outcome.get('success'):
        return 0

    failure_reason = str(outcome.get('reason') or '')
    is_local_failure = (
        failure_reason == 'poll_timeout' or
        failure_reason.startswith('write_cmd_failed')
    )
    if is_local_failure:
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main())
