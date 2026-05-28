// vscode-chat-sender extension
// Sends messages to VS Code chat via the official vscode.chat.sendRequest API.
// No UI automation (pywinauto / AHK) required — pure IPC.
//
// The extension does NOT use a custom `code --command` because VS Code's
// CLI IPC does not dispatch to extension-registered commands.  Instead the
// extension monitors a well-known command file and processes messages on
// its own schedule.
//
// Protocol (JSON command file):
//   Input:  %TEMP%\vscode_chat_send_cmd.json  ← written by caller
//   Output: %TEMP%\vscode_chat_send_result.json  ← written by extension
//
// Input file schema:
//   { "message": "<text>", "request_id": "<optional-id>" }
//
// Output file schema:
//   { "success": bool, "reason": "<status-text>", "request_id": "<echoed>" }

const vscode = require('vscode');
const fs = require('fs');
const OS = require('os');

const CMD_FILE = OS.tmpdir() + '/vscode_chat_send_cmd.json';
const RESULT_FILE = OS.tmpdir() + '/vscode_chat_send_result.json';

function writeResult(data) {
    try { fs.writeFileSync(RESULT_FILE, JSON.stringify(data, null, 0), 'utf-8'); } catch (_) {}
}

function tryProcessCommand() {
    try {
        if (!fs.existsSync(CMD_FILE)) return;
        const raw = fs.readFileSync(CMD_FILE, 'utf-8');
        const cmd = JSON.parse(raw);
        try { fs.unlinkSync(CMD_FILE); } catch (_) {}

        const message = cmd.message || '';
        const requestId = cmd.request_id || '';
        const submitChord = cmd.submit_chord || 'enter';

        if (!message) {
            writeResult({ success: false, reason: 'no_message', request_id: requestId });
            return;
        }

        // Dispatch async — the polling is fire-and-forget.
        setImmediate(async () => {
            try {
                try { await vscode.commands.executeCommand('workbench.action.chat.open'); } catch (_) {}

                if (!vscode.chat || typeof vscode.chat.sendRequest !== 'function') {
                    // sendRequest not available (VS Code stable API).  Use
                    // clipboard + command-based paste as a reliable fallback.
                    await sendViaClipboardFallback(message, requestId, submitChord);
                    return;
                }

                const candidates = ['GitHub.copilot', 'GitHub.copilot/copilot', 'copilot'];
                let lastErr = null;
                for (const pid of candidates) {
                    try {
                        await vscode.chat.sendRequest(pid, message);
                        writeResult({ success: true, reason: 'sent', participant: pid, request_id: requestId });
                        return;
                    } catch (err) {
                        lastErr = err;
                    }
                }

                try {
                    await vscode.chat.sendRequest(undefined, message);
                    writeResult({ success: true, reason: 'sent_default', request_id: requestId });
                    return;
                } catch (err) {
                    lastErr = err;
                }

                writeResult({
                    success: false, reason: 'all_participants_failed',
                    detail: String(lastErr), request_id: requestId,
                });
            } catch (err) {
                writeResult({
                    success: false, reason: 'command_error',
                    detail: String(err), request_id: requestId,
                });
            }
        });
    } catch (_) {}
}

// Poll the command file every 300ms.
let pollTimer = null;

function activate(context) {
    writeResult({ success: false, reason: 'extension_activated' });

    // Process any existing command immediately, then poll.
    tryProcessCommand();
    pollTimer = setInterval(tryProcessCommand, 300);

    // Clean up on deactivation.
    context.subscriptions.push({
        dispose: function () {
            if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        }
    });
}

function deactivate() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

/**
 * Fallback: set clipboard, open+focus chat, paste via IPC command, then submit.
 * All operations use VS Code's own command system — no UIA required.
 */
async function sendViaClipboardFallback(message, requestId, submitChord) {
    try {
        await vscode.env.clipboard.writeText(message);
        await vscode.commands.executeCommand('workbench.action.chat.open');
        await vscode.commands.executeCommand('workbench.action.chat.focusInput');
        await new Promise(r => setTimeout(r, 400));
        try { await vscode.commands.executeCommand('editor.action.clipboardPasteAction'); } catch (_) {}
        await new Promise(r => setTimeout(r, 300));
        // `workbench.action.chat.submit` handles all submit chords (Enter,
        // Ctrl+Enter, Alt+Enter) — the chord is a user preference, not a
        // separate command.
        try { await vscode.commands.executeCommand('workbench.action.chat.submit'); } catch (_) {}
        writeResult({ success: true, reason: 'sent_via_clipboard_fallback', request_id: requestId });
    } catch (err) {
        writeResult({ success: false, reason: 'clipboard_fallback_failed', detail: String(err), request_id: requestId });
    }
}

exports.activate = activate;
exports.deactivate = deactivate;

