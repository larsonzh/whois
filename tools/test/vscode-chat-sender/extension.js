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
//   Input:  %TEMP%\vscode_chat_send_cmd_<targetPid>.json  ← written by caller
//   Output: %TEMP%\vscode_chat_send_res_<targetPid>.json   ← written by extension
//
// Legacy (shared, deprecated):
//   Input:  %TEMP%\vscode_chat_send_cmd.json
//   Output: %TEMP%\vscode_chat_send_result.json
//
// The PID-scoped file enables multi-instance routing: each VS Code instance
// monitors only its own command file (keyed by main window PID = process.ppid).
// When a caller targets a specific PID, only that instance responds.
//
// Input file schema:
//   { "message": "<text>", "request_id": "<optional-id>", "priority": "normal|high" }
//
// Output file schema:
//   { "success": bool, "reason": "<status-text>", "request_id": "<echoed>" }

const vscode = require('vscode');
const fs = require('fs');
const OS = require('os');

// ---- Instance identity --------------------------------------------------
// The main VS Code window PID.  In the integrated terminal $env:VSCODE_PID
// holds the same value, so callers can auto-target this instance.
const MY_WINDOW_PID = process.ppid;

// ---- File path helpers --------------------------------------------------
function cmdFileForPid(pid)  { return OS.tmpdir() + '/vscode_chat_send_cmd_' + pid + '.json'; }
function resFileForPid(pid)  { return OS.tmpdir() + '/vscode_chat_send_res_' + pid + '.json'; }
function diagFileForPid(pid) { return OS.tmpdir() + '/vscode_chat_send_diag_' + pid + '.json'; }

const CMD_FILE_LEGACY  = OS.tmpdir() + '/vscode_chat_send_cmd.json';
const RES_FILE_LEGACY  = OS.tmpdir() + '/vscode_chat_send_result.json';
const CMD_FILE_PID     = cmdFileForPid(MY_WINDOW_PID);
const RES_FILE_PID     = resFileForPid(MY_WINDOW_PID);
const RES_FILE_DIAG    = diagFileForPid(MY_WINDOW_PID);

// ---- Helpers ------------------------------------------------------------
function writeResult(targetPath, data) {
    try { fs.writeFileSync(targetPath, JSON.stringify(data, null, 0), 'utf-8'); } catch (_) {}
}

function processCommandFile(cmdPath, resPath) {
    let raw, cmd;
    try {
        raw = fs.readFileSync(cmdPath, 'utf-8');
        cmd = JSON.parse(raw);
        try { fs.unlinkSync(cmdPath); } catch (_) {}
    } catch (_) {
        return;
    }

    const message = cmd.message || '';
    const requestId = cmd.request_id || '';
    const priority = (cmd.priority || 'normal').trim().toLowerCase();

    if (!message) {
        writeResult(resPath, { success: false, reason: 'no_message', request_id: requestId });
        return;
    }

    // Dispatch async — the polling is fire-and-forget.
    setImmediate(async () => {
        try {
            try { await vscode.commands.executeCommand('workbench.action.chat.open'); } catch (_) {}

            // ---- Path A: vscode.chat.sendRequest() — silent queue ----
            if (vscode.chat && typeof vscode.chat.sendRequest === 'function') {
                const candidates = ['GitHub.copilot', 'GitHub.copilot/copilot', 'copilot'];
                let lastErr = null;
                for (const pid of candidates) {
                    try {
                        await vscode.chat.sendRequest(pid, message);
                        writeResult(resPath, { success: true, reason: 'sent', participant: pid, request_id: requestId });
                        return;
                    } catch (err) {
                        lastErr = err;
                    }
                }

                try {
                    await vscode.chat.sendRequest(undefined, message);
                    writeResult(resPath, { success: true, reason: 'sent_default', request_id: requestId });
                    return;
                } catch (err) {
                    lastErr = err;
                }

                // sendRequest unavailable — fall through to clipboard.
            }

            // ---- Path B: clipboard fallback ----
            // Behaviour depends on priority:
            //   normal (default) → submit via `workbench.action.chat.submit`
            //     which silently queues if there's one active request.
            //     No dialog unless multiple messages are queued.
            //   high → call `chat.clear` first to cancel any active request,
            //     then submit immediately (interrupts current work).
            await sendViaClipboard(message, requestId, priority, resPath);
        } catch (err) {
            writeResult(resPath, {
                success: false, reason: 'command_error',
                detail: String(err), request_id: requestId,
            });
        }
    });
}

function tryProcessCommand() {
    // 1. PID-scoped file (instance-specific routing, preferred).
    if (fs.existsSync(CMD_FILE_PID)) {
        processCommandFile(CMD_FILE_PID, RES_FILE_PID);
        return;
    }
    // 2. Legacy shared file (backward compatible fallback).
    if (fs.existsSync(CMD_FILE_LEGACY)) {
        processCommandFile(CMD_FILE_LEGACY, RES_FILE_LEGACY);
    }
}

let pollTimer = null;

function activate(context) {
    // Write a diagnostic marker to a separate file (not the result path,
    // so it doesn't interfere with caller polling).
    writeResult(RES_FILE_DIAG, { success: false, reason: 'extension_activated', instance_pid: MY_WINDOW_PID });
    // Write v1.1.0-specific marker for version tracking.
    writeResult(OS.tmpdir() + '/vscode_chat_send_diag_v110_activated_' + MY_WINDOW_PID + '.json', { v: '1.1.0' });

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
 * Clipboard fallback with priority-aware submit.
 *
 * priority = "normal" (default):
 *   paste + submit via `workbench.action.chat.submit`.
 *   If chat is busy this silently queues; no dialog unless multiple
 *   messages are already queued.
 *
 * priority = "high":
 *   `chat.clear` first (cancels active request, safe, no dialog),
 *   then paste + submit.  Interrupts current work for urgent tickets.
 */
async function sendViaClipboard(message, requestId, priority, resPath) {
    try {
        // High-priority: cancel active request before paste+submit.
        if (priority === 'high') {
            try { await vscode.commands.executeCommand('workbench.action.chat.clear'); } catch (_) {}
            await new Promise(r => setTimeout(r, 300));
        }

        await vscode.env.clipboard.writeText(message);
        await vscode.commands.executeCommand('workbench.action.chat.open');
        await vscode.commands.executeCommand('workbench.action.chat.focusInput');
        await new Promise(r => setTimeout(r, 400));
        try { await vscode.commands.executeCommand('editor.action.clipboardPasteAction'); } catch (_) {}
        await new Promise(r => setTimeout(r, 300));

        try { await vscode.commands.executeCommand('workbench.action.chat.submit'); } catch (_) {}
        writeResult(resPath, { success: true, reason: 'sent_via_clipboard_fallback', request_id: requestId, priority: priority });
    } catch (err) {
        writeResult(resPath, { success: false, reason: 'clipboard_fallback_failed', detail: String(err), request_id: requestId });
    }
}

exports.activate = activate;
exports.deactivate = deactivate;

