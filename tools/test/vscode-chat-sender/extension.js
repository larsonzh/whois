// vscode-chat-sender extension
// Sends messages to VS Code Copilot Chat via clipboard paste + native
// chat commands.  No UI automation (pywinauto / AHK) required — pure IPC.
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

// ---- Tunable timing constants (override via environment variables) ------
const POLL_MS       = parseInt(process.env.VSCODE_CHAT_SENDER_POLL_MS, 10)       || 300;
const PASTE_DELAY_MS = parseInt(process.env.VSCODE_CHAT_SENDER_PASTE_DELAY_MS, 10) || 150;
const SUBMIT_DELAY_MS = parseInt(process.env.VSCODE_CHAT_SENDER_SUBMIT_DELAY_MS, 10) || 100;

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
    const mode = (cmd.mode || 'visible').trim().toLowerCase();
    const preferredModel = (cmd.model || '').trim().toLowerCase();
    // model_options: optional key-value object passed verbatim to the
    // LM API as modelOptions (e.g. thinking mode, context size).
    const modelOptions = (typeof cmd.model_options === 'object' && cmd.model_options !== null)
        ? cmd.model_options : {};
    const isDiscover = cmd.discover === true;

    // Discover mode: list all available LM models with metadata.
    if (isDiscover) {
        setImmediate(async () => {
            try {
                const models = (typeof vscode.lm?.selectChatModels === 'function')
                    ? await vscode.lm.selectChatModels({}) : [];
                const catalog = models.map(m => ({
                    name: m.name, vendor: m.vendor, id: m.id,
                    family: m.family || undefined,
                    version: m.version || undefined,
                    maxInputTokens: m.maxInputTokens || undefined,
                }));
                writeResult(resPath, {
                    success: true,
                    reason: 'discovery',
                    request_id: requestId,
                    models: catalog,
                });
            } catch (err) {
                writeResult(resPath, {
                    success: false,
                    reason: 'discovery_failed',
                    request_id: requestId,
                    detail: String(err),
                });
            }
        });
        return;
    }

    // 'silent' = LM API only, no UI; 'visible' = clipboard only;
    // 'auto' = LM API first, clipboard fallback.

    if (!message) {
        writeResult(resPath, { success: false, reason: 'no_message', request_id: requestId });
        return;
    }

    // Dispatch async — the polling is fire-and-forget.
    setImmediate(async () => {
        try {
            if (mode === 'visible') {
                // Clipboard-only: visible in chat panel, same session.
                try { await vscode.commands.executeCommand('workbench.action.chat.open'); } catch (_) {}
                await sendViaClipboard(message, requestId, priority, resPath);
                return;
            }

            // silent / auto: try LM API first.
            const lmResponseTimeoutMs = typeof cmd.lm_response_timeout_ms === 'number' ? cmd.lm_response_timeout_ms : undefined;
            const lmResult = await sendViaLmApi(message, requestId, priority, resPath, preferredModel, modelOptions, lmResponseTimeoutMs);
            if (lmResult) return;  // success — result already written

            if (mode === 'silent') {
                // LM API failed and caller demanded silent — report failure.
                writeResult(resPath, {
                    success: false, reason: 'lm_api_unavailable',
                    request_id: requestId,
                });
                return;
            }

            // auto mode: fall back to clipboard.
            try { await vscode.commands.executeCommand('workbench.action.chat.open'); } catch (_) {}
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
    // Diagnostic marker — confirms extension was loaded.
    writeResult(RES_FILE_DIAG, { success: false, reason: 'extension_activated', instance_pid: MY_WINDOW_PID });

    // ---- Diagnostic probe: vscode.chat API availability ----
    (function probeChatApi() {
        const probe = { version: '1.1.0', pid: MY_WINDOW_PID };
        probe.hasChatNamespace = typeof vscode.chat !== 'undefined';
        if (vscode.chat) {
            probe.chatKeys = Object.keys(vscode.chat);
            probe.hasSendRequest = typeof vscode.chat.sendRequest === 'function';
            probe.hasCreateChatParticipant = typeof vscode.chat.createChatParticipant === 'function';
            probe.hasRequestHandler = typeof vscode.chat.requestHandler !== 'undefined';
        }
        probe.hasLmNamespace = typeof vscode.lm !== 'undefined';
        if (vscode.lm) {
            probe.lmKeys = Object.keys(vscode.lm);
            probe.hasSelectChatModels = typeof vscode.lm.selectChatModels === 'function';
        }
        probe.vscodeVersion = typeof vscode.version !== 'undefined' ? vscode.version : 'unknown';
        probe.extensionMode = vscode.env.sessionId ? 'has_session' : 'no_session';
        try { probe.appName = vscode.env.appName; } catch (_) {}
        try { probe.appHost = vscode.env.appHost; } catch (_) {}
        try { probe.uriScheme = vscode.env.uriScheme; } catch (_) {}
        writeResult(OS.tmpdir() + '/vscode_chat_send_diag_probe_' + MY_WINDOW_PID + '.json', probe);

        // Async probe: try selectChatModels and report result
        (async () => {
            const lmProbe = { pid: MY_WINDOW_PID };
            try {
                if (typeof vscode.lm?.selectChatModels === 'function') {
                    const models = await vscode.lm.selectChatModels({});
                    lmProbe.modelCount = models?.length ?? 0;
                    if (models?.length > 0) {
                        lmProbe.modelNames = models.map(m => ({ name: m.name, vendor: m.vendor, id: m.id }));
                    }
                    // Also try with vendor filter
                    const copilotModels = await vscode.lm.selectChatModels({ vendor: 'copilot' });
                    lmProbe.copilotCount = copilotModels?.length ?? 0;
                    if (copilotModels?.length > 0) {
                        lmProbe.copilotNames = copilotModels.map(m => ({ name: m.name, vendor: m.vendor, id: m.id }));
                    }
                } else {
                    lmProbe.error = 'selectChatModels not available';
                }
            } catch (err) {
                lmProbe.error = String(err);
                lmProbe.errorCode = err.code;
                lmProbe.errorCause = err.cause ? String(err.cause) : undefined;
            }
            writeResult(OS.tmpdir() + '/vscode_chat_send_diag_lm_probe_' + MY_WINDOW_PID + '.json', lmProbe);
        })();
    })();

    // Process any existing command immediately, then poll.
    tryProcessCommand();
    pollTimer = setInterval(tryProcessCommand, POLL_MS);

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
 * Primary path: vscode.lm API — sends directly to the language model
 * without touching the clipboard, chat input, or any UI element.
 * No risk of polluting in-progress user typing.
 *
 * Captures the full AI response and includes it in the result file
 * (field `ai_response`).  Waits up to LM_RESPONSE_TIMEOUT_MS for the
 * model to finish generating.
 *
 * Returns true on success (result already written), false if unavailable.
 */
async function sendViaLmApi(message, requestId, priority, resPath, preferredModel, modelOptions, lmResponseTimeoutMs) {
    // Priority: per-request field > environment variable > default (60000ms)
    const LM_RESPONSE_TIMEOUT_MS = parseInt(
        lmResponseTimeoutMs ?? process.env.VSCODE_CHAT_SENDER_LM_RESPONSE_TIMEOUT_MS, 10) || 60000;

    try {
        if (typeof vscode.lm?.selectChatModels !== 'function') {
            return false;
        }

        // Fetch all available models without vendor filter, then find the
        // best match: caller-specified → 'auto' → DeepSeek → first.
        const allModels = await vscode.lm.selectChatModels({});
        if (!allModels || allModels.length === 0) {
            return false;
        }

        const pickModel = (models, preferred) => {
            // 0th choice: caller-specified model by name or id.
            if (preferred) {
                const pref = models.find(m =>
                    m.name.toLowerCase() === preferred ||
                    m.id.toLowerCase() === preferred
                );
                if (pref) return pref;
            }
            // 1st choice: 'auto' — Copilot decides the routing.
            const auto = models.find(m => m.id === 'auto' || m.name === 'Auto');
            if (auto) return auto;
            // 2nd choice: DeepSeek V4 Flash (matches typical chat panel).
            const ds = models.find(m => m.name === 'DeepSeek V4 Flash' || m.id === 'deepseek-v4-flash');
            if (ds) return ds;
            // Fallback: first available model.
            return models[0];
        };

        const model = pickModel(allModels, preferredModel);
        const modelInfo = { model_name: model.name, model_vendor: model.vendor, model_id: model.id };

        const userMessage = vscode.LanguageModelChatMessage.User(message);
        // Pass model_options as modelOptions if caller provided any.
        const requestOptions = {};
        if (modelOptions && Object.keys(modelOptions).length > 0) {
            requestOptions.modelOptions = modelOptions;
        }
        const response = await model.sendRequest([userMessage], requestOptions);

        // Collect the full response with a deadline.
        const chunks = [];
        const deadline = Date.now() + LM_RESPONSE_TIMEOUT_MS;
        let truncated = false;
        try {
            for await (const chunk of response.text) {
                chunks.push(chunk);
                if (Date.now() > deadline) { truncated = true; break; }
            }
        } catch (_) {}

        writeResult(resPath, {
            success: true,
            reason: 'sent_via_lm_api',
            request_id: requestId,
            priority: priority,
            ...modelInfo,
            ai_response: chunks.join('') || null,
            ai_response_truncated: truncated || undefined,
        });
        return true;
    } catch (_) {
        return false;
    }
}

/**
 * Clipboard fallback — sends the message via paste + submit so it appears
 * in the chat panel with the same session context.
 *
 *   normal → clear pending queue first (avoids "保留/移除" dialog), then
 *     paste + queueMessage.  If AI is working, queueMessage detects
 *     requestInProgress and silently queues the new message.
 *     If AI is stalled, message sends directly (queue empty → no dialog).
 *     Trade-off: clears queued messages, but for status tickets with
 *     similar content this is acceptable.
 *
 *   high → clear pending queue + cancel active request, then paste +
 *     submit.  No pending requests → submit goes through immediately
 *     without any dialog.
 */
async function sendViaClipboard(message, requestId, priority, resPath) {
    try {
        // Clear stale pending queue first — guarantees no dialog.
        try { await vscode.commands.executeCommand('workbench.action.chat.removeAllPendingRequests'); } catch (_) {}
        if (priority === 'high') {
            try { await vscode.commands.executeCommand('workbench.action.chat.cancel'); } catch (_) {}
        }

        // Clipboard + paste — reduced delays for speed.
        await vscode.env.clipboard.writeText(message);
        // chat.open already called in processCommandFile, skip duplicate.
        await vscode.commands.executeCommand('workbench.action.chat.focusInput');
        await new Promise(r => setTimeout(r, PASTE_DELAY_MS));
        try { await vscode.commands.executeCommand('editor.action.clipboardPasteAction'); } catch (_) {}
        await new Promise(r => setTimeout(r, SUBMIT_DELAY_MS));

        if (priority === 'normal') {
            try { await vscode.commands.executeCommand('workbench.action.chat.queueMessage'); } catch (_) {}
        } else {
            try { await vscode.commands.executeCommand('workbench.action.chat.submit'); } catch (_) {}
        }

        writeResult(resPath, { success: true, reason: 'sent_via_clipboard_fallback', request_id: requestId, priority: priority });
    } catch (err) {
        writeResult(resPath, { success: false, reason: 'clipboard_fallback_failed', detail: String(err), request_id: requestId });
    }
}

exports.activate = activate;
exports.deactivate = deactivate;

