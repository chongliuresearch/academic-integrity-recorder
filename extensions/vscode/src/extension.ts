import * as vscode from "vscode";
import { createHash, randomUUID } from "node:crypto";
import { isAbsolute, relative, sep } from "node:path";
import { evidenceEnvelope } from "./protocol.js";

interface Config { enabled: boolean; endpoint: string; token: string; projectId: string }

function config(): Config {
  const values = vscode.workspace.getConfiguration("airRecorder");
  return {
    enabled: values.get("enabled", false),
    endpoint: values.get("endpoint", "http://127.0.0.1:43119/v1/events"),
    token: values.get("token", ""),
    projectId: values.get("projectId", ""),
  };
}

function isForegroundWorkspaceDocument(document?: vscode.TextDocument): boolean {
  if (!vscode.window.state.focused || !document) return false;
  const active = vscode.window.activeTextEditor?.document;
  if (!active || active.uri.toString() !== document.uri.toString()) return false;
  return (vscode.workspace.workspaceFolders ?? []).some(folder => {
    const candidate = relative(folder.uri.fsPath, document.uri.fsPath);
    return candidate !== "" && candidate !== ".." && !candidate.startsWith(`..${sep}`) && !isAbsolute(candidate);
  });
}

function workspaceFolderFor(document: vscode.TextDocument): vscode.WorkspaceFolder | undefined {
  if (!isForegroundWorkspaceDocument(document)) return undefined;
  return (vscode.workspace.workspaceFolders ?? []).find(folder => {
    const child = relative(folder.uri.fsPath, document.uri.fsPath);
    return child !== "" && child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child);
  });
}

function pathFor(document: vscode.TextDocument): string | undefined {
  const folder = workspaceFolderFor(document);
  return folder ? `${folder.name}/${vscode.workspace.asRelativePath(document.uri, false)}` : undefined;
}

export function activate(context: vscode.ExtensionContext): void {
  const sourceIdKey = "airRecorder.sourceId";
  let sourceId = context.globalState.get<string>(sourceIdKey);
  if (!sourceId) {
    sourceId = randomUUID();
    void context.globalState.update(sourceIdKey, sourceId);
  }

  const send = async (kind: string, payload: unknown, document?: vscode.TextDocument): Promise<void> => {
    const current = config();
    if (!current.enabled || !current.token || !current.projectId || !vscode.window.state.focused) return;
    const scopedDocument = document ?? vscode.window.activeTextEditor?.document;
    if (!scopedDocument) return;
    const workspaceFolder = workspaceFolderFor(scopedDocument);
    if (!workspaceFolder) return;
    const evidencePayload = payload !== null && typeof payload === "object" && !Array.isArray(payload)
      ? { ...(payload as Record<string, unknown>), workspaceRoot: workspaceFolder.uri.fsPath, foreground: true }
      : { value: payload, workspaceRoot: workspaceFolder.uri.fsPath, foreground: true };
    const body = evidenceEnvelope({
      projectId: current.projectId,
      source: "vscode-extension",
      sourceId: sourceId!,
      token: current.token,
      kind,
      payload: evidencePayload,
    });
    const response = await fetch(current.endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${current.token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) console.warn("AIR recorder rejected VS Code event", await response.text());
  };

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(document => {
      const path = pathFor(document);
      if (!path) return;
      const text = document.getText();
      void send("fileModified", {
        path,
        languageId: document.languageId,
        version: document.version,
        length: text.length,
        contentSha256: createHash("sha256").update(text).digest("hex"),
        contentStoredByExtension: false,
      }, document);
    }),
    vscode.window.onDidChangeActiveTextEditor(editor => {
      const path = editor && pathFor(editor.document);
      if (editor && path) void send("annotation", { action: "active-editor-changed", path, languageId: editor.document.languageId }, editor.document);
    }),
    vscode.tasks.onDidStartTask(event => {
      if (!vscode.window.state.focused || !(vscode.workspace.workspaceFolders?.length)) return;
      void send("commandExecuted", { phase: "started", taskName: event.execution.task.name, source: event.execution.task.source, commandTextStored: false });
    }),
    vscode.tasks.onDidEndTaskProcess(event => {
      if (!vscode.window.state.focused || !(vscode.workspace.workspaceFolders?.length)) return;
      void send("commandExecuted", { phase: "ended", taskName: event.execution.task.name, exitCode: event.exitCode, commandTextStored: false });
    }),
  );
}

export function deactivate(): void {}
