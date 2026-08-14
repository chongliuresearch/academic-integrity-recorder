import { invoke } from "@tauri-apps/api/core";
import type { DashboardState } from "./types";

const demoState: DashboardState = {
  initialized: true,
  project: {
    id: "preview",
    name: "意识与因果关系研究",
    authorStatement: "本人自愿提交本研究过程记录，并了解其证据边界。",
    createdAt: new Date().toISOString(),
    researchRoots: ["/Users/research/Documents/consciousness"],
    selectedDomains: ["scholar.google.com", "chatgpt.com"],
    selectedTools: [
      { id: "1", label: "Microsoft Word", applicationId: "Microsoft Word", adapter: "generic", enabled: true },
      { id: "2", label: "Zotero", applicationId: "Zotero", adapter: "generic", enabled: true },
      { id: "3", label: "VS Code", applicationId: "Code", adapter: "vscode", enabled: true },
      { id: "4", label: "Terminal", applicationId: "Terminal", adapter: "shell", enabled: true },
      { id: "5", label: "Jupyter", applicationId: "jupyter", adapter: "browser", enabled: false },
    ],
    recordingPolicy: { activeWindowSeconds: 90, screenshotIntervalSeconds: 30, snapshotLimitBytes: 52428800, excludedPaths: [] }
  },
  armed: true,
  paused: false,
  privacyMode: false,
  recording: true,
  activeTool: "Microsoft Word",
  activeSeconds: 7812,
  eventCount: 1248,
  gapCount: 2,
  recentEvents: [
    { id: "e5", sequence: 1248, occurredAt: new Date().toISOString(), source: "desktop:native", kind: "fileModified", sensitivity: "sensitiveContent", payloadHash: "9c8f2f01a50d" },
    { id: "e4", sequence: 1247, occurredAt: new Date(Date.now() - 55000).toISOString(), source: "browser:extension", kind: "webNavigation", sensitivity: "publicMetadata", payloadHash: "a74fd2b160d2" },
    { id: "e3", sequence: 1246, occurredAt: new Date(Date.now() - 125000).toISOString(), source: "desktop:native", kind: "screenshot", sensitivity: "sensitiveContent", payloadHash: "38bc2f8bd09a" },
    { id: "e2", sequence: 1245, occurredAt: new Date(Date.now() - 240000).toISOString(), source: "vscode:extension", kind: "commandExecuted", sensitivity: "sensitiveContent", payloadHash: "d11ff2a19b75" },
  ],
  researchItems: [
    { id: "r1", itemType: "keyConcept", title: "现象因果的工作定义", description: "将概念与可检验的变量对应。", status: "revised", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), eventIds: ["e1", "e2"], artifactIds: [], anchorIds: [] },
    { id: "r2", itemType: "keyArgument", title: "排除共同原因的论证", description: "关键推理链与反例回应。", status: "active", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), eventIds: ["e3"], artifactIds: [], anchorIds: [] },
    { id: "r3", itemType: "aiUse", title: "AI 辅助检查术语一致性", description: "未将 AI 输出作为证据；人工复核后仅修正两处表述。", status: "final", createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), eventIds: [], artifactIds: [], anchorIds: [] }
  ],
  artifacts: [
    {id:"a1",kind:"screenshot",mediaType:"image/png",size:182034,sha256:"38bc2f8bd09a99d19b7b7c18c28a9201",capturedAt:new Date().toISOString(),contentIncluded:true},
    {id:"a2",kind:"file-snapshot",originalPath:"/Users/research/Documents/consciousness/draft.docx",mediaType:"application/vnd.openxmlformats-officedocument.wordprocessingml.document",size:84012,sha256:"9c8f2f01a50d85d4510aae673bec77b1",capturedAt:new Date().toISOString(),contentIncluded:true}
  ],
  anchors: [],
  aiDisclosures: [],
  exportPreview: {
    totalCount: 1211,
    totalBytes: 266046,
    categories: [
      { id:"event-originals", label:"事件原文与命令", count:1206, bytes:0 },
      { id:"screenshots", label:"截图", count:1, bytes:182034 },
      { id:"file-snapshots", label:"文件快照", count:1, bytes:84012 },
      { id:"ai-dialogues", label:"AI 对话", count:2, bytes:0 },
      { id:"research-notes", label:"研究者说明", count:1, bytes:0 },
    ],
    exclusions: [
      { id:"never-captured", label:"密码、系统认证与隐私浏览", count:0, reason:"永不采集" },
      { id:"redacted", label:"已主动删除内容", count:1, reason:"仅保留可验证缺口" },
    ],
  },
  quickControls: {
    globalPauseShortcut: "CommandOrControl+Shift+Alt+R",
    globalPauseAvailable: true,
    trayControlsAvailable: true,
  },
  capabilities: {
    platform: "macOS",
    platformVersion: "26.5.2",
    capabilities: [
      { id: "foreground-window", label: "前台应用与窗口", state: "available", permission: "辅助功能" },
      { id: "screen-capture", label: "屏幕截图", state: "available", permission: "屏幕录制" },
      { id: "accessible-text", label: "可访问文本变化", state: "degraded", limitation: "仅支持安全字段与可访问接口。" }
    ],
    warnings: ["安全输入和系统认证界面永不采集。"]
  }
};

function isTauri() { return "__TAURI_INTERNALS__" in window; }

export async function getDashboard(): Promise<DashboardState> {
  return isTauri() ? invoke("get_dashboard") : demoState;
}

export async function command<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!isTauri()) {
    await new Promise(resolve => setTimeout(resolve, 240));
    return undefined as T;
  }
  return invoke(name, args);
}
