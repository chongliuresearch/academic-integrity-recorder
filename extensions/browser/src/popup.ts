import { defaults, settings } from "./shared.js";

const form = document.querySelector("form")!;
const token = document.querySelector<HTMLInputElement>("#token")!;
const projectId = document.querySelector<HTMLInputElement>("#projectId")!;
const sourceId = document.querySelector<HTMLInputElement>("#sourceId")!;
const enabled = document.querySelector<HTMLInputElement>("#enabled")!;
const status = document.querySelector("#status")!;

void settings().then(config => {
  const persistedSourceId = config.sourceId || crypto.randomUUID();
  token.value = config.token;
  projectId.value = config.projectId;
  sourceId.value = persistedSourceId;
  enabled.checked = config.enabled;
  if (!config.sourceId) void chrome.storage.local.set({ sourceId: persistedSourceId });
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  const values = {
    ...defaults,
    token: token.value.trim(),
    projectId: projectId.value.trim(),
    sourceId: sourceId.value,
    enabled: enabled.checked,
  };
  if (values.enabled && (!values.token || !values.projectId || !values.sourceId)) {
    status.textContent = "启用前必须从桌面端填写项目、来源身份和专用令牌。";
    return;
  }
  await chrome.storage.local.set(values);
  status.textContent = "配对信息已保存；只有前台、非隐私且获选域名会被发送。";
});
