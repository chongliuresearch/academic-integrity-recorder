import { useEffect, useState } from "react";
import { Activity, Archive, Bot, Check, ChevronRight, CircleAlert, Clock3, EyeOff, FileCheck2, FileText, Fingerprint, FolderOpen, Globe2, KeyRound, Link2, LockKeyhole, Pause, Play, Plus, Radio, Search, Settings, ShieldCheck, Tags, TimerReset, Wrench } from "lucide-react";
import { command, getDashboard } from "./api";
import type { DashboardState, ResearchItem } from "./types";

type Tab = "overview" | "timeline" | "items" | "tools" | "export" | "settings";
const itemNames: Record<string, string> = { keyConcept: "关键概念", researchQuestion: "研究问题", keyArgument: "关键论证", evidenceOrSource: "证据 / 文献", experiment: "实验", dataResult: "数据结果", objection: "反例 / 异议", researchDecision: "研究决策", aiUse: "AI 使用", custom: "自定义" };
const eventNames: Record<string, string> = { fileModified: "文件已保存并快照", webNavigation: "访问已授权研究网页", screenshot: "已生成定时截图", commandExecuted: "已执行研究命令", applicationFocused: "目标工具进入前台", gap: "记录缺口" };

function formatDuration(seconds: number) {
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60);
  return `${h} 小时 ${m} 分`;
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function StatusPill({ state }: { state: string }) {
  const label = state === "available" ? "可用" : state === "degraded" ? "有限" : state === "permissionRequired" ? "待授权" : "不可用";
  return <span className={`pill ${state}`}><span />{label}</span>;
}

function App() {
  const [data, setData] = useState<DashboardState | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [busy, setBusy] = useState<string>();
  const [toast, setToast] = useState<string>();

  const refresh = async () => setData(await getDashboard());
  useEffect(() => { refresh(); const timer = window.setInterval(refresh, 3000); return () => clearInterval(timer); }, []);
  const act = async (name: string, args: Record<string, unknown>, message: string) => {
    setBusy(name); try { await command(name, args); await refresh(); setToast(message); window.setTimeout(() => setToast(undefined), 2600); } finally { setBusy(undefined); }
  };

  if (!data) return <div className="loading"><ShieldCheck /><span>正在校验本地证据库…</span></div>;
  if (!data.initialized || !data.project) return <Onboarding onCreated={refresh} />;
  const project = data.project;
  const nav: { id: Tab; icon: typeof Activity; label: string }[] = [
    { id: "overview", icon: Activity, label: "今日概览" }, { id: "timeline", icon: Clock3, label: "过程时间线" },
    { id: "items", icon: Tags, label: "研究条目" }, { id: "tools", icon: Wrench, label: "工具与范围" },
    { id: "export", icon: Archive, label: "导出证据包" }, { id: "settings", icon: Settings, label: "隐私与设置" }
  ];

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Fingerprint /></div><div><strong>溯研</strong><small>Research Provenance</small></div></div>
      <div className="project-chip"><span>当前项目</span><strong>{project.name}</strong><small>{project.researchRoots[0] ?? "未选择研究目录"}</small></div>
      <nav>{nav.map(({ id, icon: Icon, label }) => <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}><Icon size={18}/><span>{label}</span>{id === "timeline" && <b>{data.eventCount}</b>}</button>)}</nav>
      <div className="sidebar-bottom">
        <div className="integrity-card"><ShieldCheck/><div><strong>本地证据记录</strong><span>{data.eventCount} 个事件 · 导出时执行完整校验与签名</span></div></div>
        <span className="language-note">当前界面：简体中文 · 导出含完整双语 HTML/JSON 与英文 PDF 摘要</span>
      </div>
    </aside>
    <main>
      <header className="topbar"><div><p className="eyebrow">主动自我报告式研究记录</p><h1>{nav.find(n => n.id === tab)?.label}</h1></div><div className="record-controls">
        <button className={`privacy ${data.privacyMode ? "on" : ""}`} onClick={() => act("toggle_privacy", {}, data.privacyMode ? "隐私模式已关闭" : "隐私模式已开启")}><EyeOff size={17}/>隐私模式</button>
        <button className={`recording-button ${data.recording ? "live" : ""}`} onClick={() => act(data.paused ? "resume_recording" : "pause_recording", {}, data.paused ? "已继续记录" : "已暂停并写入缺口")}>{data.paused ? <Play/> : <Pause/>}<span>{data.recording ? "正在记录" : data.armed ? "已暂停" : "未布防"}<small>{data.activeTool ?? "等待目标工具"}</small></span></button>
      </div></header>
      <section className="content">
        {tab === "overview" && <Overview data={data} onNavigate={setTab}/>} 
        {tab === "timeline" && <Timeline data={data}/>} 
        {tab === "items" && <ResearchWorkspace data={data} onCreate={(item) => act("create_research_item", { input: item }, "研究条目已追加到证据链")}/>} 
        {tab === "tools" && <Tools data={data} onToggle={(id, enabled) => act("set_tool_enabled", { toolId: id, enabled }, "工具监控范围已更新")} onDomain={(domain,enabled)=>act("set_domain_allowed",{domain,enabled},"网站记录范围已更新")}/>} 
        {tab === "export" && <ExportPanel data={data}/>} 
        {tab === "settings" && <SettingsWorkspace data={data}/>} 
      </section>
    </main>
    {toast && <div className="toast"><Check size={18}/>{toast}</div>}
    {busy && <div className="busy-line"/>}
  </div>;
}

function Overview({ data, onNavigate }: { data: DashboardState; onNavigate: (tab: Tab) => void }) {
  const degraded = data.capabilities.capabilities.filter(c => c.state !== "available");
  return <>
    <div className="notice"><CircleAlert/><div><strong>证据边界</strong><span>本工具记录主动提交的研究过程，不构成作者身份、原创性或学术诚信认证。</span></div></div>
    <div className="metrics">
      <Metric icon={TimerReset} label="有效累计时间" value={formatDuration(data.activeSeconds)} note="前台 + 90 秒活动窗口" tone="green"/>
      <Metric icon={Radio} label="已记录事件" value={data.eventCount.toLocaleString()} note="前向哈希链连续" tone="blue"/>
      <Metric icon={Tags} label="研究条目" value={String(data.researchItems.length)} note="概念·论证·数据·AI" tone="gold"/>
      <Metric icon={CircleAlert} label="可见缺口" value={String(data.gapCount)} note="暂停、权限或遮盖" tone="rust"/>
    </div>
    <div className="two-col">
      <div className="panel"><PanelHead title="最近过程" action="查看全部" onClick={() => onNavigate("timeline")}/><div className="event-list">{data.recentEvents.slice(0,4).map((event, i) => <div className="event" key={event.id}><div className="event-node"><span/>{i < data.recentEvents.length-1 && <i/>}</div><div><strong>{eventNames[event.kind] ?? event.kind}</strong><span>{event.source} · {new Date(event.occurredAt).toLocaleTimeString("zh-CN", {hour:"2-digit",minute:"2-digit"})}</span><code>sha256:{event.payloadHash.slice(0,12)}…</code></div></div>)}</div></div>
      <div className="panel"><PanelHead title="采集能力" action="管理权限" onClick={() => onNavigate("tools")}/><div className="capability-summary"><div className="platform"><Globe2/><div><strong>{data.capabilities.platform}</strong><span>{data.capabilities.platformVersion} · 实时探测</span></div></div>{data.capabilities.capabilities.map(c => <div className="cap-row" key={c.id}><span>{c.label}</span><StatusPill state={c.state}/></div>)}{degraded.length > 0 && <p className="cap-warning"><CircleAlert/>{degraded.length} 项能力存在限制，限制将随证据包披露。</p>}</div></div>
    </div>
    <div className="panel research-preview"><PanelHead title="关键研究条目" action="管理条目" onClick={() => onNavigate("items")}/><div className="item-grid">{data.researchItems.slice(0,3).map(item => <ItemCard key={item.id} item={item}/>)}</div></div>
  </>;
}

function Metric({icon: Icon,label,value,note,tone}:{icon:typeof Activity;label:string;value:string;note:string;tone:string}) { return <div className={`metric ${tone}`}><div className="metric-icon"><Icon/></div><div><span>{label}</span><strong>{value}</strong><small>{note}</small></div></div>; }
function PanelHead({title,action,onClick}:{title:string;action?:string;onClick?:()=>void}) { return <div className="panel-head"><h2>{title}</h2>{action && <button onClick={onClick}>{action}<ChevronRight/></button>}</div>; }
const statusNames: Record<string,string> = { forming:"形成中",active:"有效",revised:"已修正",rejected:"已放弃",superseded:"已取代",final:"已定稿" };
function ItemCard({item}:{item:ResearchItem}) { return <article className="item-card"><div><span className={`item-type ${item.itemType}`}>{itemNames[item.itemType] ?? item.itemType}</span><small>{statusNames[item.status]??item.status}</small></div><h3>{item.title}</h3><p>{item.description}</p><footer><Link2/> {item.eventIds.length} 事件 · {item.artifactIds.length} 附件 · {item.anchorIds.length} 锚点</footer></article>; }

function Timeline({data}:{data:DashboardState}) {
  const [query,setQuery]=useState("");
  const normalized=query.trim().toLowerCase();
  const visible=data.recentEvents.filter(event=>!normalized||[
    String(event.sequence),event.kind,eventNames[event.kind]??"",event.source,event.sensitivity,event.payloadHash,
    new Date(event.occurredAt).toLocaleString("zh-CN"),
  ].some(value=>value.toLowerCase().includes(normalized)));
  return <div className="panel page-panel"><div className="toolbar"><div className="search"><Search/><input value={query} onChange={event=>setQuery(event.target.value)} placeholder="搜索当前已加载的事件、来源或哈希…"/></div><small className="toolbar-note">显示 {visible.length} / {data.recentEvents.length} 条已加载事件；完整链在导出时校验</small></div><div className="timeline-table"><div className="table-head"><span>#</span><span>时间</span><span>事件</span><span>来源</span><span>敏感度</span><span>负载哈希</span></div>{visible.map(e=><div className="table-row" key={e.id}><span>{e.sequence}</span><span>{new Date(e.occurredAt).toLocaleString("zh-CN")}</span><strong>{eventNames[e.kind]??e.kind}</strong><span>{e.source}</span><span>{e.sensitivity === "publicMetadata"?"公开元数据":"敏感内容"}</span><code>{e.payloadHash.slice(0,12)}…</code></div>)}{visible.length===0&&<p className="empty-state">没有匹配当前条件的已加载事件。</p>}</div></div>;
}

function ResearchItems({items,onCreate}:{items:ResearchItem[];onCreate:(input:Record<string,string>)=>void}) { const [open,setOpen]=useState(false); const [title,setTitle]=useState(""); const [description,setDescription]=useState(""); const [type,setType]=useState("keyConcept"); return <><div className="page-heading"><div><h2>让最终论文内容可回溯</h2><p>为概念、论证、实验和 AI 使用主动绑定过程证据。修正与放弃路径同样保留。</p></div><button className="primary" onClick={()=>setOpen(true)}><Plus/>新建研究条目</button></div><div className="item-grid large">{items.map(item=><ItemCard key={item.id} item={item}/>)}</div>{open&&<div className="modal-backdrop"><form className="modal" onSubmit={e=>{e.preventDefault();onCreate({title,description,itemType:type});setOpen(false);setTitle("");setDescription("")}}><h2>新建研究条目</h2><label>类型<select value={type} onChange={e=>setType(e.target.value)}>{Object.entries(itemNames).map(([v,l])=><option value={v} key={v}>{l}</option>)}</select></label><label>标题<input required value={title} onChange={e=>setTitle(e.target.value)}/></label><label>说明<textarea required rows={4} value={description} onChange={e=>setDescription(e.target.value)}/></label><div className="modal-actions"><button type="button" className="secondary" onClick={()=>setOpen(false)}>取消</button><button className="primary">创建并写入证据链</button></div></form></div>}</>; }

function ResearchWorkspace({data,onCreate}:{data:DashboardState;onCreate:(input:Record<string,string>)=>void}) {
  const items=data.researchItems;
  const [mode,setMode]=useState<"item"|"edit"|"anchor"|"ai"|"linkAi">();
  const [form,setForm]=useState<Record<string,string>>({itemType:"keyConcept",researchItemId:items[0]?.id??"",disposition:"modified"});
  const [aiUserSupplied,setAiUserSupplied]=useState(false);
  const update=(key:string,value:string)=>setForm(current=>({...current,[key]:value}));
  const openEdit=(item:ResearchItem)=>{setForm(current=>({...current,itemId:item.id,title:item.title,description:item.description,status:item.status}));setMode("edit")};
  const submit=async(event:React.FormEvent)=>{event.preventDefault();if(mode==="item")onCreate({title:form.title,description:form.description,itemType:form.itemType});if(mode==="edit")await command("update_research_item",{input:{itemId:form.itemId,title:form.title,description:form.description,status:form.status,eventIds:form.eventId?[form.eventId]:[],artifactIds:form.artifactId?[form.artifactId]:[],anchorIds:form.anchorId?[form.anchorId]:[]}});if(mode==="anchor")await command("create_manuscript_anchor",{input:{researchItemId:form.researchItemId,documentPath:form.documentPath,selectedText:form.selectedText,locator:{userStatement:form.locator}}});if(mode==="ai")await command("create_ai_disclosure",{input:{researchItemId:form.researchItemId||null,anchorIds:form.anchorId?[form.anchorId]:[],service:form.service,modelStatement:form.modelStatement||null,prompt:form.prompt,output:form.output,disposition:form.disposition,humanReview:form.humanReview,sourceIsUserSupplied:aiUserSupplied}});if(mode==="linkAi")await command("link_ai_disclosure",{input:{disclosureId:form.disclosureId,researchItemId:form.researchItemId||null,anchorIds:form.anchorId?[form.anchorId]:[]}});setAiUserSupplied(false);setMode(undefined);};
  const revalidate=async()=>{await command("revalidate_manuscript_anchors",{});window.location.reload()};
  return <><div className="page-heading"><div><h2>让最终论文内容可回溯</h2><p>为概念、论证、实验和 AI 使用主动绑定过程证据。修正与放弃路径同样保留。</p></div><div className="heading-actions"><button className="secondary" disabled={!data.anchors.length} onClick={revalidate}>重新校验锚点</button><button className="secondary" disabled={!data.aiDisclosures.length} onClick={()=>setMode("linkAi")}>追加 AI 关联</button><button className="secondary" disabled={!items.length} onClick={()=>setMode("anchor")}><Link2/>关联终稿</button><button className="secondary" onClick={()=>setMode("ai")}><Bot/>披露 AI 使用</button><button className="primary" onClick={()=>setMode("item")}><Plus/>新建研究条目</button></div></div><div className="item-grid large">{items.map(item=><div key={item.id}><ItemCard item={item}/><button className="secondary" onClick={()=>openEdit(item)}>追加修订 / 状态</button></div>)}</div>{data.anchors.length>0&&<div className="panel"><PanelHead title="终稿锚点"/>{data.anchors.map(anchor=><div className="artifact-row" key={anchor.id}><FileText/><div><strong>{anchor.format.toUpperCase()} · {anchor.status}</strong><span>{anchor.documentPath}</span><code>{anchor.validationDetail??"尚未重新校验"}</code></div></div>)}</div>}{mode&&<div className="modal-backdrop"><form className="modal" onSubmit={submit}><h2>{mode==="item"?"新建研究条目":mode==="edit"?"追加研究条目修订":mode==="anchor"?"关联 PDF / DOCX / TeX / Markdown 终稿":mode==="linkAi"?"追加 AI 披露关联":"披露生成式 AI 使用"}</h2>{mode==="item"&&<><label>类型<select value={form.itemType} onChange={e=>update("itemType",e.target.value)}>{Object.entries(itemNames).map(([v,l])=><option value={v} key={v}>{l}</option>)}</select></label><label>标题<input required onChange={e=>update("title",e.target.value)}/></label><label>说明<textarea required rows={4} onChange={e=>update("description",e.target.value)}/></label></>}{mode==="edit"&&<><label>标题<input required value={form.title} onChange={e=>update("title",e.target.value)}/></label><label>说明<textarea required rows={4} value={form.description} onChange={e=>update("description",e.target.value)}/></label><label>状态<select value={form.status} onChange={e=>update("status",e.target.value)}>{Object.entries(statusNames).map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label></>}{mode==="anchor"&&<><ItemSelect items={items} value={form.researchItemId} onChange={value=>update("researchItemId",value)}/><label>终稿绝对路径<input required onChange={e=>update("documentPath",e.target.value)} placeholder="paper.pdf / manuscript.docx / main.tex / paper.md"/></label><label>论文中选定文字<textarea required rows={4} onChange={e=>update("selectedText",e.target.value)}/></label><label>位置说明<input required onChange={e=>update("locator",e.target.value)} placeholder="例：第 8 页第 2 段"/></label></>}{mode==="linkAi"&&<><label>AI 披露<select required value={form.disclosureId??""} onChange={e=>update("disclosureId",e.target.value)}><option value="">请选择</option>{data.aiDisclosures.map(disclosure=><option key={disclosure.id} value={disclosure.id}>{disclosure.service} · {disclosure.disposition}</option>)}</select></label><ItemSelect items={items} value={form.researchItemId} onChange={value=>update("researchItemId",value)}/><AnchorSelect data={data} itemId={form.researchItemId} value={form.anchorId??""} onChange={value=>update("anchorId",value)} optional/></>}{mode==="ai"&&<><ItemSelect items={items} value={form.researchItemId} onChange={value=>update("researchItemId",value)} optional/><AnchorSelect data={data} itemId={form.researchItemId} value={form.anchorId??""} onChange={value=>update("anchorId",value)} optional/><label>AI 服务<input required onChange={e=>update("service",e.target.value)} placeholder="ChatGPT / Claude / Gemini / local model"/></label><label>模型声明<input onChange={e=>update("modelStatement",e.target.value)} placeholder="仅写入你能确认的模型名称"/></label><label>处置<select value={form.disposition} onChange={e=>update("disposition",e.target.value)}><option value="adopted">采纳</option><option value="modified">修改后采纳</option><option value="rejected">拒绝</option><option value="referenceOnly">仅参考</option></select></label><label>提示词<textarea required rows={3} onChange={e=>update("prompt",e.target.value)}/></label><label>AI 输出<textarea required rows={3} onChange={e=>update("output",e.target.value)}/></label><label>人工复核和修改说明<textarea required rows={3} onChange={e=>update("humanReview",e.target.value)}/></label><label className="checkbox-label"><input type="checkbox" checked={aiUserSupplied} onChange={e=>setAiUserSupplied(e.target.checked)}/><span>该对话是通过 JSON、HTML、Markdown、截图或手工粘贴导入的用户提供材料，而非本工具直接识别采集。</span></label></>}<div className="modal-actions"><button type="button" className="secondary" onClick={()=>{setAiUserSupplied(false);setMode(undefined)}}>取消</button><button className="primary">写入追加记录</button></div></form></div>}</>;
}

function ItemSelect({items,value,onChange,optional=false}:{items:ResearchItem[];value:string;onChange:(value:string)=>void;optional?:boolean}){return <label>关联研究条目<select required={!optional} value={value} onChange={e=>onChange(e.target.value)}>{optional&&<option value="">不关联具体条目</option>}{items.map(item=><option value={item.id} key={item.id}>{item.title}</option>)}</select></label>}
function AnchorSelect({data,itemId,value,onChange,optional=false}:{data:DashboardState;itemId:string;value:string;onChange:(value:string)=>void;optional?:boolean}){const anchors=data.anchors.filter(anchor=>!itemId||anchor.researchItemId===itemId);return <label>关联论文锚点<select required={!optional} value={value} onChange={e=>onChange(e.target.value)}>{optional&&<option value="">不关联锚点</option>}{anchors.map(anchor=><option value={anchor.id} key={anchor.id}>{anchor.format.toUpperCase()} · {anchor.documentPath}</option>)}</select></label>}

interface PairingInfo { endpoint:string;projectId:string;sources:{browser:{token:string};vscode:{token:string};shell:{token:string}} }
function Tools({data,onToggle,onDomain}:{data:DashboardState;onToggle:(id:string,enabled:boolean)=>void;onDomain:(domain:string,enabled:boolean)=>void}) {
  const [domain,setDomain]=useState("");
  const [pairing,setPairing]=useState<PairingInfo>();
  return <><div className="page-heading"><div><h2>用户选择后才监控</h2><p>只有已开启的工具和获选域名才能向当前项目写入事件。</p></div></div><div className="two-col tools-layout"><div className="panel"><PanelHead title="研究软件"/><div className="tool-list">{data.project!.selectedTools.map(t=><div className="tool" key={t.id}><div className="tool-icon"><Wrench/></div><div><strong>{t.label}</strong><span>{t.adapter} 适配器 · {t.applicationId}</span></div><button aria-label={`${t.enabled?"关闭":"开启"} ${t.label}`} className={`switch ${t.enabled?"on":""}`} onClick={()=>onToggle(t.id,!t.enabled)}><i/></button></div>)}</div></div><div className="panel"><PanelHead title="权限与平台实况"/><div className="permission-list">{data.capabilities.capabilities.map(c=><div key={c.id}><div><strong>{c.label}</strong><StatusPill state={c.state}/></div><p>{c.limitation??`${c.permission??"系统"}权限已经满足。`}</p></div>)}</div></div></div><div className="two-col tools-layout"><div className="panel scope-panel"><PanelHead title="获选网站"/><form onSubmit={e=>{e.preventDefault();if(domain.trim()){onDomain(domain,true);setDomain("")}}}><input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="例：scholar.google.com"/><button className="primary">添加</button></form><div className="domain-list">{data.project!.selectedDomains.length===0?<p>尚未授权任何网站；浏览器事件将被拒绝。</p>:data.project!.selectedDomains.map(value=><span key={value}><Globe2/>{value}<button aria-label={`移除 ${value}`} onClick={()=>onDomain(value,false)}>×</button></span>)}</div></div><div className="panel scope-panel"><PanelHead title="扩展本机配对"/><p>浏览器、VS Code 与 Shell 使用不同令牌；一个来源的令牌不能冒充另一个来源。来源安装 ID 由各扩展首次启用时在本地生成。</p>{pairing?<div className="pairing-details"><label>当前项目 ID<code className="token">{pairing.projectId}</code></label>{([['browser','浏览器'],['vscode','VS Code'],['shell','Shell']] as const).map(([id,label])=><label key={id}>{label} 专用令牌<code className="token">{pairing.sources[id].token}</code></label>)}<small>{pairing.endpoint}</small></div>:<button className="secondary pairing-button" onClick={async()=>setPairing(await command<PairingInfo>("get_extension_pairing"))}><Link2/>显示当前项目的专用配对信息</button>}</div></div></>;
}

function ExportPanel({data}:{data:DashboardState}) {
  const [destination,setDestination]=useState("research-process.evidence.zip");
  const [password,setPassword]=useState("");
  const [result,setResult]=useState<{destination:string;reviewPassword:string;packageId:string;deviceFingerprint:string}>();
  const preview=data.exportPreview;
  const run=async()=>{if(!preview)return;setResult(await command("export_evidence",{destination,password:password||null}))};
  return <div className="export-layout"><div className="panel export-main"><div className="export-icon"><Archive/></div><h2>生成可离线校验的双层证据包</h2><p>公开层可验证时间线、哈希、签名和所有缺口；敏感层包含原文、截图、文件快照、命令和 AI 对话，使用独立口令加密。</p><div className="export-summary"><div><FileText/><span>公开层<strong>{data.eventCount} 条事件元数据</strong></span></div><div><LockKeyhole/><span>敏感层<strong>{preview?`${preview.totalCount} 项 · ${formatBytes(preview.totalBytes)}`:"尚未完成清点"}</strong></span></div><div><CircleAlert/><span>必定披露<strong>{data.gapCount} 个记录缺口</strong></span></div></div>{preview?<div className="material-inventory"><h3>敏感层完整清单</h3>{preview.categories.map(category=><div className="inventory-row" key={category.id}><span>{category.label}</span><strong>{category.count} 项</strong><code>{formatBytes(category.bytes)}</code></div>)}<h3>排除项</h3>{preview.exclusions.map(exclusion=><div className="inventory-row excluded" key={exclusion.id}><span>{exclusion.label}<small>{exclusion.reason}</small></span><strong>{exclusion.count} 项</strong></div>)}</div>:<p className="preview-error"><CircleAlert/>完整证据库清点不可用。为避免未经知情确认的敏感导出，本次不能生成证据包。</p>}{result?<div className="export-result"><ShieldCheck/><div><strong>证据包已生成</strong><span>{result.destination}</span><label>审阅口令（只显示在这里）<code>{result.reviewPassword}</code></label><small>请通过与 ZIP 不同的渠道传递。设备指纹 {result.deviceFingerprint.slice(0,16)}…</small></div></div>:<><label>导出路径<input value={destination} onChange={e=>setDestination(e.target.value)}/></label><label>审阅口令 <small>留空则自动生成</small><input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="通过另一渠道交给获授权审查者"/></label><button className="primary wide" disabled={!preview} onClick={run}><ShieldCheck/>确认上述完整清单并生成</button></>}</div><aside className="panel export-aside"><h3>导出前必须理解</h3><ul><li><Check/>安全字段的原文应不进入清单；排除数量和原因仍会披露。</li><li><Check/>已删除内容不可恢复，但缺口仍会显示。</li><li><Check/>证据包同时生成不含研究内容的时间锚定摘要；是否交由 OpenTimestamps / Bitcoin 见证完全可选，默认不联网。</li><li><Check/>审阅口令不写入 ZIP，请分开传递。</li><li><CircleAlert/>时间锚定与本地校验通过都不等于学术诚信获得认证。</li></ul></aside></div>;
}

function SettingsPanel({data}:{data:DashboardState}) { return <div className="settings-grid"><div className="panel"><PanelHead title="隐私硬边界"/><div className="setting"><KeyRound/><div><strong>密码与安全输入</strong><span>永不记录；字段安全性不明时仅记事件类别。</span></div><b>强制</b></div><div className="setting"><EyeOff/><div><strong>隐私模式</strong><span>立即停止内容采集并写入可见缺口。</span></div><b>可用</b></div><div className="setting"><Pause/><div><strong>全局暂停 / 恢复</strong><span>{data.quickControls.globalPauseShortcut} · 托盘菜单始终可用</span></div><b>{data.quickControls.globalPauseAvailable?"已注册":"快捷键冲突"}</b></div></div><div className="panel"><PanelHead title="计时和快照"/><div className="setting"><Clock3/><div><strong>{data.project!.recordingPolicy.activeWindowSeconds} 秒活动窗口</strong><span>前台工具最近发生合格活动时才累计。</span></div></div><div className="setting"><FileCheck2/><div><strong>{data.project!.recordingPolicy.screenshotIntervalSeconds} 秒截图间隔</strong><span>只在有效活动期间且已授权时执行。</span></div></div></div></div>; }

function PolicyControls({data}:{data:DashboardState}) {
  const [seconds,setSeconds]=useState(data.project!.recordingPolicy.screenshotIntervalSeconds);
  return <div className="panel sync-panel"><PanelHead title="按项目设置截图频率"/><p>允许范围为 10–3600 秒。修改前后的值都会进入追加式证据链，并随导出报告披露。</p><div><input type="number" min={10} max={3600} value={seconds} onChange={event=>setSeconds(Number(event.target.value))}/><button className="primary" disabled={seconds<10||seconds>3600} onClick={async()=>{await command("set_screenshot_interval",{seconds});window.location.reload()}}><FileCheck2/>保存截图间隔</button></div></div>
}

function SettingsWorkspace({data}:{data:DashboardState}) {
  const [directory,setDirectory]=useState("");
  const [excludedPath,setExcludedPath]=useState("");
  const [status,setStatus]=useState("");
  const refresh=()=>window.location.reload();
  return <>
    <SettingsPanel data={data}/>
    <PolicyControls data={data}/>
    <div className="panel sync-panel">
      <PanelHead title="研究目录排除表"/>
      <p>排除路径必须真实存在并位于当前研究目录内。被排除路径不会产生文件快照；范围变化本身会写入追加式记录。</p>
      <div><input value={excludedPath} onChange={e=>setExcludedPath(e.target.value)} placeholder="输入需要排除的文件或文件夹绝对路径"/><button className="primary" disabled={!excludedPath.trim()} onClick={async()=>{await command("set_excluded_path",{path:excludedPath,enabled:true});refresh()}}><EyeOff/>加入排除表</button></div>
      <div className="domain-list">{data.project!.recordingPolicy.excludedPaths.length===0?<p>当前没有研究目录排除项。</p>:data.project!.recordingPolicy.excludedPaths.map(path=><span key={path}><FolderOpen/>{path}<button aria-label={`移除排除项 ${path}`} onClick={async()=>{await command("set_excluded_path",{path,enabled:false});refresh()}}>×</button></span>)}</div>
    </div>
    <div className="panel sync-panel"><PanelHead title="自选加密同步目录"/><p>复制加密不可变事件分片、内容对象和签名检查点。SQLite 索引与项目/设备密钥不同步，所以此备份单独不是可跨设备迁移包；恢复仍需原系统凭据库。v1 不支持多设备并发写入。</p><div><input value={directory} onChange={e=>setDirectory(e.target.value)} placeholder="输入同步文件夹绝对路径"/><button className="primary" onClick={async()=>{const count=await command<number>("set_sync_directory",{directory:directory||null});setStatus(`已复制 ${count} 个加密不可变文件`)}}><FolderOpen/>设置并同步</button></div>{status&&<small>{status}</small>}</div>
    <div className="panel redaction-panel"><PanelHead title="敏感内容删除与缺口"/><p>删除会永久移除加密内容，但保留哈希、时间、数量和理由。相同内容的所有引用将一并标记。</p>{data.artifacts.filter(a=>a.contentIncluded).slice(-8).map(artifact=><div className="artifact-row" key={artifact.id}><FileText/><div><strong>{artifact.kind}</strong><span>{artifact.originalPath??artifact.mediaType}</span><code>{artifact.sha256.slice(0,16)}… · {Math.ceil(artifact.size/1024)} KB</code></div><button className="danger" onClick={async()=>{const reason=window.prompt("请输入将随证据包公开的删除理由");if(reason&&window.confirm("内容删除后无法恢复，但缺口和哈希会保留。确认吗？"))await command("redact_artifact",{artifactId:artifact.id,reason})}}>删除内容并保留缺口</button></div>)}</div>
  </>
}

function Onboarding({onCreated}:{onCreated:()=>void}) { const [name,setName]=useState(""); const [author,setAuthor]=useState(""); const [root,setRoot]=useState(""); return <div className="onboarding"><div className="onboarding-copy"><div className="brand-mark large"><Fingerprint/></div><p className="eyebrow">Research provenance, under your control</p><h1>让论文的形成过程<br/>成为可审查的证据</h1><p>本地加密、主动选择、缺口透明。它提供过程佐证，而不是诚信认证。</p><div className="principles"><span><ShieldCheck/>本地优先</span><span><Fingerprint/>防篡改签名</span><span><EyeOff/>随时暂停</span></div></div><form className="onboarding-form" onSubmit={async e=>{e.preventDefault();await command("create_project",{name,authorStatement:author,researchRoot:root||null});onCreated()}}><h2>创建首个研究项目</h2><p>密钥将存入系统安全存储，原始证据不会上传到我们的服务器。</p><label>项目名称<input required value={name} onChange={e=>setName(e.target.value)} placeholder="例：相关关系与因果解释"/></label><label>作者自我声明<textarea required rows={4} value={author} onChange={e=>setAuthor(e.target.value)} placeholder="说明你自愿记录和提交该研究过程…"/></label><label>研究目录<input value={root} onChange={e=>setRoot(e.target.value)} placeholder="可稍后选择"/></label><div className="consent"><Check/><span>我了解：该工具不能证明未记录活动从未发生。</span></div><button className="primary wide">创建加密项目 <ChevronRight/></button></form></div>; }

export default App;
