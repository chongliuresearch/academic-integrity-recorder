export type CapabilityState = "available" | "permissionRequired" | "degraded" | "unavailable";

export interface Capability {
  id: string;
  label: string;
  state: CapabilityState;
  permission?: string;
  limitation?: string;
}

export interface ToolTarget {
  id: string;
  label: string;
  applicationId: string;
  adapter: string;
  enabled: boolean;
}

export interface ResearchItem {
  id: string;
  itemType: string;
  title: string;
  description: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  eventIds: string[];
  artifactIds: string[];
  anchorIds: string[];
  parentItemId?: string;
}

export type AnchorStatus = "valid" | "relocatable" | "stale";
export interface ManuscriptAnchor {
  id: string;
  researchItemId: string;
  format: "pdf" | "docx" | "tex" | "markdown";
  documentPath: string;
  documentSha256: string;
  status: AnchorStatus;
  createdAt: string;
  lastValidatedAt?: string;
  lastValidatedDocumentSha256?: string;
  validationCapability?: "exactDocumentHash" | "textFingerprint" | "manualReanchorRequired" | "documentUnavailable";
  validationDetail?: string;
}

export interface AiUseDisclosure {
  id: string;
  researchItemId?: string;
  service: string;
  modelStatement?: string;
  promptArtifactId?: string;
  outputArtifactId?: string;
  disposition: "adopted" | "modified" | "rejected" | "referenceOnly";
  humanReview: string;
  sourceIsUserSupplied: boolean;
  anchorIds: string[];
  createdAt: string;
}

export interface TimelineEvent {
  id: string;
  sequence: number;
  occurredAt: string;
  source: string;
  kind: string;
  sensitivity: string;
  payloadHash: string;
}
export interface Artifact { id:string;kind:string;originalPath?:string;mediaType:string;size:number;sha256:string;capturedAt:string;contentIncluded:boolean }

export interface ExportMaterialCategory {
  id: string;
  label: string;
  count: number;
  bytes: number;
}

export interface ExportExclusion {
  id: string;
  label: string;
  count: number;
  reason: string;
}

export interface ExportPreview {
  totalCount: number;
  totalBytes: number;
  categories: ExportMaterialCategory[];
  exclusions: ExportExclusion[];
}

export interface DashboardState {
  initialized: boolean;
  project?: {
    id: string;
    name: string;
    authorStatement: string;
    createdAt: string;
    researchRoots: string[];
    selectedTools: ToolTarget[];
    selectedDomains: string[];
    recordingPolicy: {
      activeWindowSeconds: number;
      screenshotIntervalSeconds: number;
      snapshotLimitBytes: number;
      excludedPaths: string[];
    };
  };
  armed: boolean;
  paused: boolean;
  privacyMode: boolean;
  recording: boolean;
  activeTool?: string;
  activeSeconds: number;
  eventCount: number;
  gapCount: number;
  recentEvents: TimelineEvent[];
  researchItems: ResearchItem[];
  artifacts: Artifact[];
  anchors: ManuscriptAnchor[];
  aiDisclosures: AiUseDisclosure[];
  /** Exact inventory over the complete evidence store, computed by the Rust runtime. */
  exportPreview?: ExportPreview;
  quickControls: {
    globalPauseShortcut: string;
    globalPauseAvailable: boolean;
    trayControlsAvailable: boolean;
  };
  capabilities: {
    platform: string;
    platformVersion: string;
    capabilities: Capability[];
    warnings: string[];
  };
}
