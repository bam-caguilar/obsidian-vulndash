import type { ComponentOccurrence } from '../../domain/sbom/ComponentOccurrence';
import type {
  NormalizedComponent,
  NormalizedCweGroup,
  NormalizedSbomFormat,
  NormalizedSeverity,
  NormalizedVulnerability
} from '../../domain/sbom/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';

export type TrackedComponentSource = ComponentOccurrence;

export interface TrackedComponent {
  cweGroups: NormalizedCweGroup[];
  formats: NormalizedSbomFormat[];
  isEnabled: boolean;
  isFollowed: boolean;
  key: string;
  name: string;
  sourceFiles: string[];
  sources: TrackedComponentSource[];
  vulnerabilities: NormalizedVulnerability[];
  vulnerabilityCount: number;
  cpe?: string;
  highestSeverity?: NormalizedSeverity;
  license?: string;
  notePath?: string | null;
  purl?: string;
  supplier?: string;
  version?: string;
}

export interface ComponentCatalog {
  componentCount: number;
  components: TrackedComponent[];
  formats: NormalizedSbomFormat[];
  occurrenceCount: number;
  sourceFiles: string[];
}

export interface ComponentInventoryIssue {
  hasCachedData: boolean;
  message: string;
  sbomId: string;
  sourcePath?: string;
  title: string;
}

export interface ComponentInventorySnapshot {
  catalog: ComponentCatalog;
  configuredSbomCount: number;
  enabledSbomCount: number;
  failedSbomCount: number;
  issues: ComponentInventoryIssue[];
  occurrences: readonly ComponentOccurrence[];
  occurrenceCount: number;
  parsedSbomCount: number;
}

export type ComponentVulnerabilityLinkEvidence =
  | 'component-query-cache'
  | 'cpe'
  | 'explicit'
  | 'name-version'
  | 'osv-query-purl'
  | 'payload-purl'
  | 'purl';

export interface ComponentQueryMatch {
  queriedPurl: string;
  sourceId: string;
  vulnerability: Vulnerability;
  vulnerabilityCacheKey: string;
  vulnerabilityId: string;
}

export type ComponentPurlQueryState =
  | 'error'
  | 'hit'
  | 'miss'
  | 'not-queried'
  | 'queried'
  | 'stale';

export interface ComponentPurlMatchFinding {
  cacheKey?: string;
  evidence: ComponentVulnerabilityLinkEvidence;
  source: string;
  vulnerabilityId: string;
}

export interface ComponentPurlMatchSummary {
  cachedHitCount: number;
  cachedHits: readonly ComponentPurlMatchFinding[];
  componentKey: string;
  componentName: string;
  componentVersion?: string;
  correlatedMatchCount: number;
  correlatedMatches: readonly ComponentPurlMatchFinding[];
  normalizedPurl: string;
  queryState: ComponentPurlQueryState;
}

export interface ComponentVulnerabilityRelationship {
  componentKey: string;
  occurrenceId: string;
  evidence: ComponentVulnerabilityLinkEvidence;
  projectId?: string;
  projectName?: string;
  sbomFileName?: string;
  sbomId?: string;
  sbomLabel?: string;
  sourcePath?: string;
  vulnerabilityId: string;
  vulnerabilityRef: string;
  vulnerabilitySource: string;
}

export interface RelatedComponentSummary {
  evidence: ComponentVulnerabilityLinkEvidence;
  key: string;
  name: string;
  occurrenceId?: string;
  projectId?: string;
  projectName?: string;
  sbomFileName?: string;
  sbomId?: string;
  sbomLabel?: string;
  sourcePath?: string;
  vulnerabilityCount: number;
  cpe?: string;
  highestSeverity?: NormalizedSeverity;
  notePath?: string | null;
  purl?: string;
  version?: string;
}

export interface RelatedVulnerabilitySummary {
  cvssScore: number;
  evidence: ComponentVulnerabilityLinkEvidence;
  id: string;
  referenceCount: number;
  severity: string;
  source: string;
  title: string;
  notePath?: string;
}

export interface ComponentRelationshipGraph {
  componentsByVulnerability: Map<string, RelatedComponentSummary[]>;
  relationships: ComponentVulnerabilityRelationship[];
  vulnerabilitiesByComponent: Map<string, RelatedVulnerabilitySummary[]>;
  vulnerabilitiesByOccurrence: Map<string, RelatedVulnerabilitySummary[]>;
}

export interface ComponentPurlQueryVulnerabilitySummary {
  id: string;
  severity: string;
  source: string;
  title: string;
}

export interface ComponentPurlQueryMatchSummary {
  cachedVulnerabilityCount: number;
  componentKey: string;
  componentName: string;
  correlatedPurlMatchCount: number;
  purl: string;
  queryState: 'error' | 'hit' | 'miss' | 'unqueried';
  vulnerabilities: ComponentPurlQueryVulnerabilitySummary[];
}

export interface ComponentInventoryWorkspaceSnapshot {
  inventory: ComponentInventorySnapshot;
  purlMatches: readonly ComponentPurlMatchSummary[];
  relationships: ComponentRelationshipGraph;
}

export interface CatalogComponentInput {
  component: NormalizedComponent;
  document: {
    format: NormalizedSbomFormat;
    name: string;
    projectId?: string;
    projectName?: string;
    sbomFileName?: string;
    sbomId?: string;
    sbomLabel?: string;
    sourcePath: string;
  };
}
