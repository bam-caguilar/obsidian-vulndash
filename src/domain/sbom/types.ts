import type { NormalizedSeverity as ResolvedSeverity } from '../vulnerabilities/NormalizedSeverity';
import type {
  KnownPatch,
  UpgradePathResolution,
  VulnerabilityRange
} from '../vulnerabilities/remediation';

export type NormalizedSbomFormat = 'cyclonedx' | 'spdx';

export type NormalizedSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational';

export interface NormalizedComponentVulnerabilitySummary {
  cweIds: number[];
  highestSeverity?: NormalizedSeverity;
  severities: NormalizedSeverity[];
  vulnerabilityCount: number;
  vulnerabilityIds: string[];
}

export interface NormalizedCweGroup {
  count: number;
  cwe: number;
  vulnerabilityIds: string[];
}

export interface NormalizedVulnerability {
  cwes: number[];
  id: string;
  bomRef?: string;
  description?: string;
  ecosystem?: string;
  knownPatches?: KnownPatch[];
  method?: string;
  normalizedSeverity?: ResolvedSeverity;
  packageIdentity?: string;
  packageName?: string;
  published?: string;
  ranges?: VulnerabilityRange[];
  score?: number;
  severity?: NormalizedSeverity;
  sourceName?: string;
  sourcePatchedVersionsText?: string;
  sourceRangeText?: string;
  sourceUrl?: string;
  upgradePathResolution?: UpgradePathResolution;
  updated?: string;
  vector?: string;
}

export interface NormalizedComponent {
  bomRef?: string;
  cweGroups: NormalizedCweGroup[];
  id: string;
  name: string;
  notePath?: string | null;
  vulnerabilitySummary: NormalizedComponentVulnerabilitySummary;
  vulnerabilities: NormalizedVulnerability[];
  vulnerabilityCount: number;
  cpe?: string;
  highestSeverity?: NormalizedSeverity;
  license?: string;
  purl?: string;
  supplier?: string;
  version?: string;
}

export interface NormalizedSbomDocument {
  components: NormalizedComponent[];
  format: NormalizedSbomFormat;
  name: string;
  sourcePath: string;
}
