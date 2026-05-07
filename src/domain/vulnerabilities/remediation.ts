export type VulnerabilityRangeType = 'SEMVER' | 'ECOSYSTEM' | 'GIT';

export interface VulnerabilityRangeEvent {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
  limit?: string;
}

export interface VulnerabilityRange {
  type: VulnerabilityRangeType;
  repo?: string;
  events: VulnerabilityRangeEvent[];
  sourceRangeText?: string;
}

export interface KnownPatch {
  version: string;
  source?: 'OSV' | 'GHSA' | 'NVD' | 'MANUAL' | string;
  sourceText?: string;
}

export type UpgradePathResolutionStatus =
  | 'resolved'
  | 'already-safe'
  | 'unresolved'
  | 'unsupported-version-scheme'
  | 'insufficient-data';

export interface RejectedUpgradeCandidate {
  version: string;
  reason: string;
  blockingVulnerabilityId?: string;
}

export interface UpgradePathResolution {
  recommendedUpgradeVersion?: string;
  status: UpgradePathResolutionStatus;
  rejectedCandidates: RejectedUpgradeCandidate[];
  diagnostics?: string[];
}
