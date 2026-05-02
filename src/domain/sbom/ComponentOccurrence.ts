import type { NormalizedSbomFormat } from './types';

export interface ComponentOccurrence {
  readonly id: string;
  readonly componentKey: string;
  readonly componentId: string;
  readonly documentName: string;
  readonly format: NormalizedSbomFormat;
  readonly name: string;
  readonly projectId: string;
  readonly projectName: string;
  readonly sbomFileName: string;
  readonly sbomId: string;
  readonly sbomLabel: string;
  readonly sourcePath: string;
  readonly vulnerabilityCount: number;
  readonly vulnerabilityIds: readonly string[];
  readonly bomRef?: string;
  readonly cpe?: string;
  readonly notePath?: string | null;
  readonly purl?: string;
  readonly version?: string;
}

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const slugifyToken = (value: string): string =>
  normalizeToken(value)
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');

export const createComponentOccurrenceId = (
  sbomId: string,
  identity: {
    bomRef?: string;
    componentId?: string;
    name: string;
    purl?: string;
    version?: string;
  }
): string => {
  const normalizedSbomId = sbomId.trim();
  if (!normalizedSbomId) {
    throw new Error('Component occurrence requires an SBOM identifier.');
  }

  const candidate = identity.bomRef?.trim()
    || identity.purl?.trim()
    || [identity.name.trim(), identity.version?.trim()].filter(Boolean).join('@')
    || identity.componentId?.trim()
    || identity.name.trim();
  const normalizedCandidate = slugifyToken(candidate);
  if (!normalizedCandidate) {
    throw new Error('Component occurrence requires a stable identity token.');
  }

  return `component-occurrence::${normalizedSbomId}::${normalizedCandidate}`;
};
