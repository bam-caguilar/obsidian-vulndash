import type {
  NormalizedSbomFormat,
  NormalizedSeverity
} from '../../domain/sbom/types';
import { getHighestSeverity, getSeverityRank } from '../../domain/value-objects/Severity';
import type {
  ComponentPurlMatchSummary,
  ComponentInventoryWorkspaceSnapshot,
  RelatedVulnerabilitySummary,
  TrackedComponent,
  TrackedComponentSource
} from '../../application/sbom/types';

export type ComponentSeverityFilter = 'any' | NormalizedSeverity;

export interface ComponentInventoryFilters {
  enabledOnly: boolean;
  followedOnly: boolean;
  projectId: string;
  searchQuery: string;
  sourceFile: string;
  sourceFormat: 'all' | NormalizedSbomFormat;
  severityThreshold: ComponentSeverityFilter;
  sbomId: string;
  vulnerableOnly: boolean;
}

export interface ComponentInventorySummary {
  enabledCount: number;
  followedCount: number;
  totalCount: number;
  vulnerableCount: number;
}

export interface ComponentInventoryDerivedState {
  availableProjects: Array<{ id: string; name: string }>;
  availableSourceFiles: string[];
  availableSboms: Array<{ id: string; label: string }>;
  components: ComponentInventoryDisplayEntry[];
  hasActiveFilters: boolean;
  purlMatches: ComponentPurlMatchSummary[];
  summary: ComponentInventorySummary;
}

export interface ComponentInventoryDisplayEntry {
  component: TrackedComponent;
  highestSeverity: NormalizedSeverity | undefined;
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[];
  visibleSources: readonly TrackedComponentSource[];
  vulnerabilityCount: number;
}

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const severityFromRelatedVulnerability = (
  vulnerability: RelatedVulnerabilitySummary
): NormalizedSeverity | undefined => {
  switch (normalizeToken(vulnerability.severity)) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'informational':
    case 'info':
      return 'informational';
    default:
      return undefined;
  }
};

const getUniqueVulnerabilityCount = (
  vulnerabilityIds: readonly string[],
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[]
): number => {
  const identifiers = new Set<string>();

  for (const vulnerabilityId of vulnerabilityIds) {
    identifiers.add(normalizeToken(vulnerabilityId));
  }

  for (const vulnerability of relatedVulnerabilities) {
    identifiers.add(normalizeToken(vulnerability.id));
  }

  return Array.from(identifiers).filter(Boolean).length;
};

const getEffectiveHighestSeverity = (
  severities: ReadonlyArray<NormalizedSeverity | undefined>,
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[]
): NormalizedSeverity | undefined =>
  getHighestSeverity([
    ...severities,
    ...relatedVulnerabilities.map((vulnerability) => severityFromRelatedVulnerability(vulnerability))
  ]);

const matchesSourceScope = (
  source: TrackedComponentSource,
  filters: Pick<ComponentInventoryFilters, 'projectId' | 'sbomId' | 'sourceFile' | 'sourceFormat'>
): boolean => {
  if (filters.sourceFormat !== 'all' && source.format !== filters.sourceFormat) {
    return false;
  }

  if (filters.projectId !== 'all' && source.projectId !== filters.projectId) {
    return false;
  }

  if (filters.sbomId !== 'all' && source.sbomId !== filters.sbomId) {
    return false;
  }

  if (filters.sourceFile !== 'all' && source.sourcePath !== filters.sourceFile) {
    return false;
  }

  return true;
};

const hasScopedSourceFilters = (
  filters: Pick<ComponentInventoryFilters, 'projectId' | 'sbomId' | 'sourceFile' | 'sourceFormat'>
): boolean =>
  filters.projectId !== 'all'
  || filters.sbomId !== 'all'
  || filters.sourceFile !== 'all'
  || filters.sourceFormat !== 'all';

const getVisibleSources = (
  component: TrackedComponent,
  filters: Pick<ComponentInventoryFilters, 'projectId' | 'sbomId' | 'sourceFile' | 'sourceFormat'>
): readonly TrackedComponentSource[] => {
  if (!hasScopedSourceFilters(filters)) {
    return component.sources;
  }

  return component.sources.filter((source) => matchesSourceScope(source, filters));
};

const getScopedEmbeddedVulnerabilities = (
  component: TrackedComponent,
  sources: readonly TrackedComponentSource[]
): ReadonlyArray<TrackedComponent['vulnerabilities'][number]> => {
  const visibleVulnerabilityIds = new Set(
    sources.flatMap((source) => source.vulnerabilityIds.map((vulnerabilityId) => normalizeToken(vulnerabilityId)))
  );
  if (visibleVulnerabilityIds.size === 0) {
    return [];
  }

  return component.vulnerabilities.filter((vulnerability) => visibleVulnerabilityIds.has(normalizeToken(vulnerability.id)));
};

const getScopedRelatedVulnerabilities = (
  snapshot: ComponentInventoryWorkspaceSnapshot,
  component: TrackedComponent,
  sources: readonly TrackedComponentSource[]
): readonly RelatedVulnerabilitySummary[] => {
  const deduped = new Map<string, RelatedVulnerabilitySummary>();
  let hasOccurrenceMappings = false;

  for (const source of sources) {
    if (snapshot.relationships.vulnerabilitiesByOccurrence.has(source.id)) {
      hasOccurrenceMappings = true;
    }
    const related = snapshot.relationships.vulnerabilitiesByOccurrence.get(source.id) ?? [];
    for (const vulnerability of related) {
      const key = `${normalizeToken(vulnerability.source)}::${normalizeToken(vulnerability.id)}`;
      if (!deduped.has(key)) {
        deduped.set(key, vulnerability);
      }
    }
  }

  if (!hasOccurrenceMappings) {
    for (const vulnerability of snapshot.relationships.vulnerabilitiesByComponent.get(component.key) ?? []) {
      const key = `${normalizeToken(vulnerability.source)}::${normalizeToken(vulnerability.id)}`;
      if (!deduped.has(key)) {
        deduped.set(key, vulnerability);
      }
    }
  }

  return Array.from(deduped.values());
};

const toDisplayEntry = (
  snapshot: ComponentInventoryWorkspaceSnapshot,
  component: TrackedComponent,
  filters: Pick<ComponentInventoryFilters, 'projectId' | 'sbomId' | 'sourceFile' | 'sourceFormat'>
): ComponentInventoryDisplayEntry => {
  const visibleSources = getVisibleSources(component, filters);
  const embeddedVulnerabilities = getScopedEmbeddedVulnerabilities(component, visibleSources);
  const relatedVulnerabilities = getScopedRelatedVulnerabilities(snapshot, component, visibleSources);

  return {
    component,
    highestSeverity: getEffectiveHighestSeverity(
      [
        ...embeddedVulnerabilities.map((vulnerability) => vulnerability.severity),
        visibleSources.length === component.sources.length ? component.highestSeverity : undefined
      ],
      relatedVulnerabilities
    ),
    relatedVulnerabilities,
    visibleSources,
    vulnerabilityCount: getUniqueVulnerabilityCount(
      embeddedVulnerabilities.map((vulnerability) => vulnerability.id),
      relatedVulnerabilities
    )
  };
};

const buildSearchHaystack = (entry: ComponentInventoryDisplayEntry): string =>
  [
    entry.component.name,
    entry.component.version,
    entry.component.supplier,
    entry.component.license,
    entry.component.purl,
    entry.component.cpe,
    entry.component.key,
    entry.component.notePath ?? '',
    ...entry.component.sourceFiles,
    ...entry.component.formats,
    ...entry.visibleSources.flatMap((source) => [
      source.projectId,
      source.projectName,
      source.sbomId,
      source.sbomLabel,
      source.sbomFileName
    ]),
    ...entry.component.vulnerabilities.map((vulnerability) => vulnerability.id),
    ...entry.component.cweGroups.map((group) => `cwe-${group.cwe}`),
    ...entry.relatedVulnerabilities.flatMap((vulnerability) => [
      vulnerability.id,
      vulnerability.source,
      vulnerability.title
    ])
  ].join(' ').toLowerCase();

const matchesSeverityThreshold = (
  entry: ComponentInventoryDisplayEntry,
  threshold: ComponentSeverityFilter
): boolean => {
  if (threshold === 'any') {
    return true;
  }

  const highestSeverity = entry.highestSeverity;
  if (!highestSeverity) {
    return false;
  }

  return getSeverityRank(highestSeverity) >= getSeverityRank(threshold);
};

export const createDefaultComponentInventoryFilters = (): ComponentInventoryFilters => ({
  enabledOnly: false,
  followedOnly: false,
  projectId: 'all',
  searchQuery: '',
  severityThreshold: 'any',
  sbomId: 'all',
  sourceFile: 'all',
  sourceFormat: 'all',
  vulnerableOnly: false
});

export const summarizeComponentInventory = (
  components: readonly ComponentInventoryDisplayEntry[]
): ComponentInventorySummary =>
  components.reduce<ComponentInventorySummary>((summary, component) => ({
    enabledCount: summary.enabledCount + (component.component.isEnabled ? 1 : 0),
    followedCount: summary.followedCount + (component.component.isFollowed ? 1 : 0),
    totalCount: summary.totalCount + 1,
    vulnerableCount: summary.vulnerableCount + (component.vulnerabilityCount > 0 ? 1 : 0)
  }), {
    enabledCount: 0,
    followedCount: 0,
    totalCount: 0,
    vulnerableCount: 0
  });

export const filterTrackedComponents = (
  components: readonly ComponentInventoryDisplayEntry[],
  filters: ComponentInventoryFilters
): ComponentInventoryDisplayEntry[] => {
  const normalizedQueryTokens = normalizeToken(filters.searchQuery)
    .split(' ')
    .filter(Boolean);

  return components.filter((component) => {
    if (filters.followedOnly && !component.component.isFollowed) {
      return false;
    }

    if (filters.enabledOnly && !component.component.isEnabled) {
      return false;
    }

    if (filters.vulnerableOnly && component.vulnerabilityCount === 0) {
      return false;
    }

    if (!matchesSeverityThreshold(component, filters.severityThreshold)) {
      return false;
    }

    if (getVisibleSources(component.component, filters).length === 0) {
      return false;
    }

    if (normalizedQueryTokens.length > 0) {
      const haystack = buildSearchHaystack(component);
      if (!normalizedQueryTokens.every((token) => haystack.includes(token))) {
        return false;
      }
    }

    return true;
  });
};

export const deriveComponentInventoryState = (
  snapshot: ComponentInventoryWorkspaceSnapshot,
  filters: ComponentInventoryFilters
): ComponentInventoryDerivedState => {
  const unscopedFilters = createDefaultComponentInventoryFilters();
  const sbomOptionScope = {
    projectId: filters.projectId,
    sbomId: 'all',
    sourceFile: 'all',
    sourceFormat: filters.sourceFormat
  } satisfies Pick<ComponentInventoryFilters, 'projectId' | 'sbomId' | 'sourceFile' | 'sourceFormat'>;
  const sourceFileOptionScope = {
    projectId: filters.projectId,
    sbomId: filters.sbomId,
    sourceFile: 'all',
    sourceFormat: filters.sourceFormat
  } satisfies Pick<ComponentInventoryFilters, 'projectId' | 'sbomId' | 'sourceFile' | 'sourceFormat'>;
  const allComponents = snapshot.inventory.catalog.components.map((component) =>
    toDisplayEntry(snapshot, component, unscopedFilters)
  );
  const filteredComponents = filterTrackedComponents(allComponents, filters)
    .map((entry) => toDisplayEntry(snapshot, entry.component, filters));
  const visibleComponentKeys = new Set(filteredComponents.map((entry) => entry.component.key));
  const availableProjects = Array.from(new Map(snapshot.inventory.occurrences
    .map((occurrence) => [occurrence.projectId, { id: occurrence.projectId, name: occurrence.projectName }] as const)).values())
    .sort((left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id));
  const availableSboms = Array.from(new Map(snapshot.inventory.occurrences
    .filter((occurrence) => matchesSourceScope(occurrence, sbomOptionScope))
    .map((occurrence) => [occurrence.sbomId, { id: occurrence.sbomId, label: occurrence.sbomFileName }] as const)).values())
    .sort((left, right) => left.label.localeCompare(right.label) || left.id.localeCompare(right.id));
  const availableSourceFiles = Array.from(new Set(snapshot.inventory.occurrences
    .filter((occurrence) => matchesSourceScope(occurrence, sourceFileOptionScope))
    .map((occurrence) => occurrence.sourcePath)
    .filter((sourcePath): sourcePath is string => Boolean(sourcePath))))
    .sort((left, right) => left.localeCompare(right));

  return {
    availableProjects,
    availableSourceFiles,
    availableSboms,
    components: filteredComponents,
    hasActiveFilters: hasActiveComponentInventoryFilters(filters),
    purlMatches: snapshot.purlMatches.filter((match) => visibleComponentKeys.has(match.componentKey)),
    summary: summarizeComponentInventory(allComponents)
  };
};

export const hasActiveComponentInventoryFilters = (
  filters: ComponentInventoryFilters
): boolean =>
  filters.enabledOnly
  || filters.followedOnly
  || filters.projectId !== 'all'
  || filters.sbomId !== 'all'
  || filters.vulnerableOnly
  || filters.severityThreshold !== 'any'
  || filters.sourceFormat !== 'all'
  || filters.sourceFile !== 'all'
  || normalizeToken(filters.searchQuery).length > 0;
