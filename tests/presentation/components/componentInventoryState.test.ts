import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ComponentPurlMatchSummary,
  ComponentInventoryWorkspaceSnapshot,
  RelatedVulnerabilitySummary,
  TrackedComponent,
  TrackedComponentSource
} from '../../../src/application/sbom/types';
import {
  createDefaultComponentInventoryFilters,
  deriveComponentInventoryState,
  filterTrackedComponents
} from '../../../src/presentation/components/sbom/ComponentInventoryStore';

const createSource = (
  overrides: Partial<TrackedComponentSource> = {}
): TrackedComponentSource => ({
  componentId: 'component-1',
  componentKey: 'name-version:component@1.0.0',
  documentName: 'a',
  format: 'cyclonedx',
  id: 'component-occurrence::sbom-a::component-1',
  name: 'component',
  projectId: 'project::portal-web',
  projectName: 'Portal Web',
  sbomFileName: 'a.cdx.json',
  sbomId: 'sbom-a',
  sbomLabel: 'a',
  sourcePath: 'reports/a.cdx.json',
  vulnerabilityCount: 0,
  vulnerabilityIds: [],
  version: '1.0.0',
  ...overrides
});

const createComponent = (overrides: Partial<TrackedComponent> = {}): TrackedComponent => {
  const base: TrackedComponent = {
    cweGroups: [],
    formats: ['cyclonedx'],
    isEnabled: true,
    isFollowed: false,
    key: 'name-version:component@1.0.0',
    name: 'component',
    sourceFiles: ['reports/a.cdx.json'],
    sources: [],
    vulnerabilities: [],
    vulnerabilityCount: 0,
    version: '1.0.0'
  };
  const component = {
    ...base,
    ...overrides
  };

  return {
    ...component,
    sources: overrides.sources ?? [createSource({
      componentKey: component.key,
      name: component.name,
      vulnerabilityCount: component.vulnerabilityCount,
      vulnerabilityIds: component.vulnerabilities.map((vulnerability) => vulnerability.id),
      ...(component.purl ? { purl: component.purl } : {}),
      ...(component.version ? { version: component.version } : {})
    })]
  };
};

const createRelatedVulnerability = (
  overrides: Partial<RelatedVulnerabilitySummary> = {}
): RelatedVulnerabilitySummary => ({
  cvssScore: 8.1,
  evidence: 'purl',
  id: 'GHSA-aaaa-bbbb-cccc',
  referenceCount: 2,
  severity: 'HIGH',
  severityRank: 5,
  source: 'GitHub',
  title: 'Widget issue',
  ...overrides
});

const createSnapshot = (
  components: TrackedComponent[],
  relationshipsByComponent?: Map<string, RelatedVulnerabilitySummary[]>,
  purlMatches: readonly ComponentPurlMatchSummary[] = [],
  relationshipsByOccurrence: Map<string, RelatedVulnerabilitySummary[]> = new Map()
): ComponentInventoryWorkspaceSnapshot => {
  const occurrences = components.flatMap((component) => component.sources);
  const occurrenceCount = occurrences.length;
  const sourceFiles = Array.from(new Set(occurrences
    .map((occurrence) => occurrence.sourcePath)
    .filter((sourcePath): sourcePath is string => Boolean(sourcePath))))
    .sort((left, right) => left.localeCompare(right));
  const formats = Array.from(new Set(occurrences.map((occurrence) => occurrence.format)))
    .sort((left, right) => left.localeCompare(right));

  return {
    inventory: {
      catalog: {
        componentCount: components.length,
        components,
        formats,
        occurrenceCount,
        sourceFiles
      },
      configuredSbomCount: 2,
      enabledSbomCount: 2,
      failedSbomCount: 0,
      issues: [],
      occurrences,
      occurrenceCount,
      parsedSbomCount: 2
    },
    relationships: {
      allSeveritiesByComponent: new Map(),
      componentsByVulnerability: new Map(),
      relationships: [],
      vulnerabilitiesByComponent: relationshipsByComponent ?? new Map(),
      vulnerabilitiesByOccurrence: relationshipsByOccurrence
    },
    purlMatches
  };
};

test('filterTrackedComponents combines search, follow, enabled, vulnerability, severity, format, and source filters', () => {
  const snapshot = createSnapshot([
    createComponent({
      cweGroups: [{ count: 1, cwe: 79, vulnerabilityIds: ['CVE-2026-0001'] }],
      highestSeverity: 'high',
      isFollowed: true,
      key: 'purl:pkg:npm/lodash@4.17.21',
      name: 'lodash',
      purl: 'pkg:npm/lodash@4.17.21',
      supplier: 'Example Co',
      vulnerabilities: [{
        cwes: [79],
        id: 'CVE-2026-0001',
        severity: 'high'
      }],
      vulnerabilityCount: 1,
      version: '4.17.21'
    }),
    createComponent({
      formats: ['spdx'],
      isEnabled: false,
      key: 'name-version:express@4.19.2',
      name: 'express',
      sourceFiles: ['reports/b.spdx.json'],
      sources: [createSource({
        componentId: 'component-2',
        componentKey: 'name-version:express@4.19.2',
        documentName: 'b',
        format: 'spdx',
        id: 'component-occurrence::sbom-b::component-2',
        name: 'express',
        projectId: 'project::identity-api',
        projectName: 'Identity API',
        sbomFileName: 'b.spdx.json',
        sbomId: 'sbom-b',
        sbomLabel: 'b',
        sourcePath: 'reports/b.spdx.json',
        version: '4.19.2'
      })],
      version: '4.19.2'
    })
  ]);

  const filters = {
    ...createDefaultComponentInventoryFilters(),
    enabledOnly: true,
    followedOnly: true,
    searchQuery: 'lodash cve-2026-0001',
    severityThreshold: 'high' as const,
    sourceFile: 'reports/a.cdx.json',
    sourceFormat: 'cyclonedx' as const,
    vulnerableOnly: true
  };

  const unfiltered = deriveComponentInventoryState(snapshot, createDefaultComponentInventoryFilters());

  assert.deepEqual(filterTrackedComponents(unfiltered.components, filters).map((entry) => entry.component.name), ['lodash']);
});

test('deriveComponentInventoryState returns deterministic summaries and no-results visibility data', () => {
  const snapshot = createSnapshot([
    createComponent({
      isFollowed: true,
      key: 'purl:pkg:npm/lodash@4.17.21',
      name: 'lodash',
      vulnerabilities: [{
        cwes: [79],
        id: 'CVE-2026-0001',
        severity: 'high'
      }],
      vulnerabilityCount: 1
    }),
    createComponent({
      isEnabled: false,
      key: 'name-version:express@4.19.2',
      name: 'express'
    })
  ]);

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    followedOnly: true
  });

  assert.equal(derived.summary.totalCount, 2);
  assert.equal(derived.summary.followedCount, 1);
  assert.equal(derived.summary.enabledCount, 1);
  assert.equal(derived.summary.vulnerableCount, 1);
  assert.equal(derived.hasActiveFilters, true);
  assert.deepEqual(derived.components.map((entry) => entry.component.name), ['lodash']);
  assert.deepEqual(derived.availableProjects, [
    { id: 'project::portal-web', name: 'Portal Web' }
  ]);
  assert.deepEqual(derived.availableSboms, [
    { id: 'sbom-a', label: 'a.cdx.json' }
  ]);
  assert.deepEqual(derived.availableSourceFiles, ['reports/a.cdx.json']);
});

test('deriveComponentInventoryState counts linked vulnerabilities even when the SBOM component has none embedded', () => {
  const snapshot = createSnapshot([
    createComponent({
      key: 'purl:pkg:npm/widget@1.2.3',
      name: 'widget',
      purl: 'pkg:npm/widget@1.2.3',
      version: '1.2.3'
    })
  ], new Map([
    ['purl:pkg:npm/widget@1.2.3', [createRelatedVulnerability()]]
  ]));

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    searchQuery: 'ghsa-aaaa-bbbb-cccc',
    vulnerableOnly: true
  });

  assert.equal(derived.summary.vulnerableCount, 1);
  assert.equal(derived.components[0]?.vulnerabilityCount, 1);
  assert.equal(derived.components[0]?.highestSeverity, 'high');
  assert.deepEqual(derived.components.map((entry) => entry.component.name), ['widget']);
});

test('deriveComponentInventoryState filters purl diagnostics to the visible component set', () => {
  const snapshot = createSnapshot([
    createComponent({
      isFollowed: true,
      key: 'purl:pkg:npm/lodash@4.17.21',
      name: 'lodash',
      purl: 'pkg:npm/lodash@4.17.21',
      version: '4.17.21'
    }),
    createComponent({
      isFollowed: false,
      key: 'purl:pkg:npm/express@4.19.2',
      name: 'express',
      purl: 'pkg:npm/express@4.19.2',
      version: '4.19.2'
    })
  ], undefined, [
    {
      cachedHitCount: 1,
      cachedHits: [{
        cacheKey: 'osv-default::GHSA-lodash',
        evidence: 'component-query-cache',
        source: 'OSV',
        vulnerabilityId: 'GHSA-lodash'
      }],
      componentKey: 'purl:pkg:npm/lodash@4.17.21',
      componentName: 'lodash',
      componentVersion: '4.17.21',
      correlatedMatchCount: 1,
      correlatedMatches: [{
        evidence: 'payload-purl',
        source: 'OSV',
        vulnerabilityId: 'GHSA-lodash'
      }],
      normalizedPurl: 'pkg:npm/lodash@4.17.21',
      queryState: 'hit'
    },
    {
      cachedHitCount: 0,
      cachedHits: [],
      componentKey: 'purl:pkg:npm/express@4.19.2',
      componentName: 'express',
      componentVersion: '4.19.2',
      correlatedMatchCount: 0,
      correlatedMatches: [],
      normalizedPurl: 'pkg:npm/express@4.19.2',
      queryState: 'not-queried'
    }
  ]);

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    followedOnly: true
  });

  assert.deepEqual(derived.components.map((entry) => entry.component.name), ['lodash']);
  assert.deepEqual(derived.purlMatches.map((entry) => entry.componentName), ['lodash']);
  assert.equal(derived.purlMatches[0]?.queryState, 'hit');
});

test('deriveComponentInventoryState scopes SBOM and source-file filters to the selected project', () => {
  const portalSource = createSource();
  const identitySource = createSource({
    componentId: 'component-2',
    componentKey: 'name-version:component@1.0.0',
    documentName: 'b',
    format: 'spdx',
    id: 'component-occurrence::sbom-b::component-2',
    projectId: 'project::identity-api',
    projectName: 'Identity API',
    sbomFileName: 'identity-api.spdx.json',
    sbomId: 'sbom-b',
    sbomLabel: 'b',
    sourcePath: 'reports/identity-api.spdx.json'
  });

  const snapshot = createSnapshot([
    createComponent({
      sources: [portalSource, identitySource],
      sourceFiles: ['reports/a.cdx.json', 'reports/identity-api.spdx.json']
    })
  ]);

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    projectId: 'project::identity-api'
  });

  assert.deepEqual(derived.availableSboms, [
    { id: 'sbom-b', label: 'identity-api.spdx.json' }
  ]);
  assert.deepEqual(derived.availableSourceFiles, ['reports/identity-api.spdx.json']);
  assert.deepEqual(derived.components[0]?.visibleSources.map((source) => source.projectId), ['project::identity-api']);
});

test('deriveComponentInventoryState scopes vulnerability counts to the selected project occurrence', () => {
  const portalSource = createSource({
    id: 'component-occurrence::sbom-a::widget',
    vulnerabilityCount: 1,
    vulnerabilityIds: ['CVE-2026-0001']
  });
  const identitySource = createSource({
    componentId: 'component-2',
    componentKey: 'purl:pkg:npm/widget@1.2.3',
    id: 'component-occurrence::sbom-b::widget',
    projectId: 'project::identity-api',
    projectName: 'Identity API',
    sbomFileName: 'identity-api.spdx.json',
    sbomId: 'sbom-b',
    sbomLabel: 'b',
    sourcePath: 'reports/identity-api.spdx.json',
    vulnerabilityCount: 0,
    vulnerabilityIds: []
  });

  const component = createComponent({
    highestSeverity: 'high',
    key: 'purl:pkg:npm/widget@1.2.3',
    name: 'widget',
    purl: 'pkg:npm/widget@1.2.3',
    sourceFiles: ['reports/a.cdx.json', 'reports/identity-api.spdx.json'],
    sources: [portalSource, identitySource],
    vulnerabilities: [{
      cwes: [],
      id: 'CVE-2026-0001',
      severity: 'high'
    }],
    vulnerabilityCount: 1,
    version: '1.2.3'
  });

  const snapshot = createSnapshot(
    [component],
    undefined,
    [],
    new Map([
      ['component-occurrence::sbom-a::widget', [createRelatedVulnerability({
        id: 'CVE-2026-0001',
        severity: 'HIGH'
      })]]
    ])
  );

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    projectId: 'project::identity-api'
  });

  assert.equal(derived.components[0]?.vulnerabilityCount, 0);
  assert.equal(derived.components[0]?.highestSeverity, undefined);
  assert.deepEqual(derived.components[0]?.visibleSources.map((source) => source.id), ['component-occurrence::sbom-b::widget']);
});

test('deriveComponentInventoryState projects unknown vulnerability severity and filters it explicitly', () => {
  const snapshot = createSnapshot([createComponent({
    key: 'purl:pkg:npm/unknown-widget@1.2.3',
    name: 'unknown-widget',
    purl: 'pkg:npm/unknown-widget@1.2.3',
    version: '1.2.3'
  })], undefined, [], new Map([
    ['component-occurrence::sbom-a::component-1', [createRelatedVulnerability({
      cvssScore: 0,
      normalizedSeverity: {
        method: 'CVSS_V4',
        rating: 'unknown',
        source: 'osv-top-level',
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
      },
      severity: 'Unknown'
    })]]
  ]));

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    severityThreshold: 'unknown',
    vulnerableOnly: true
  });

  assert.equal(derived.components.length, 1);
  assert.equal(derived.components[0]?.highestSeverity, 'unknown');
  assert.equal(derived.components[0]?.relatedVulnerabilities[0]?.severity, 'Unknown');
});

test('filterTrackedComponents matches a component via a secondary lower-severity finding (multi-severity filtering defect)', () => {
  // Component has CRITICAL as highestSeverity but also has a HIGH finding.
  // Filtering by 'high' must still match it even though highestSeverity is 'critical'.
  const componentKey = 'purl:pkg:npm/multi-vuln@2.0.0';
  const sourceId = 'component-occurrence::sbom-a::component-1';
  const snapshot = createSnapshot(
    [createComponent({
      key: componentKey,
      name: 'multi-vuln',
      purl: 'pkg:npm/multi-vuln@2.0.0',
      version: '2.0.0'
    })],
    undefined,
    [],
    new Map([
      [sourceId, [
        createRelatedVulnerability({
          id: 'CVE-2026-CRITICAL',
          severity: 'CRITICAL',
          severityRank: 6,
          normalizedSeverity: { rating: 'critical', source: 'unknown' }
        }),
        createRelatedVulnerability({
          id: 'CVE-2026-HIGH',
          severity: 'HIGH',
          severityRank: 5,
          normalizedSeverity: { rating: 'high', source: 'unknown' }
        })
      ]]
    ])
  );

  // Manually inject allSeveritiesByComponent because createSnapshot uses an empty Map.
  (snapshot.relationships.allSeveritiesByComponent as Map<string, string[]>).set(
    componentKey,
    ['critical', 'high']
  );

  const defaultFilters = createDefaultComponentInventoryFilters();

  const filteredByCritical = filterTrackedComponents(
    deriveComponentInventoryState(snapshot, defaultFilters).components,
    { ...defaultFilters, severityThreshold: 'critical' }
  );
  assert.equal(filteredByCritical.length, 1, 'critical filter should match component with critical finding');

  const filteredByHigh = filterTrackedComponents(
    deriveComponentInventoryState(snapshot, defaultFilters).components,
    { ...defaultFilters, severityThreshold: 'high' }
  );
  assert.equal(filteredByHigh.length, 1, 'high filter should also match component that has a high finding alongside a critical one');

  const filteredByMedium = filterTrackedComponents(
    deriveComponentInventoryState(snapshot, defaultFilters).components,
    { ...defaultFilters, severityThreshold: 'medium' }
  );
  assert.equal(filteredByMedium.length, 0, 'medium filter should not match a component with only critical and high findings');
});
