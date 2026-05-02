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
} from '../../../src/presentation/components/ComponentInventoryStore';

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
  source: 'GitHub',
  title: 'Widget issue',
  ...overrides
});

const createSnapshot = (
  components: TrackedComponent[],
  relationships?: Map<string, RelatedVulnerabilitySummary[]>,
  purlMatches: readonly ComponentPurlMatchSummary[] = []
): ComponentInventoryWorkspaceSnapshot => {
  const occurrences = components.flatMap((component) => component.sources);
  const occurrenceCount = occurrences.length;

  return {
    inventory: {
      catalog: {
        componentCount: components.length,
        components,
        formats: ['cyclonedx', 'spdx'],
        occurrenceCount,
        sourceFiles: ['reports/a.cdx.json', 'reports/b.spdx.json']
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
      componentsByVulnerability: new Map(),
      relationships: [],
      vulnerabilitiesByComponent: relationships ?? new Map(),
      vulnerabilitiesByOccurrence: new Map()
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
    severityThreshold: 'medium' as const,
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
  assert.deepEqual(derived.availableSourceFiles, ['reports/a.cdx.json', 'reports/b.spdx.json']);
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
