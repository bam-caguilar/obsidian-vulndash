import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ComponentQueryMatch,
  ComponentInventorySnapshot,
  ComponentRelationshipGraph,
  TrackedComponent,
  TrackedComponentSource
} from '../../../src/application/sbom/types';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import type { ComponentOccurrence } from '../../../src/domain/sbom/ComponentOccurrence';
import { buildComponentRelationshipGraphFromCache } from '../../../src/presentation/plugin/ComponentRelationshipGraph';

const createSource = (
  overrides: Partial<TrackedComponentSource> = {}
): TrackedComponentSource => ({
  componentId: 'component-1',
  componentKey: 'purl:pkg:npm/widget@1.2.3',
  documentName: 'sbom',
  format: 'cyclonedx',
  id: 'component-occurrence::sbom-1::component-1',
  name: 'widget',
  projectId: 'project::portal-web',
  projectName: 'Portal Web',
  sbomFileName: 'sbom.json',
  sbomId: 'sbom-1',
  sbomLabel: 'sbom',
  sourcePath: 'reports/sbom.json',
  vulnerabilityCount: 0,
  vulnerabilityIds: [],
  version: '1.2.3',
  ...overrides
});

const createComponent = (overrides: Partial<TrackedComponent> = {}): TrackedComponent => {
  const base: TrackedComponent = {
    cweGroups: [],
    formats: ['cyclonedx'],
    isEnabled: true,
    isFollowed: false,
    key: 'purl:pkg:npm/widget@1.2.3',
    name: 'widget',
    sourceFiles: ['reports/sbom.json'],
    sources: [],
    vulnerabilities: [],
    vulnerabilityCount: 0,
    version: '1.2.3'
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

const createInventory = (components: TrackedComponent[]): ComponentInventorySnapshot => {
  const occurrences = components.flatMap((component) => component.sources);
  const occurrenceCount = occurrences.length;

  return {
    catalog: {
      componentCount: components.length,
      components,
      formats: ['cyclonedx'],
      occurrenceCount,
      sourceFiles: ['reports/sbom.json']
    },
    configuredSbomCount: 1,
    enabledSbomCount: 1,
    failedSbomCount: 0,
    issues: [],
    occurrences,
    occurrenceCount,
    parsedSbomCount: 1
  };
};

const createVulnerability = (id: string): Vulnerability => ({
  affectedProducts: ['widget'],
  cvssScore: 8.1,
  hydrationState: 'complete',
  id,
  publishedAt: '2026-01-01T00:00:00.000Z',
  references: [`https://example.com/${id}`],
  severity: 'HIGH',
  source: 'OSV',
  summary: `${id} summary`,
  title: `${id} title`,
  updatedAt: '2026-01-02T00:00:00.000Z'
});

test('buildComponentRelationshipGraphFromCache always uses cached vulnerabilities as correlation input', () => {
  const components = [createComponent()];
  const inventory = createInventory(components);
  const cachedVulnerabilities = [createVulnerability('OSV-2026-1'), createVulnerability('OSV-2026-2')];
  let capturedComponents: readonly TrackedComponent[] | null = null;
  let capturedOccurrences: readonly ComponentOccurrence[] | null = null;
  let capturedVulnerabilities: readonly Vulnerability[] | null = null;

  const graph: ComponentRelationshipGraph = {
    allSeveritiesByComponent: new Map(),
    componentsByVulnerability: new Map(),
    relationships: [],
    vulnerabilitiesByComponent: new Map(),
    vulnerabilitiesByOccurrence: new Map()
  };

  const result = buildComponentRelationshipGraphFromCache({
    buildGraph: (receivedComponents, receivedOccurrences, receivedVulnerabilities) => {
      capturedComponents = receivedComponents;
      capturedOccurrences = receivedOccurrences;
      capturedVulnerabilities = receivedVulnerabilities;
      return graph;
    }
  }, inventory, cachedVulnerabilities);

  assert.equal(result, graph);
  assert.equal(capturedComponents, inventory.catalog.components);
  assert.equal(capturedOccurrences, inventory.occurrences);
  assert.deepEqual(capturedVulnerabilities, cachedVulnerabilities);
  assert.notEqual(capturedVulnerabilities, cachedVulnerabilities);
});

test('buildComponentRelationshipGraphFromCache forwards purl query cache matches to the graph builder', () => {
  const components = [createComponent()];
  const inventory = createInventory(components);
  const cachedVulnerabilities = [createVulnerability('OSV-2026-1')];
  const queryMatches = new Map<string, readonly ComponentQueryMatch[]>([[
    'pkg:npm/widget@1.2.3',
    [{
      queriedPurl: 'pkg:npm/widget@1.2.3',
      sourceId: 'osv-default',
      vulnerability: cachedVulnerabilities[0]!,
      vulnerabilityCacheKey: 'osv-default::OSV-2026-1',
      vulnerabilityId: 'OSV-2026-1'
    }]
  ]]);
  let capturedOptions:
    | { purlQueryCacheMatches?: ReadonlyMap<string, readonly ComponentQueryMatch[]> }
    | undefined;

  buildComponentRelationshipGraphFromCache({
    buildGraph: (_receivedComponents, _receivedOccurrences, _receivedVulnerabilities, options) => {
      capturedOptions = options;
      return {
        allSeveritiesByComponent: new Map(),
        componentsByVulnerability: new Map(),
        relationships: [],
        vulnerabilitiesByComponent: new Map(),
        vulnerabilitiesByOccurrence: new Map()
      };
    }
  }, inventory, cachedVulnerabilities, { purlQueryCacheMatches: queryMatches });

  assert.equal(capturedOptions?.purlQueryCacheMatches, queryMatches);
});
