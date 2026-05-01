import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ComponentInventorySnapshot,
  ComponentRelationshipGraph,
  TrackedComponent
} from '../../../src/application/sbom/types';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { buildComponentRelationshipGraphFromCache } from '../../../src/presentation/plugin/ComponentRelationshipGraph';

const createComponent = (overrides: Partial<TrackedComponent> = {}): TrackedComponent => ({
  cweGroups: [],
  formats: ['cyclonedx'],
  isEnabled: true,
  isFollowed: false,
  key: 'purl:pkg:npm/widget@1.2.3',
  name: 'widget',
  sourceFiles: ['reports/sbom.json'],
  sources: [{
    componentId: 'component-1',
    documentName: 'sbom',
    format: 'cyclonedx',
    name: 'widget',
    sourcePath: 'reports/sbom.json',
    version: '1.2.3'
  }],
  vulnerabilities: [],
  vulnerabilityCount: 0,
  version: '1.2.3',
  ...overrides
});

const createInventory = (components: TrackedComponent[]): ComponentInventorySnapshot => ({
  catalog: {
    componentCount: components.length,
    components,
    formats: ['cyclonedx'],
    sourceFiles: ['reports/sbom.json']
  },
  configuredSbomCount: 1,
  enabledSbomCount: 1,
  failedSbomCount: 0,
  issues: [],
  parsedSbomCount: 1
});

const createVulnerability = (id: string): Vulnerability => ({
  affectedProducts: ['widget'],
  cvssScore: 8.1,
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
  let capturedVulnerabilities: readonly Vulnerability[] | null = null;

  const graph: ComponentRelationshipGraph = {
    componentsByVulnerability: new Map(),
    relationships: [],
    vulnerabilitiesByComponent: new Map()
  };

  const result = buildComponentRelationshipGraphFromCache({
    buildGraph: (receivedComponents, receivedVulnerabilities) => {
      capturedComponents = receivedComponents;
      capturedVulnerabilities = receivedVulnerabilities;
      return graph;
    }
  }, inventory, cachedVulnerabilities);

  assert.equal(result, graph);
  assert.equal(capturedComponents, inventory.catalog.components);
  assert.deepEqual(capturedVulnerabilities, cachedVulnerabilities);
  assert.notEqual(capturedVulnerabilities, cachedVulnerabilities);
});
