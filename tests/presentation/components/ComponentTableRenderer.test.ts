import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  RelatedVulnerabilitySummary,
  TrackedComponent,
  TrackedComponentSource
} from '../../../src/application/sbom/types';
import {
  type ComponentTableRowModel,
  ComponentTableRenderer
} from '../../../src/presentation/components/sbom/ComponentTableRenderer';
import { installFakeDom, createRoot, type FakeTableRowElement } from '../../support/fakeDom';

installFakeDom();

const createSource = (
  overrides: Partial<TrackedComponentSource> = {}
): TrackedComponentSource => ({
  componentId: 'component-1',
  componentKey: 'purl:pkg:npm/widget@1.0.0',
  documentName: 'widget',
  format: 'cyclonedx',
  id: 'component-occurrence::sbom-a::widget',
  name: 'widget',
  projectId: 'project::portal-web',
  projectName: 'Portal Web',
  sbomFileName: 'portal-web.cdx.json',
  sbomId: 'sbom-a',
  sbomLabel: 'portal-web',
  sourcePath: 'reports/portal-web.cdx.json',
  vulnerabilityCount: 0,
  vulnerabilityIds: [],
  version: '1.0.0',
  ...overrides
});

const createComponent = (
  key: string,
  overrides: Partial<TrackedComponent> = {}
): TrackedComponent => ({
  cweGroups: [],
  formats: ['cyclonedx'],
  isEnabled: true,
  isFollowed: false,
  key,
  name: key.split('@')[0]?.split('/').pop() ?? key,
  sourceFiles: ['reports/portal-web.cdx.json'],
  sources: [createSource({ componentKey: key, id: `component-occurrence::${key}` })],
  vulnerabilities: [],
  vulnerabilityCount: 0,
  version: '1.0.0',
  ...overrides
});

const createRelatedVulnerability = (
  overrides: Partial<RelatedVulnerabilitySummary> = {}
): RelatedVulnerabilitySummary => ({
  cvssScore: 8.1,
  evidence: 'purl',
  id: 'CVE-2026-0001',
  referenceCount: 1,
  severity: 'HIGH',
  source: 'OSV',
  title: 'Widget issue',
  ...overrides
});

const createRowModel = (
  key: string,
  overrides: Partial<ComponentTableRowModel> = {}
): ComponentTableRowModel => {
  const component = overrides.component ?? createComponent(key);
  const vulnerabilityCount = overrides.vulnerabilityCount ?? 0;
  const highestSeverity = overrides.highestSeverity;
  const relatedVulnerabilities = overrides.relatedVulnerabilities ?? [];
  const isExpanded = overrides.isExpanded ?? false;
  const isSelected = overrides.isSelected ?? false;

  return {
    component,
    componentName: component.name,
    highestSeverity,
    identifierLabel: component.purl ?? component.cpe ?? 'None',
    isExpanded,
    isSelected,
    key,
    projectLabel: 'Portal Web',
    relatedVulnerabilities,
    rowStateHash: [
      key,
      component.name,
      component.version ?? '',
      String(vulnerabilityCount),
      highestSeverity ?? '',
      isExpanded ? 'expanded' : 'collapsed',
      isSelected ? 'selected' : 'unselected',
      relatedVulnerabilities.map((vulnerability) => vulnerability.id).join('|')
    ].join('::'),
    sbomLabel: 'portal-web.cdx.json',
    supplierLabel: component.supplier ?? 'Unknown supplier',
    versionLabel: component.version ?? 'No version',
    vulnerabilityCount,
    ...overrides
  };
};

const getBodyRows = (container: HTMLElement): FakeTableRowElement[] => {
  const body = container.querySelector('tbody');
  assert.ok(body);
  return Array.from(body.children)
    .filter((child) =>
      child instanceof HTMLTableRowElement && child.classList.contains('vulndash-component-table-row')
    ) as unknown as FakeTableRowElement[];
};

const getRowByKey = (container: HTMLElement, key: string): FakeTableRowElement => {
  const row = getBodyRows(container).find((entry) => entry.dataset.componentKey === key);
  assert.ok(row, `expected row for ${key}`);
  return row;
};

const createRenderer = () => new ComponentTableRenderer({
  detailsRenderer: {
    renderDetails: async (containerEl: HTMLElement, component: TrackedComponent): Promise<void> => {
      containerEl.textContent = `details:${component.key}`;
    }
  } as never,
  onDisableComponent: async () => undefined,
  onEnableComponent: async () => undefined,
  onFollowComponent: async () => undefined,
  onSelectComponent: () => undefined,
  onToggleExpanded: () => undefined,
  onUnfollowComponent: async () => undefined
});

test('ComponentTableRenderer initial render creates stable table rows', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();
  renderer.mount(host);

  renderer.render([
    createRowModel('purl:pkg:npm/a@1.0.0'),
    createRowModel('purl:pkg:npm/b@1.0.0')
  ]);

  assert.equal(getBodyRows(host).length, 2);
  assert.equal(renderer.getLastRenderMetrics()?.createdRows, 2);
});

test('ComponentTableRenderer identical render preserves row identities', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();
  const rows = [
    createRowModel('purl:pkg:npm/a@1.0.0'),
    createRowModel('purl:pkg:npm/b@1.0.0')
  ];

  renderer.mount(host);
  renderer.render(rows);
  const beforeA = getRowByKey(host, rows[0]!.key);
  const beforeB = getRowByKey(host, rows[1]!.key);

  renderer.render(rows);

  assert.equal(getRowByKey(host, rows[0]!.key), beforeA);
  assert.equal(getRowByKey(host, rows[1]!.key), beforeB);
  assert.equal(renderer.getLastRenderMetrics()?.patchedRows, 0);
  assert.equal(renderer.getLastRenderMetrics()?.createdRows, 0);
});

test('ComponentTableRenderer adding one row creates only one new node', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();
  const baseRows = [
    createRowModel('purl:pkg:npm/a@1.0.0'),
    createRowModel('purl:pkg:npm/b@1.0.0')
  ];

  renderer.mount(host);
  renderer.render(baseRows);
  const beforeA = getRowByKey(host, baseRows[0]!.key);
  const beforeB = getRowByKey(host, baseRows[1]!.key);

  const nextRows = [...baseRows, createRowModel('purl:pkg:npm/c@1.0.0')];
  renderer.render(nextRows);

  assert.equal(getRowByKey(host, baseRows[0]!.key), beforeA);
  assert.equal(getRowByKey(host, baseRows[1]!.key), beforeB);
  assert.equal(getBodyRows(host).length, 3);
  assert.equal(renderer.getLastRenderMetrics()?.createdRows, 1);
});

test('ComponentTableRenderer removing one row removes only that node', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();
  const rows = [
    createRowModel('purl:pkg:npm/a@1.0.0'),
    createRowModel('purl:pkg:npm/b@1.0.0'),
    createRowModel('purl:pkg:npm/c@1.0.0')
  ];

  renderer.mount(host);
  renderer.render(rows);
  const beforeA = getRowByKey(host, rows[0]!.key);
  const beforeC = getRowByKey(host, rows[2]!.key);

  renderer.render([rows[0]!, rows[2]!]);

  assert.equal(getBodyRows(host).length, 2);
  assert.equal(getRowByKey(host, rows[0]!.key), beforeA);
  assert.equal(getRowByKey(host, rows[2]!.key), beforeC);
  assert.equal(getBodyRows(host).some((row) => row.dataset.componentKey === rows[1]!.key), false);
  assert.equal(renderer.getLastRenderMetrics()?.removedRows, 1);
});

test('ComponentTableRenderer patches only dirty rows in place', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();
  const cleanRow = createRowModel('purl:pkg:npm/a@1.0.0');
  const dirtyRow = createRowModel('purl:pkg:npm/b@1.0.0');

  renderer.mount(host);
  renderer.render([cleanRow, dirtyRow]);
  const beforeClean = getRowByKey(host, cleanRow.key);
  const beforeDirty = getRowByKey(host, dirtyRow.key);

  const updatedDirtyRow = createRowModel('purl:pkg:npm/b@1.0.0', {
    highestSeverity: 'high',
    relatedVulnerabilities: [createRelatedVulnerability()],
    vulnerabilityCount: 1
  });
  renderer.render([cleanRow, updatedDirtyRow]);

  assert.equal(getRowByKey(host, cleanRow.key), beforeClean);
  assert.equal(getRowByKey(host, updatedDirtyRow.key), beforeDirty);
  assert.equal(getRowByKey(host, updatedDirtyRow.key).cells.item(5)?.textContent.includes('1'), true);
  assert.equal(renderer.getLastRenderMetrics()?.patchedRows, 1);
  assert.equal(renderer.getLastRenderMetrics()?.createdRows, 0);
  assert.equal(renderer.getLastRenderMetrics()?.removedRows, 0);
});

test('ComponentTableRenderer sorting reorders existing row nodes', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();
  const rows = [
    createRowModel('purl:pkg:npm/a@1.0.0'),
    createRowModel('purl:pkg:npm/b@1.0.0'),
    createRowModel('purl:pkg:npm/c@1.0.0')
  ];

  renderer.mount(host);
  renderer.render(rows);
  const beforeA = getRowByKey(host, rows[0]!.key);
  const beforeB = getRowByKey(host, rows[1]!.key);
  const beforeC = getRowByKey(host, rows[2]!.key);

  renderer.render([rows[2]!, rows[1]!, rows[0]!]);

  const reordered = getBodyRows(host);
  assert.deepEqual(reordered.map((row) => row.dataset.componentKey), [
    rows[2]!.key,
    rows[1]!.key,
    rows[0]!.key
  ]);
  assert.equal(getRowByKey(host, rows[0]!.key), beforeA);
  assert.equal(getRowByKey(host, rows[1]!.key), beforeB);
  assert.equal(getRowByKey(host, rows[2]!.key), beforeC);
  assert.equal(renderer.getLastRenderMetrics()?.movedRows, 2);
});

test('ComponentTableRenderer ignores duplicate or missing keys safely', () => {
  const host = createRoot() as unknown as HTMLElement;
  const renderer = createRenderer();

  renderer.mount(host);
  renderer.render([
    createRowModel('purl:pkg:npm/a@1.0.0'),
    createRowModel(''),
    createRowModel('purl:pkg:npm/a@1.0.0', { componentName: 'duplicate-a' })
  ]);

  assert.equal(getBodyRows(host).length, 1);
  assert.equal(getBodyRows(host)[0]?.dataset.componentKey, 'purl:pkg:npm/a@1.0.0');
});
