import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ComponentInventoryWorkspaceSnapshot,
  RelatedVulnerabilitySummary,
  TrackedComponent,
  TrackedComponentSource
} from '../../../src/application/sbom/types';
import { ComponentInventoryView } from '../../../src/presentation/components/sbom/ComponentInventoryView';
import { createDefaultComponentInventoryFilters, deriveComponentInventoryState } from '../../../src/presentation/components/sbom/ComponentInventoryStore';
import { createRoot, installFakeDom } from '../../support/fakeDom';

installFakeDom();

const deferred = <T>() => {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, reject, resolve };
};

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
  name: 'widget',
  sourceFiles: ['reports/portal-web.cdx.json'],
  sources: [createSource({ componentKey: key, id: `component-occurrence::${key}` })],
  vulnerabilities: [],
  vulnerabilityCount: 0,
  version: '1.0.0',
  ...overrides
});

const createSnapshot = (
  components: TrackedComponent[],
  related: Map<string, RelatedVulnerabilitySummary[]> = new Map()
): ComponentInventoryWorkspaceSnapshot => {
  const occurrences = components.flatMap((component) => component.sources);
  return {
    inventory: {
      catalog: {
        componentCount: components.length,
        components,
        formats: ['cyclonedx'],
        occurrenceCount: occurrences.length,
        sourceFiles: ['reports/portal-web.cdx.json']
      },
      configuredSbomCount: 1,
      enabledSbomCount: 1,
      failedSbomCount: 0,
      issues: [],
      occurrences,
      occurrenceCount: occurrences.length,
      parsedSbomCount: 1
    },
    purlMatches: [],
    relationships: {
      allSeveritiesByComponent: new Map(),
      componentsByVulnerability: new Map(),
      relationships: [],
      vulnerabilitiesByComponent: related,
      vulnerabilitiesByOccurrence: new Map()
    }
  };
};

const getTableShell = (root: HTMLElement): HTMLElement => {
  const shell = root.querySelector('.vulndash-component-table-shell') as HTMLElement | null;
  assert.ok(shell);
  return shell;
};

const getMainRows = (root: HTMLElement): HTMLElement[] =>
  Array.from(root.querySelectorAll('.vulndash-component-table-row')) as HTMLElement[];

const getRowComponentNames = (root: HTMLElement): string[] =>
  getMainRows(root)
    .map((row) => row.querySelector('.vulndash-component-name-stack'))
    .filter((stack): stack is HTMLElement => stack instanceof HTMLElement)
    .map((stack) => {
      const label = stack.querySelector('strong');
      return label?.textContent ?? '';
    });

const getSortButton = (root: HTMLElement, label: string): HTMLElement => {
  const buttons = Array.from(root.querySelectorAll('.vulndash-col-sort-btn')) as HTMLElement[];
  const match = buttons.find((button) => button.textContent.includes(label));
  assert.ok(match);
  return match;
};

test('ComponentInventoryView keeps the same table host during normal refresh', async () => {
  const root = createRoot() as unknown as HTMLElement;
  let nextSnapshot = createSnapshot([createComponent('purl:pkg:npm/widget@1.0.0')]);
  const view = new ComponentInventoryView({
    detailsRenderer: {
      renderDetails: async (): Promise<void> => undefined
    } as never,
    loadSnapshot: async () => nextSnapshot,
    onDisableComponent: async () => undefined,
    onEnableComponent: async () => undefined,
    onFollowComponent: async () => undefined,
    onUnfollowComponent: async () => undefined
  });

  view.mount(root);
  await view.setActive(true);
  const firstShell = getTableShell(root);
  const firstRow = getMainRows(root)[0];
  assert.ok(firstRow);

  nextSnapshot = createSnapshot([createComponent('purl:pkg:npm/widget@1.0.0')]);
  view.invalidate();
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(getTableShell(root), firstShell);
  assert.equal(getMainRows(root)[0], firstRow);
});

test('ComponentInventoryView keeps last known good rows visible during background sync and failure', async () => {
  const root = createRoot() as unknown as HTMLElement;
  const initialSnapshot = createSnapshot([createComponent('purl:pkg:npm/widget@1.0.0')]);
  const pendingRefresh = deferred<ComponentInventoryWorkspaceSnapshot>();
  let loadSnapshot = async (): Promise<ComponentInventoryWorkspaceSnapshot> => initialSnapshot;

  const view = new ComponentInventoryView({
    detailsRenderer: {
      renderDetails: async (): Promise<void> => undefined
    } as never,
    loadSnapshot: async () => loadSnapshot(),
    onDisableComponent: async () => undefined,
    onEnableComponent: async () => undefined,
    onFollowComponent: async () => undefined,
    onUnfollowComponent: async () => undefined
  });

  view.mount(root);
  await view.setActive(true);
  const shell = getTableShell(root);
  const firstRow = getMainRows(root)[0];
  assert.ok(firstRow);

  loadSnapshot = async () => pendingRefresh.promise;
  view.invalidate();
  await Promise.resolve();

  assert.equal(getTableShell(root), shell);
  assert.equal(getMainRows(root)[0], firstRow);

  pendingRefresh.reject(new Error('sync failed'));
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(getTableShell(root), shell);
  assert.equal(getMainRows(root)[0], firstRow);
});

test('deriveComponentInventoryState filtered empty state can retain the table shell contract', () => {
  const snapshot = createSnapshot([createComponent('purl:pkg:npm/widget@1.0.0')]);
  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    searchQuery: 'missing-component'
  });

  assert.equal(derived.hasActiveFilters, true);
  assert.equal(derived.components.length, 0);
});

test('ComponentInventoryView applies header sort state to row order and visible indicators', async () => {
  const root = createRoot() as unknown as HTMLElement;
  const snapshot = createSnapshot([
    createComponent('purl:pkg:npm/zeta@2.0.0', {
      name: 'Zeta',
      version: '2.0.0'
    }),
    createComponent('purl:pkg:npm/alpha@1.0.0', {
      name: 'Alpha',
      version: '1.0.0'
    })
  ]);

  const view = new ComponentInventoryView({
    detailsRenderer: {
      renderDetails: async (): Promise<void> => undefined
    } as never,
    loadSnapshot: async () => snapshot,
    onDisableComponent: async () => undefined,
    onEnableComponent: async () => undefined,
    onFollowComponent: async () => undefined,
    onUnfollowComponent: async () => undefined
  });

  view.mount(root);
  await view.setActive(true);

  assert.deepEqual(getRowComponentNames(root), ['Zeta', 'Alpha']);

  const sortButton = getSortButton(root, 'Component');
  sortButton.click();

  assert.deepEqual(getRowComponentNames(root), ['Alpha', 'Zeta']);
  assert.equal((sortButton as unknown as { attributes: Map<string, string> }).attributes.get('aria-sort'), 'ascending');

  const ascendingIndicator = sortButton.querySelector('.vulndash-sort-indicator');
  assert.equal(ascendingIndicator?.textContent, '^');

  sortButton.click();

  assert.deepEqual(getRowComponentNames(root), ['Zeta', 'Alpha']);
  assert.equal((sortButton as unknown as { attributes: Map<string, string> }).attributes.get('aria-sort'), 'descending');

  const descendingIndicator = sortButton.querySelector('.vulndash-sort-indicator');
  assert.equal(descendingIndicator?.textContent, 'v');
});
