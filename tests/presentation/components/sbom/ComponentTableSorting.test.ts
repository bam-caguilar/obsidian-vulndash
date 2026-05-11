import assert from 'node:assert/strict';
import test from 'node:test';
import type { TrackedComponent } from '../../../../src/application/sbom/types';
import { COMPONENT_TABLE_COLUMNS } from '../../../../src/presentation/components/sbom/ComponentTableColumns';
import type { ComponentInventoryDisplayEntry } from '../../../../src/presentation/components/sbom/ComponentInventoryStore';
import {
  applyColumnSort,
  DEFAULT_COMPONENT_TABLE_SORT_STATE,
  type ComponentTableSortState
} from '../../../../src/presentation/components/sbom/ComponentTableSortState';
import { sortComponentEntries } from '../../../../src/presentation/components/sbom/ComponentTableSorting';

function makeEntry(
  overrides: Omit<Partial<TrackedComponent>, 'highestSeverity' | 'vulnerabilityCount'> & {
    highestSeverity?: ComponentInventoryDisplayEntry['highestSeverity'];
    vulnerabilityCount?: number;
  }
): ComponentInventoryDisplayEntry {
  const { highestSeverity, vulnerabilityCount = 0, ...componentOverrides } = overrides;
  const component: TrackedComponent = {
    cweGroups: [],
    formats: [],
    isEnabled: true,
    isFollowed: false,
    key: componentOverrides.name ?? 'component',
    name: 'Component',
    sourceFiles: [],
    sources: [],
    vulnerabilities: [],
    vulnerabilityCount: 0,
    ...componentOverrides
  };

  return {
    allSeverities: [],
    activeRelatedVulnerabilities: [],
    component,
    highestSeverity,
    hydrationState: 'notApplicable',
    relatedVulnerabilities: [],
    visibleSources: [],
    vulnerabilityCount: vulnerabilityCount ?? component.vulnerabilityCount
  };
}

const sortAsc = (column: ComponentTableSortState['column']): ComponentTableSortState => ({
  column,
  direction: 'asc'
});

const sortDesc = (column: ComponentTableSortState['column']): ComponentTableSortState => ({
  column,
  direction: 'desc'
});

test('applyColumnSort defaults non-vulnerability columns to ascending and toggles on repeat clicks', () => {
  const first = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'name');
  const second = applyColumnSort(first, 'name');
  const third = applyColumnSort(second, 'name');

  assert.deepEqual(first, { column: 'name', direction: 'asc' });
  assert.deepEqual(second, { column: 'name', direction: 'desc' });
  assert.deepEqual(third, { column: 'name', direction: 'asc' });
});

test('applyColumnSort defaults vulnerabilities to descending and resets when switching columns', () => {
  const first = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'vulnerabilities');
  const second = applyColumnSort(first, 'version');

  assert.deepEqual(first, { column: 'vulnerabilities', direction: 'desc' });
  assert.deepEqual(second, { column: 'version', direction: 'asc' });
});

test('COMPONENT_TABLE_COLUMNS keeps metadata boundaries for sortable and non-sortable headers', () => {
  const sortableIds = COMPONENT_TABLE_COLUMNS.filter((column) => column.sortable).map((column) => column.id);

  assert.equal(COMPONENT_TABLE_COLUMNS.find((column) => column.id === 'actions')?.sortable, false);
  assert.equal(COMPONENT_TABLE_COLUMNS.find((column) => column.id === 'project')?.sortable, false);
  assert.equal(COMPONENT_TABLE_COLUMNS.find((column) => column.id === 'sbom')?.sortable, false);
  assert.deepEqual(sortableIds, ['name', 'version', 'purl', 'vulnerabilities']);
});

test('sortComponentEntries sorts names case-insensitively', () => {
  const alpha = makeEntry({ name: 'Alpha', key: 'a' });
  const beta = makeEntry({ name: 'beta', key: 'b' });
  const gamma = makeEntry({ name: 'Gamma', key: 'g' });

  const ascending = sortComponentEntries([gamma, alpha, beta], sortAsc('name'));
  const descending = sortComponentEntries([alpha, gamma, beta], sortDesc('name'));

  assert.deepEqual(ascending.map((entry) => entry.component.name), ['Alpha', 'beta', 'Gamma']);
  assert.deepEqual(descending.map((entry) => entry.component.name), ['Gamma', 'beta', 'Alpha']);
});

test('sortComponentEntries sorts versions numerically and keeps entries without versions first when ascending', () => {
  const v1 = makeEntry({ key: 'v1', version: '1.2.0' });
  const v2 = makeEntry({ key: 'v2', version: '1.10.0' });
  const v3 = makeEntry({ key: 'v3', version: '2.0.0' });
  const missing = makeEntry({ key: 'missing' });

  const ascending = sortComponentEntries([v2, v1, v3], sortAsc('version'));
  const descending = sortComponentEntries([v1, v3, v2], sortDesc('version'));
  const withMissing = sortComponentEntries([v1, missing], sortAsc('version'));

  assert.deepEqual(ascending.map((entry) => entry.component.version), ['1.2.0', '1.10.0', '2.0.0']);
  assert.deepEqual(descending.map((entry) => entry.component.version), ['2.0.0', '1.10.0', '1.2.0']);
  assert.equal(withMissing[0]?.component.key, 'missing');
});

test('sortComponentEntries uses supplier as the current type sort key', () => {
  const apache = makeEntry({ key: 'a', supplier: 'Apache' });
  const eclipse = makeEntry({ key: 'e', supplier: 'Eclipse' });
  const noSupplier = makeEntry({ key: 'n' });

  const ascending = sortComponentEntries([eclipse, apache, noSupplier], sortAsc('type'));
  const descending = sortComponentEntries([apache, eclipse, noSupplier], sortDesc('type'));

  assert.deepEqual(ascending.map((entry) => entry.component.supplier ?? ''), ['', 'Apache', 'Eclipse']);
  assert.deepEqual(descending.map((entry) => entry.component.supplier ?? ''), ['Eclipse', 'Apache', '']);
});

test('sortComponentEntries sorts purl using purl first and cpe as fallback', () => {
  const withPurl = makeEntry({ key: 'purl', purl: 'pkg:npm/lodash@4.0.0' });
  const withCpe = makeEntry({ key: 'cpe', cpe: 'cpe:/a:openssl:openssl:1.1.1' });
  const withoutIdentifier = makeEntry({ key: 'none' });

  const ascending = sortComponentEntries([withPurl, withCpe, withoutIdentifier], sortAsc('purl'));
  const descending = sortComponentEntries([withoutIdentifier, withPurl, withCpe], sortDesc('purl'));

  assert.deepEqual(ascending.map((entry) => entry.component.key), ['none', 'cpe', 'purl']);
  assert.deepEqual(descending.map((entry) => entry.component.key), ['purl', 'cpe', 'none']);
});

test('sortComponentEntries orders vulnerabilities by severity first and count second', () => {
  const critical = makeEntry({ key: 'critical', highestSeverity: 'critical', vulnerabilityCount: 5 });
  const high = makeEntry({ key: 'high', highestSeverity: 'high', vulnerabilityCount: 3 });
  const highMore = makeEntry({ key: 'high-more', highestSeverity: 'high', vulnerabilityCount: 10 });
  const none = makeEntry({ key: 'none', highestSeverity: 'none', vulnerabilityCount: 0 });
  const unknown = makeEntry({ key: 'unknown', vulnerabilityCount: 0 });

  const descending = sortComponentEntries([none, high, critical, highMore], sortDesc('vulnerabilities'));
  const ascending = sortComponentEntries([critical, high, none, unknown], sortAsc('vulnerabilities'));

  assert.deepEqual(descending.map((entry) => entry.component.key), ['critical', 'high-more', 'high', 'none']);
  assert.equal(ascending.at(-1)?.component.key, 'critical');
  assert.equal(sortComponentEntries([critical, unknown], sortDesc('vulnerabilities'))[1]?.component.key, 'unknown');
});

test('sortComponentEntries does not mutate the source array and returns a new array for null sort state', () => {
  const beta = makeEntry({ name: 'Beta', key: 'b' });
  const alpha = makeEntry({ name: 'Alpha', key: 'a' });
  const original = [beta, alpha];
  const snapshot = [...original];

  sortComponentEntries(original, sortAsc('name'));
  const untouched = sortComponentEntries(original, DEFAULT_COMPONENT_TABLE_SORT_STATE);

  assert.deepEqual(original, snapshot);
  assert.notEqual(untouched, original);
});

test('sortComponentEntries falls back to name and version when primary sort keys are equal', () => {
  const first = makeEntry({ key: 'a', name: 'alpha', version: '1.0.0' });
  const second = makeEntry({ key: 'b', name: 'alpha', version: '2.0.0' });

  const result = sortComponentEntries([second, first], sortAsc('type'));

  assert.deepEqual(result.map((entry) => entry.component.key), ['a', 'b']);
});
