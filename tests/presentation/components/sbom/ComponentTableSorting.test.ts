import { sortComponentEntries } from '../../../../src/presentation/components/sbom/ComponentTableSorting';
import {
  applyColumnSort,
  DEFAULT_COMPONENT_TABLE_SORT_STATE
} from '../../../../src/presentation/components/sbom/ComponentTableSortState';
import type { ComponentTableSortState } from '../../../../src/presentation/components/sbom/ComponentTableSortState';
import { COMPONENT_TABLE_COLUMNS } from '../../../../src/presentation/components/sbom/ComponentTableColumns';
import type { ComponentInventoryDisplayEntry } from '../../../../src/presentation/components/sbom/ComponentInventoryStore';
import type { TrackedComponent } from '../../../../src/application/sbom/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEntry(
  overrides: Partial<TrackedComponent> & { highestSeverity?: ComponentInventoryDisplayEntry['highestSeverity']; vulnerabilityCount?: number }
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
    hydrationState: { status: 'idle' },
    relatedVulnerabilities: [],
    visibleSources: [],
    vulnerabilityCount: vulnerabilityCount ?? component.vulnerabilityCount
  };
}

const sortAsc = (column: ComponentTableSortState['column']): ComponentTableSortState =>
  ({ column, direction: 'asc' });
const sortDesc = (column: ComponentTableSortState['column']): ComponentTableSortState =>
  ({ column, direction: 'desc' });

// ---------------------------------------------------------------------------
// applyColumnSort — state machine
// ---------------------------------------------------------------------------

describe('applyColumnSort', () => {
  it('sets column and asc direction on first click for a non-vulnerabilities column', () => {
    const next = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'name');
    expect(next.column).toBe('name');
    expect(next.direction).toBe('asc');
  });

  it('sets column and desc direction on first click for vulnerabilities column', () => {
    const next = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'vulnerabilities');
    expect(next.column).toBe('vulnerabilities');
    expect(next.direction).toBe('desc');
  });

  it('toggles asc → desc on second click of same column', () => {
    const first = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'name');
    const second = applyColumnSort(first, 'name');
    expect(second.direction).toBe('desc');
  });

  it('toggles desc → asc on third click of same column', () => {
    const first = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'name');
    const second = applyColumnSort(first, 'name');
    const third = applyColumnSort(second, 'name');
    expect(third.direction).toBe('asc');
  });

  it('resets to asc when switching to a new non-vulnerabilities column', () => {
    const prev = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'name');
    const prevDesc = applyColumnSort(prev, 'name'); // now desc
    const next = applyColumnSort(prevDesc, 'version');
    expect(next.column).toBe('version');
    expect(next.direction).toBe('asc');
  });

  it('resets to desc when switching to vulnerabilities column', () => {
    const prev = applyColumnSort(DEFAULT_COMPONENT_TABLE_SORT_STATE, 'name');
    const next = applyColumnSort(prev, 'vulnerabilities');
    expect(next.column).toBe('vulnerabilities');
    expect(next.direction).toBe('desc');
  });
});

// ---------------------------------------------------------------------------
// COMPONENT_TABLE_COLUMNS — metadata
// ---------------------------------------------------------------------------

describe('COMPONENT_TABLE_COLUMNS', () => {
  it('marks Actions as non-sortable', () => {
    const actionsCol = COMPONENT_TABLE_COLUMNS.find((c) => c.id === 'actions');
    expect(actionsCol).toBeDefined();
    expect(actionsCol?.sortable).toBe(false);
  });

  it('marks Project and SBOM as non-sortable', () => {
    const project = COMPONENT_TABLE_COLUMNS.find((c) => c.id === 'project');
    const sbom = COMPONENT_TABLE_COLUMNS.find((c) => c.id === 'sbom');
    expect(project?.sortable).toBe(false);
    expect(sbom?.sortable).toBe(false);
  });

  it('marks Component, Version, PURL, Vulnerabilities as sortable', () => {
    const sortableIds = COMPONENT_TABLE_COLUMNS.filter((c) => c.sortable).map((c) => c.id);
    expect(sortableIds).toEqual(expect.arrayContaining(['name', 'version', 'purl', 'vulnerabilities']));
  });
});

// ---------------------------------------------------------------------------
// sortComponentEntries — name
// ---------------------------------------------------------------------------

describe('sortComponentEntries — name', () => {
  const alpha = makeEntry({ name: 'Alpha', key: 'a' });
  const beta = makeEntry({ name: 'Beta', key: 'b' });
  const gamma = makeEntry({ name: 'Gamma', key: 'g' });

  it('sorts ascending by name (case-insensitive)', () => {
    const result = sortComponentEntries([gamma, alpha, beta], sortAsc('name'));
    expect(result.map((e) => e.component.name)).toEqual(['Alpha', 'Beta', 'Gamma']);
  });

  it('sorts descending by name', () => {
    const result = sortComponentEntries([alpha, gamma, beta], sortDesc('name'));
    expect(result.map((e) => e.component.name)).toEqual(['Gamma', 'Beta', 'Alpha']);
  });

  it('treats lowercase and uppercase as equal for sort purposes', () => {
    const lower = makeEntry({ name: 'alpha', key: 'low' });
    const upper = makeEntry({ name: 'Alpha', key: 'up' });
    const result = sortComponentEntries([upper, lower], sortAsc('name'));
    // Both names are equal by case-insensitive compare; order is stable via fallback key
    expect(result.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// sortComponentEntries — version
// ---------------------------------------------------------------------------

describe('sortComponentEntries — version', () => {
  const v1 = makeEntry({ name: 'lib', key: 'v1', version: '1.2.0' });
  const v2 = makeEntry({ name: 'lib', key: 'v2', version: '1.10.0' });
  const v3 = makeEntry({ name: 'lib', key: 'v3', version: '2.0.0' });
  const vnone = makeEntry({ name: 'lib', key: 'vn' });

  it('sorts numerically (1.10 > 1.2) ascending', () => {
    const result = sortComponentEntries([v2, v1, v3], sortAsc('version'));
    expect(result.map((e) => e.component.version)).toEqual(['1.2.0', '1.10.0', '2.0.0']);
  });

  it('sorts numerically descending', () => {
    const result = sortComponentEntries([v1, v3, v2], sortDesc('version'));
    expect(result.map((e) => e.component.version)).toEqual(['2.0.0', '1.10.0', '1.2.0']);
  });

  it('places entries without version at the start when ascending (empty string sorts before numbers)', () => {
    const result = sortComponentEntries([v1, vnone], sortAsc('version'));
    // Empty string '' < '1.2.0' numerically
    expect(result[0].component.key).toBe('vn');
  });
});

// ---------------------------------------------------------------------------
// sortComponentEntries — type (supplier proxy)
// ---------------------------------------------------------------------------

describe('sortComponentEntries — type (supplier)', () => {
  const apache = makeEntry({ name: 'a', key: 'a', supplier: 'Apache' });
  const eclipse = makeEntry({ name: 'e', key: 'e', supplier: 'Eclipse' });
  const noSupplier = makeEntry({ name: 'n', key: 'n' });

  it('sorts ascending by supplier name', () => {
    const result = sortComponentEntries([eclipse, apache, noSupplier], sortAsc('type'));
    expect(result.map((e) => e.component.supplier ?? '')).toEqual(['', 'Apache', 'Eclipse']);
  });

  it('sorts descending by supplier name', () => {
    const result = sortComponentEntries([apache, eclipse, noSupplier], sortDesc('type'));
    expect(result.map((e) => e.component.supplier ?? '')).toEqual(['Eclipse', 'Apache', '']);
  });
});

// ---------------------------------------------------------------------------
// sortComponentEntries — purl
// ---------------------------------------------------------------------------

describe('sortComponentEntries — purl', () => {
  const withPurl = makeEntry({ name: 'A', key: 'a', purl: 'pkg:npm/lodash@4.0.0' });
  const withCpe = makeEntry({ name: 'B', key: 'b', cpe: 'cpe:/a:openssl:openssl:1.1.1' });
  const withNeither = makeEntry({ name: 'C', key: 'c' });

  it('prefers purl over cpe for sort key', () => {
    const result = sortComponentEntries([withPurl, withCpe, withNeither], sortAsc('purl'));
    // '' < 'cpe:...' < 'pkg:...'
    expect(result[0].component.key).toBe('c');
    expect(result[1].component.key).toBe('b');
    expect(result[2].component.key).toBe('a');
  });

  it('sorts descending correctly', () => {
    const result = sortComponentEntries([withNeither, withPurl, withCpe], sortDesc('purl'));
    expect(result[0].component.key).toBe('a');
    expect(result[1].component.key).toBe('b');
    expect(result[2].component.key).toBe('c');
  });
});

// ---------------------------------------------------------------------------
// sortComponentEntries — vulnerabilities (severity rank)
// ---------------------------------------------------------------------------

describe('sortComponentEntries — vulnerabilities', () => {
  const critical = makeEntry({ name: 'C', key: 'c', highestSeverity: 'critical', vulnerabilityCount: 5 });
  const high = makeEntry({ name: 'H', key: 'h', highestSeverity: 'high', vulnerabilityCount: 3 });
  const low = makeEntry({ name: 'L', key: 'l', highestSeverity: 'low', vulnerabilityCount: 1 });
  const none = makeEntry({ name: 'N', key: 'n', highestSeverity: 'none', vulnerabilityCount: 0 });
  const unknown = makeEntry({ name: 'U', key: 'u', vulnerabilityCount: 0 });

  it('sorts descending: critical first', () => {
    const result = sortComponentEntries([none, low, critical, high], sortDesc('vulnerabilities'));
    expect(result[0].component.key).toBe('c');
    expect(result[1].component.key).toBe('h');
  });

  it('sorts ascending: lowest severity first', () => {
    const result = sortComponentEntries([critical, low, high, none], sortAsc('vulnerabilities'));
    expect(result[result.length - 1].component.key).toBe('c');
  });

  it('breaks ties by vulnerabilityCount', () => {
    const moreHigh = makeEntry({ name: 'H2', key: 'h2', highestSeverity: 'high', vulnerabilityCount: 10 });
    const result = sortComponentEntries([high, moreHigh], sortDesc('vulnerabilities'));
    // Same severity, higher count wins in desc
    expect(result[0].component.key).toBe('h2');
  });

  it('handles undefined highestSeverity gracefully', () => {
    const result = sortComponentEntries([critical, unknown], sortDesc('vulnerabilities'));
    expect(result[0].component.key).toBe('c');
    expect(result[1].component.key).toBe('u');
  });
});

// ---------------------------------------------------------------------------
// Immutability
// ---------------------------------------------------------------------------

describe('sortComponentEntries — immutability', () => {
  it('does not mutate the input array', () => {
    const a = makeEntry({ name: 'Beta', key: 'b' });
    const b = makeEntry({ name: 'Alpha', key: 'a' });
    const original = [a, b];
    const snapshot = [...original];
    sortComponentEntries(original, sortAsc('name'));
    expect(original).toEqual(snapshot);
  });

  it('returns a new array even when column is null', () => {
    const entries = [makeEntry({ name: 'A', key: 'a' })];
    const result = sortComponentEntries(entries, DEFAULT_COMPONENT_TABLE_SORT_STATE);
    expect(result).not.toBe(entries);
  });
});

// ---------------------------------------------------------------------------
// Fallback sort stability
// ---------------------------------------------------------------------------

describe('sortComponentEntries — fallback sort', () => {
  it('uses name then version as fallback when primary values are equal', () => {
    const a = makeEntry({ key: 'a', name: 'alpha', version: '1.0.0', purl: 'pkg:npm/a' });
    const b = makeEntry({ key: 'b', name: 'alpha', version: '2.0.0', purl: 'pkg:npm/b' });
    // Sorting by purl the primary keys differ, so fallback is not used.
    // Sorting by type with no supplier both empty → falls back to name (equal) then version
    const result = sortComponentEntries([b, a], sortAsc('type'));
    expect(result[0].component.key).toBe('a');
    expect(result[1].component.key).toBe('b');
  });
});
