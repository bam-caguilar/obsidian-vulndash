import { getSeverityRank } from '../../../domain/value-objects/Severity';
import type { ComponentInventoryDisplayEntry } from './ComponentInventoryStore';
import type { ComponentTableSortState } from './ComponentTableSortState';

const TEXT_COLLATOR_OPTIONS: Intl.CollatorOptions = { sensitivity: 'base' };
const VERSION_COLLATOR_OPTIONS: Intl.CollatorOptions = { sensitivity: 'base', numeric: true };

/**
 * Extracts the primary key used for the 'type' sort column.
 * Currently backed by component.supplier, which represents the component vendor context.
 * When a dedicated `type` field is added to TrackedComponent this accessor should be updated.
 */
const getTypeKey = (entry: ComponentInventoryDisplayEntry): string =>
  entry.component.supplier?.trim() ?? '';

const getPurlKey = (entry: ComponentInventoryDisplayEntry): string =>
  entry.component.purl?.trim() ?? entry.component.cpe?.trim() ?? '';

/**
 * Deterministic fallback comparator applied when the primary sort value is equal.
 * Order: name → version → purl/key.
 * Ensures a stable visual order regardless of the active sort column.
 */
const fallbackCompare = (
  a: ComponentInventoryDisplayEntry,
  b: ComponentInventoryDisplayEntry
): number => {
  const nameCompare = (a.component.name ?? '').localeCompare(
    b.component.name ?? '',
    undefined,
    TEXT_COLLATOR_OPTIONS
  );
  if (nameCompare !== 0) {
    return nameCompare;
  }

  const versionCompare = (a.component.version ?? '').localeCompare(
    b.component.version ?? '',
    undefined,
    VERSION_COLLATOR_OPTIONS
  );
  if (versionCompare !== 0) {
    return versionCompare;
  }

  const purlA = getPurlKey(a) || a.component.key;
  const purlB = getPurlKey(b) || b.component.key;
  return purlA.localeCompare(purlB, undefined, TEXT_COLLATOR_OPTIONS);
};

const compareEntries = (
  a: ComponentInventoryDisplayEntry,
  b: ComponentInventoryDisplayEntry,
  column: ComponentTableSortState['column']
): number => {
  if (column === null) {
    return 0;
  }

  let primary = 0;

  switch (column) {
    case 'name':
      primary = (a.component.name ?? '').localeCompare(
        b.component.name ?? '',
        undefined,
        TEXT_COLLATOR_OPTIONS
      );
      break;

    case 'version':
      primary = (a.component.version ?? '').localeCompare(
        b.component.version ?? '',
        undefined,
        VERSION_COLLATOR_OPTIONS
      );
      break;

    case 'type':
      primary = getTypeKey(a).localeCompare(getTypeKey(b), undefined, TEXT_COLLATOR_OPTIONS);
      break;

    case 'purl':
      primary = getPurlKey(a).localeCompare(getPurlKey(b), undefined, TEXT_COLLATOR_OPTIONS);
      break;

    case 'vulnerabilities': {
      // Sort by highest severity rank first, then by vulnerability count as a tiebreaker.
      const rankA = getSeverityRank(a.highestSeverity);
      const rankB = getSeverityRank(b.highestSeverity);
      primary = rankA !== rankB ? rankA - rankB : a.vulnerabilityCount - b.vulnerabilityCount;
      break;
    }

    default:
      break;
  }

  if (primary !== 0) {
    return primary;
  }

  return fallbackCompare(a, b);
};

/**
 * Returns a new sorted array of component inventory entries according to the given sort state.
 * Does not mutate the input array.
 * When sortState.column is null, the original order is preserved (stable copy).
 */
export function sortComponentEntries(
  entries: readonly ComponentInventoryDisplayEntry[],
  sortState: ComponentTableSortState
): ComponentInventoryDisplayEntry[] {
  if (sortState.column === null) {
    return [...entries];
  }

  const directionMultiplier = sortState.direction === 'asc' ? 1 : -1;

  return [...entries].sort(
    (a, b) => compareEntries(a, b, sortState.column) * directionMultiplier
  );
}
